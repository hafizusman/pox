"""
Author Muhammad Usman

This is an L3 load balancer written directly against the OpenFlow library.
Derived from  James McCauley's load balancer
Service Virtual IP = 10.0.0.250

Usage example:
  python pox.py log.level --DEBUG forwarding.proj2 --replicas="10.0.0.3,10.0.0.4"

"""


from pox.core import core
import pox
import time


import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.util import str_to_bool, dpid_to_str

log = core.getLogger("l3loadbalancer")

SERVICE_MAC = "00:00:00:00:ff:ff"
SERVICE_IP = "10.0.0.250"

# How long do we wait for an probe reply (ARP) before we consider a replica dead?
REPLICA_ARP_RETRIES = 3

# How often do we send out probes?
REPLICA_RETRY_FREQ = 5


FLOW_IDLE_TIMEOUT = 10
FLOW_MEMORY_TIMEOUT = 60 * 5


"""
  Holds data for the flow that we're load balancing. Flows are cached on
  an MRU basis - if a flow hasn't been used for a while, it is forgotten
"""
class FlowInfo (object):
  def __init__ (self, replica, first_packet, client_port):
    self.replica = replica
    self.first_packet = first_packet
    self.client_port = client_port
    self.refresh()

  def refresh (self):
    self.timeout = time.time() + FLOW_MEMORY_TIMEOUT

  @property
  def is_expired (self):
    return time.time() > self.timeout

  @property
  def key1 (self):
    ethp = self.first_packet
    ipp = ethp.find('ipv4')
    tcpp = ethp.find('tcp')
    return ipp.srcip,ipp.dstip,tcpp.srcport,tcpp.dstport

  @property
  def key2 (self):
    ethp = self.first_packet
    ipp = ethp.find('ipv4')
    tcpp = ethp.find('tcp')
    return self.replica,ipp.srcip,tcpp.dstport,tcpp.srcport




class l3loadbalancer (object):
  """
  Traffic to the service's virtual IP will be redirected to one of the replicas

  Replica liveliness is checked using ARP requests.
  """
  def __init__ (self, connection, replicas = []):
    self.service_ip = IPAddr(SERVICE_IP)
    self.mac = EthAddr(SERVICE_MAC)
    self.replicas = [IPAddr(a) for a in replicas]
    self.con = connection
    self.server_loaded_index = 0
    self.servers_loaded = {}

    self.log = log.getChild(dpid_to_str(self.con.dpid))
 
    # IP -> expire_time
    self.outstanding_probes = {}

    # We remember where we directed flows so that if they start up again,
    # we can send them to the same replica if it's still up.  Alternate
    # approach: hashing.
    self.traffic_flows = {} # (srcip,dstip,srcport,dstport) -> FlowInfo

    self._do_probe() # Kick off the probing

  def _do_expire (self):
    """
    Expire probes and "memorized" flows


    Each of these should only have a limited lifetime.
    """
    t = time.time()

    # Expire probes
    for ip,expire_at in self.outstanding_probes.items():
      if t > expire_at:
        self.outstanding_probes.pop(ip, None)
        if ip in self.servers_loaded:
          self.log.warn("Server %s down", ip)
          del self.servers_loaded[ip]


    # Expire old flows
    c = len(self.traffic_flows)
    self.traffic_flows = {k:v for k,v in self.traffic_flows.items()
                   if not v.is_expired}
    if len(self.traffic_flows) != c:
      self.log.debug("Expired %i flows", c-len(self.traffic_flows))


  def _do_probe (self):
    """
    Sends arps to replica to see if it's still alive
    """
    self._do_expire()

    replica = self.replicas.pop(0)
    self.replicas.append(replica)

    r = arp()
    r.hwtype = r.HW_TYPE_ETHERNET
    r.prototype = r.PROTO_TYPE_IP
    r.opcode = r.REQUEST
    r.hwdst = ETHER_BROADCAST
    r.protodst = replica
    r.hwsrc = self.mac
    r.protosrc = self.service_ip
    e = ethernet(type=ethernet.ARP_TYPE, src=self.mac,
                 dst=ETHER_BROADCAST)
    e.set_payload(r)

    msg = of.ofp_packet_out()
    msg.data = e.pack()
    msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
    msg.in_port = of.OFPP_NONE
    self.con.send(msg)

    self.outstanding_probes[replica] = time.time() + REPLICA_ARP_RETRIES
    r = REPLICA_RETRY_FREQ/ float(len(self.replicas))
    r = REPLICA_RETRY_FREQ / float(len(self.replicas))
    r = max(.25, r)
    core.callDelayed(r, self._do_probe)


  def _next_server (self):
    """
    Pick a replica for load balancing in a round-robin fashion
    """
    keys = self.servers_loaded.keys()
    picked_server = keys[self.server_loaded_index]
    self.server_loaded_index += 1
    if self.server_loaded_index >= len(keys):
      self.server_loaded_index = 0
    return picked_server

  def _handle_PacketIn (self, event):
    inport = event.port
    packet = event.parsed

    def drop ():
      if event.ofp.buffer_id is not None:
        msg = of.ofp_packet_out(data = event.ofp)
        self.con.send(msg)
      return None

    tcpp = packet.find('tcp')

    # handle arp requests for replica liveliness
    if not tcpp:
      arpp = packet.find('arp')
      if arpp:
        # Let our liveliness arp requests know that we're still alive
        if arpp.opcode == arpp.REPLY:
          if arpp.protosrc in self.outstanding_probes:
            # Replica is up, remove it from pending list
            del self.outstanding_probes[arpp.protosrc]

            if (self.servers_loaded.get(arpp.protosrc, (None,None))
                != (arpp.hwsrc,inport)):
              # A new replica has been discovered.
              self.servers_loaded[arpp.protosrc] = arpp.hwsrc,inport
              self.log.info("Replica %s is now online", arpp.protosrc)
        return

      # Unhandled packet type, discard
      return drop()

    # handle higher layer packet
    ipp = packet.find('ipv4')

    # Is it from one of the replicas, if so send it back to the client
    if ipp.srcip in self.replicas:
      key = ipp.srcip,ipp.dstip,tcpp.srcport,tcpp.dstport
      entry = self.traffic_flows.get(key)

      if entry is None:
        # We weren't talking to this client
        self.log.debug("No client for %s", key)
        return drop()

      # Update timeout and reinstall.
      entry.refresh()

      # Install reverse table entry
      mac,port = self.servers_loaded[entry.replica]

      actions = []
      actions.append(of.ofp_action_dl_addr.set_src(self.mac))
      actions.append(of.ofp_action_nw_addr.set_src(self.service_ip))
      actions.append(of.ofp_action_output(port = entry.client_port))
      match = of.ofp_match.from_packet(packet, inport)

      msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                            idle_timeout=FLOW_IDLE_TIMEOUT,
                            hard_timeout=of.OFP_FLOW_PERMANENT,
                            data=event.ofp,
                            actions=actions,
                            match=match)
      self.con.send(msg)

    elif ipp.dstip == self.service_ip:
      # Valid request for our virtial service IP. Will be redirected to a replica
      key = ipp.srcip,ipp.dstip,tcpp.srcport,tcpp.dstport
      entry = self.traffic_flows.get(key)

      if entry is None or entry.replica not in self.servers_loaded:
        # Are there any unloaded replicas to redirect this request to?
        if len(self.servers_loaded) == 0:
          self.log.warn("No unloaded replicas! Dropping packet")
          return drop()

        # Load balance
        replica = self._next_server()
        self.log.debug("Traffic from client %s directed to replica %s" % (ipp.srcip.toStr(), replica))
        entry = FlowInfo(replica, packet, inport)
        self.traffic_flows[entry.key1] = entry
        self.traffic_flows[entry.key2] = entry
   
      # Update timeout and reinstall
      entry.refresh()

      # Set up table entry towards selected replica
      mac,port = self.servers_loaded[entry.replica]

      actions = []
      actions.append(of.ofp_action_dl_addr.set_dst(mac))
      actions.append(of.ofp_action_nw_addr.set_dst(entry.replica))
      actions.append(of.ofp_action_output(port = port))
      match = of.ofp_match.from_packet(packet, inport)

      msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                            idle_timeout=FLOW_IDLE_TIMEOUT,
                            hard_timeout=of.OFP_FLOW_PERMANENT,
                            data=event.ofp,
                            actions=actions,
                            match=match)
      self.con.send(msg)


# Remember which DPID we're operating on (first one to connect)
_dpid = None

def launch (replicas):
  replicas = replicas.replace(","," ").split()
  replicas = [IPAddr(x) for x in replicas]

  def _handle_ConnectionUp (event):
    global _dpid
    if _dpid is None:
      log.info("Connection up for Load Balancer")
      core.registerNew(l3loadbalancer, event.connection, replicas)
      _dpid = event.dpid

    if _dpid != event.dpid:
      log.info("Switch load balancing ignored for %s", event.connection)
    else:
      log.info("Switch load balancing on %s", event.connection)
      # save connection state for use during HandleIn Packet
      core.l3loadbalancer.con = event.connection
      event.connection.addListeners(core.l3loadbalancer)

  core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)

