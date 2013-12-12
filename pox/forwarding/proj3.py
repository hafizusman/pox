"""
Author Muhammad Usman

An NAT + Bridge implementation written directly against the OpenFlow library.

Usage example:
  python pox.py log.level --DEBUG forwarding.proj3 --blockedservers="172.64.3.21,172.64.3.22"
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.util import *
import time

log = core.getLogger()

# We don't want to flood immediately when a switch connects.
_flood_delay = 0
_NAT_IP = IPAddr("172.64.3.1")
_NAT_PORT_START = 10000

# todo: open these before submitting
# _TCP_TRANSITORY_IDLE_TIMEOUT = 300
# _TCP_ESTABLISHED_IDLE_TIMEOUT = 7440
_TCP_TRANSITORY_IDLE_TIMEOUT = 300
_TCP_ESTABLISHED_IDLE_TIMEOUT = 5

_TCP_STATE_NONE = 0
_TCP_STATE_HANDSHAKE = 1
_TCP_STATE_CONNECTED = 2


class NAT (object):

  def __init__ (self, connection, mac, ip, blockedservers):
    self.connection = connection
    self.external_mac = mac
    self.external_ip = ip
    self.blockedservers = blockedservers
    self.external_network = '172.64.3.0/24'
    self.internal_network = '10.0.1.0/24'
    self.arp_table =  {
                      IPAddr("10.0.1.101"):EthAddr("00:00:00:00:00:01"),
                      IPAddr("10.0.1.102"):EthAddr("00:00:00:00:00:02"),
                      IPAddr("10.0.1.103"):EthAddr("00:00:00:00:00:03"),
                      IPAddr("172.64.3.21"):EthAddr("00:00:00:00:00:04"),
                      IPAddr("172.64.3.22"):EthAddr("00:00:00:00:00:05"),
                      }

    self.client_to_nat_port = {}
    self.nat_port_to_client = {}
    self.next_free_nat_port = _NAT_PORT_START
    self.nat_ports_in_use = {}
    self.nat_ports_in_use_ref_count = {}


    log.debug("NAT connection: %s" % (connection))
    log.debug("NAT blockedservers: ")
    log.debug(self.blockedservers)
    # Our table that maps the MAC addresses to the port
    self.macToPort = {}

    # Add listner for packetIn messages
    connection.addListeners(self)

  def _translate_To_External_Network(self, packet, event):
      msg = of.ofp_packet_out()
      msg.in_port = event.port

      # todo: send out ARP request to get server IP instead of using our static arp table
      msg.actions.append(of.ofp_action_dl_addr.set_dst(self.arp_table[packet.next.dstip]))
      msg.actions.append(of.ofp_action_dl_addr.set_src(self.external_mac))
      msg.actions.append(of.ofp_action_nw_addr.set_src(self.external_ip))
      msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      msg.data = event.ofp
      return msg

  def _translate_From_External_Network(self, packet, event):
      msg = of.ofp_packet_out()
      msg.in_port = event.port
      msg.actions.append(of.ofp_action_dl_addr.set_dst(self.arp_table[IPAddr("10.0.1.101")]))
      msg.actions.append(of.ofp_action_dl_addr.set_src(self.external_mac))
      msg.actions.append(of.ofp_action_nw_addr.set_dst(IPAddr("10.0.1.101")))
      msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      msg.data = event.ofp
      return msg

  def _translate_To_External_NetworkEx(self, msg, packet, event, port):
    # todo: send out ARP request to get server IP instead of using our static arp table
    msg.actions.append(of.ofp_action_dl_addr.set_src(self.external_mac))
    msg.actions.append(of.ofp_action_dl_addr.set_dst(self.arp_table[packet.next.dstip])) #todo: we need this?
    msg.actions.append(of.ofp_action_nw_addr.set_src(self.external_ip))
    msg.actions.append(of.ofp_action_tp_port.set_src(port))
    msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
    msg.data = event.ofp
    return msg

  def _new_nat_port(self):
    if (self.next_free_nat_port >= 65535):
      self.next_free_nat_port = _NAT_PORT_START
    else:
      self.next_free_nat_port = self.next_free_nat_port + 1

    if (self.next_free_nat_port in self.nat_ports_in_use):
      log.debug("ERROR: _new_nat_port(): no free ports ")
      raise Exception("ERROR: _new_nat_port(): no free ports ")

    self.nat_ports_in_use[self.next_free_nat_port] = _TCP_STATE_NONE
    log.debug("_new_nat_port(): returning %d " % self.next_free_nat_port)
    return self.next_free_nat_port

  def _add_nat_entry(self, nat_port, ippsrcip, tcppsrcport):
    log.debug("_add_nat_entry(): Before:")
    for k,v in self.nat_port_to_client.items():
      print k,v
    self.client_to_nat_port[(ippsrcip, tcppsrcport)] = nat_port
    self.nat_port_to_client[nat_port] = (ippsrcip, tcppsrcport)
    self.nat_ports_in_use[nat_port] = _TCP_STATE_HANDSHAKE
    log.debug("_add_nat_entry(): After:")
    for k,v in self.nat_port_to_client.items():
      print k,v
    log.debug("_add_nat_entry(): End:")
    return

  def _remove_nat_entry(self, port):
    if self.nat_port_to_client.has_key(port):
      log.debug("_remove_nat_entry(): Before:")
      for k,v in self.nat_port_to_client.items():
        print k,v
      temp = self.nat_port_to_client[port]
      del self.client_to_nat_port[(temp[0], temp[1])]
      del self.nat_port_to_client[port]
      del self.nat_ports_in_use[port]
      log.debug("_remove_nat_entry(): After:")
      for k,v in self.nat_port_to_client.items():
        print k,v
      log.debug("_remove_nat_entry(): End:")
    else:
      raise Exception("ERROR: _remove_nat_entry(): has no nat port=%d" % port)
    return

  def _handle_FlowRemoved (self, event):
    log.debug("_handle_FlowRemoved(): Called...")
    if event.idleTimeout == False:
      raise Exception ("ERROR: rule was removed for some unknown reason!")
    log.debug("_handle_FlowRemoved(): cleaning up srcip = %s" % (event.ofp.match.nw_src))
    temp = self.client_to_nat_port[(event.ofp.match.nw_src, event.ofp.match.tp_src)]
    self._remove_nat_entry(temp)
    return


  def _handle_Tcp (self, packet, event):
    ipp = packet.find('ipv4')
    tcpp = packet.find('tcp')
    log.debug("_handle_Tcp(): srcip=%s,dstip=%s,srcport=%d,dstport=%d,flags=0x%x, %d" % 
      (ipp.srcip, ipp.dstip, tcpp.srcport, tcpp.dstport, tcpp.flags, tcpp.SYN))

    if ipp.srcip.in_network(self.internal_network):
      log.debug("_handle_Tcp(): From Internal netork")
      if (tcpp.SYN):
        log.debug("_handle_Tcp(): From Internal netork SYN")
        if (ipp.dstip in self.blockedservers):
          log.debug("_handle_Tcp(): WARN: ipp.dstip=%s is blocked!! Ignoring request" % ipp.dstip)
          return
        nat_port = self._new_nat_port()
        self._add_nat_entry(nat_port, ipp.srcip, tcpp.srcport)
        msg = of.ofp_packet_out()
        msg.in_port = event.port
        msg = self._translate_To_External_NetworkEx(msg, packet, event, self.client_to_nat_port[(ipp.srcip, tcpp.srcport)])
        self.connection.send(msg)
        log.debug("_handle_Tcp(): nat_ports_in_use[%d] = %d" % (nat_port, self.nat_ports_in_use[nat_port]))
      if (tcpp.ACK):
        log.debug("_handle_Tcp(): From Internal netork ACK")
        nat_port = self.client_to_nat_port[(ipp.srcip, tcpp.srcport)]

        # if the 3-way handshake has just completed, add a flow mod and transition to established state
        # the flow mod rule should handle all packets if we're in connected state 
        if (self.nat_ports_in_use[nat_port] == _TCP_STATE_HANDSHAKE):
          self.nat_ports_in_use[nat_port] = _TCP_STATE_CONNECTED
          log.debug("_handle_Tcp(): nat_ports_in_use[%d] = %d" % (nat_port, self.nat_ports_in_use[nat_port]))

          msg = of.ofp_flow_mod()
          msg.match = of.ofp_match.from_packet(packet, event.port)
          msg.match.in_port = event.port
          msg.idle_timeout = _TCP_ESTABLISHED_IDLE_TIMEOUT
          msg.hard_timeout = of.OFP_FLOW_PERMANENT
          msg.flags |= of.OFPFF_SEND_FLOW_REM
          # todo: send out ARP request to get server IP instead of using our static arp table
          msg = self._translate_To_External_NetworkEx(msg, packet, event, self.client_to_nat_port[(ipp.srcip, tcpp.srcport)])
          self.connection.send(msg)

    elif ipp.srcip.in_network(self.external_network):
      log.debug("_handle_Tcp(): From External netork")
      nat_port = tcpp.dstport
      client_info = self.nat_port_to_client[nat_port]
      log.debug("_handle_Tcp(): client_info=%s,%d, state=%d" %(client_info[0], client_info[1], self.nat_ports_in_use[nat_port]))
      msg = of.ofp_packet_out()
      msg.in_port = event.port
      msg.actions.append(of.ofp_action_dl_addr.set_src(self.external_mac)) # todo: needed??
      msg.actions.append(of.ofp_action_dl_addr.set_dst(self.arp_table[client_info[0]]))
      msg.actions.append(of.ofp_action_nw_addr.set_dst(client_info[0]))
      msg.actions.append(of.ofp_action_tp_port.set_dst(client_info[1]))
      msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      msg.data = event.ofp
      self.connection.send(msg)
      log.debug(msg)

    else:
      log.debug("ERROR: _handle_Tcp(): unhandled tcp packet ")
      raise Exception("ERROR: _handle_Tcp(): unhandled tcp packet ")

    return


  def _handle_Icmp (self, packet, event):
    icmpp = packet.find('icmp')
    log.debug("_handle_Icmp(): icmpp.type=%d" % (icmpp.type))

    if packet.next.dstip == self.external_ip:
      log.debug("_handle_Icmp(): ICMP packet FROM External Network")
      msg = self._translate_From_External_Network(packet, event)
      self.connection.send(msg)
      return

    if packet.next.dstip.in_network(self.external_network):
      log.debug("_handle_Icmp(): ICMP packet TO External Network")
      msg = self._translate_To_External_Network(packet, event)
      self.connection.send(msg)
      return


  def _handle_PacketIn (self, event):
    # parsing the input packet
    packet = event.parsed
    log.debug("NAT packet received")

    def flood (message = None):
      """ 
      This function floods the packet (doesn't send back to the in port since
        we're using OFPP_FLOOD) 
      """
      # The ofp_packet_out message instructs a switch to send a packet.
      msg = of.ofp_packet_out()

      # Have we waited long enough to flood?
      if time.time() - self.connection.connect_time >= _flood_delay:
        if message is not None: log.debug(message)
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      else:
        pass
      msg.data = event.ofp
      msg.in_port = event.port
      self.connection.send(msg)

    def drop (duration = None):
      """
      This function will discard the packet and install a flow modification
      rule on the controller in case of a timeout
      """
      if duration is not None:
        if not isinstance(duration, tuple):
          duration = (duration,duration)
        log.debug("adding drop flow_mod")
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet)
        msg.idle_timeout = duration[0]
        msg.hard_timeout = duration[1]
        msg.buffer_id = event.ofp.buffer_id
        self.connection.send(msg)
      elif event.ofp.buffer_id is not None:
        msg = of.ofp_packet_out()
        msg.buffer_id = event.ofp.buffer_id
        msg.in_port = event.port
        self.connection.send(msg)

    # Cache the mac-port mapping 
    self.macToPort[packet.src] = event.port

    # Drop LLDP packets 
    # Drop IPv6 packets
    if packet.type == packet.LLDP_TYPE or packet.dst.isBridgeFiltered():
      drop()
      return

    # Multicast messages need to be sent to all ports
    if packet.dst.is_multicast:
      flood()
    elif packet.dst == ETHER_BROADCAST:
      log.debug("ERROR: received broadcast, can't handle...")
      return
    else:
      icmpp = packet.find('icmp')
      tcpp = packet.find('tcp')
      if icmpp:
        self._handle_Icmp(packet, event)
        return
      elif tcpp:
        self._handle_Tcp(packet, event)
        return
      else:
        log.debug("ERROR: UNHANDLED message TYPE")
        return

      if packet.dst not in self.macToPort:
        flood("Port for %s unknown" % (packet.dst,))
      else:
        port = self.macToPort[packet.dst]
        if port == event.port:
          log.warning("Can't send to same port: %s -> %s on %s.%s.  Dropping..."
              % (packet.src, packet.dst, dpid_to_str(event.dpid), port))
          drop(10)
          return

        # Update the controllers flow table
        log.debug("adding flow_mod: for %s.%i -> %s.%i..." % (packet.src, event.port, packet.dst, port))
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet, event.port)
        msg.idle_timeout = 10
        msg.hard_timeout = 30
        msg.actions.append(of.ofp_action_output(port = port))
        msg.data = event.ofp
        self.connection.send(msg)


class Bridge (object):

  def __init__ (self, connection):
    self.connection = connection

    log.debug("Bridge connection: %s" % (connection))
    # Our table that maps the MAC addresses to the port
    self.macToPort = {}

    # Add listner for packetIn messages
    connection.addListeners(self)

  def _handle_PacketIn (self, event):
    # parsing the input packet
    packet = event.parsed
    log.debug("BRIDGE packet received")

    def flood (message = None):
      """ 
      This function floods the packet (doesn't send back to the in port since
        we're using OFPP_FLOOD) 
      """
      # The ofp_packet_out message instructs a switch to send a packet.
      msg = of.ofp_packet_out()

      # Have we waited long enough to flood?
      if time.time() - self.connection.connect_time >= _flood_delay:
        if message is not None: log.debug(message)
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      else:
        pass
      msg.data = event.ofp
      msg.in_port = event.port
      self.connection.send(msg)

    def drop (duration = None):
      """
      This function will discard the packet and install a flow modification
      rule on the controller in case of a timeout
      """
      if duration is not None:
        if not isinstance(duration, tuple):
          duration = (duration,duration)
        log.debug("adding drop flow_mod")
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet)
        msg.idle_timeout = duration[0]
        msg.hard_timeout = duration[1]
        msg.buffer_id = event.ofp.buffer_id
        self.connection.send(msg)
      elif event.ofp.buffer_id is not None:
        msg = of.ofp_packet_out()
        msg.buffer_id = event.ofp.buffer_id
        msg.in_port = event.port
        self.connection.send(msg)

    # Cache the mac-port mapping 
    self.macToPort[packet.src] = event.port

    # Drop LLDP packets 
    # Drop IPv6 packets
    if packet.type == packet.LLDP_TYPE or packet.dst.isBridgeFiltered():
      drop()
      return

    # Multicast messages need to be sent to all ports
    if packet.dst.is_multicast:
      flood()
    else:
      if packet.dst not in self.macToPort:
        flood("Port for %s unknown" % (packet.dst,))
      else:
        port = self.macToPort[packet.dst]
        if port == event.port:
          log.warning("Can't send to same port: %s -> %s on %s.%s.  Dropping..."
              % (packet.src, packet.dst, dpid_to_str(event.dpid), port))
          drop(10)
          return

        # Update the controllers flow table
        log.debug("adding flow_mod: for %s.%i -> %s.%i..." % (packet.src, event.port, packet.dst, port))
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet, event.port)
        msg.idle_timeout = 10
        msg.hard_timeout = 30
        msg.actions.append(of.ofp_action_output(port = port))
        msg.data = event.ofp
        self.connection.send(msg)



class MySwitch (object):
  """
  Launches the appropriate instance of the switch based on DPID: NAT or BRIDGE
  """
  def __init__ (self, blockedservers):
    self.blockedservers = [IPAddr(a) for a in blockedservers]

    core.openflow.addListeners(self)

  def _handle_ConnectionUp (self, event):
    log.debug("Connection %s" % (event.connection))
    log.debug("DPID: %d, %s" % (event.connection.dpid, event.connection.dpid))
    """
    We should only get two ConnectionUp:
        . one for the switch that'll act as a simple L2 learning switch
        . one for the switch that'll act as a NAT
    """
    if event.connection.dpid == 1:
        log.debug("Launching BRIDGE on dpid: %d" % (event.connection.dpid))
        Bridge(event.connection)
    else:
        _NAT_MAC = EthAddr(dpid_to_str(event.connection.dpid))
        log.debug("Launching NAT on dpid: %d, mac=%s" % (event.connection.dpid, _NAT_MAC.toStr()))
        NAT(event.connection, _NAT_MAC, _NAT_IP, self.blockedservers)




"""
launch function is one that POX calls to tell the component to initialize itself
We don't use any command line parameters for now
"""
def launch (blockedservers):
  """
  Register our L2 learning switch
  """
  blockedservers = blockedservers.replace(","," ").split()
  blockedservers = [IPAddr(x) for x in blockedservers]
  core.registerNew(MySwitch, blockedservers)
