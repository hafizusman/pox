"""
Author Muhammad Usman

An NAT + Bridge implementation written directly against the OpenFlow library.
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
_NAT_MAC = EthAddr("00:00:00:00:00:00")

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


class NAT (object):

  def __init__ (self, connection):
    self.connection = connection
    self.externel_network = '172.64.3.0/24'
    self.arp_table = {
                      IPAddr("10.0.1.1"):EthAddr("00:00:00:00:00:01"),
                      IPAddr("10.0.1.2"):EthAddr("00:00:00:00:00:02"),
                      IPAddr("10.0.1.3"):EthAddr("00:00:00:00:00:03"),
                      IPAddr("172.64.3.21"):EthAddr("00:00:00:00:00:04"),
                      IPAddr("172.64.3.22"):EthAddr("00:00:00:00:00:05")
                      }

    log.debug("NAT connection: %s" % (connection))
    # Our table that maps the MAC addresses to the port
    self.macToPort = {}

    # Add listner for packetIn messages
    connection.addListeners(self)

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
      if packet.next.dstip.in_network(self.externel_network):
        log.debug("Got external network packet, setting IP to: %s" % _NAT_IP.toStr())
        msg = of.ofp_packet_out()
        msg.in_port = event.port
        msg.actions.append(of.ofp_action_dl_addr.set_dst(self.arp_table[packet.next.dstip]))
        msg.actions.append(of.ofp_action_dl_addr.set_src(_NAT_MAC))
        msg.actions.append(of.ofp_action_nw_addr.set_src(_NAT_IP))
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        msg.data = event.ofp
        self.connection.send(msg)
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


class MySwitch (object):
  """
  Waits for OpenFlow switches to connect and makes them learning switches.
  """
  def __init__ (self):
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
        NAT(event.connection)

"""
launch function is one that POX calls to tell the component to initialize itself
We don't use any command line parameters for now
"""
def launch ():
  """
  Register our L2 learning switch
  """
  core.registerNew(MySwitch)
