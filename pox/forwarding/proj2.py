"""
Author Muhammad Usman

This is an L3 load balancer written directly against the OpenFlow library.
Derived from http://courses.cs.washington.edu/courses/csep561/13au/projects/LearningSwitch.txt
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
import time

log = core.getLogger()

HARD_TIMEOUT = 30
IDLE_TIMEOUT = 30

CONFIG_MAX_NODES = (4)
CONFIG_SERVER_NODES = (CONFIG_MAX_NODES / 2)
CONFIG_CLIENT_NODES = (CONFIG_MAX_NODES - CONFIG_SERVER_NODES)

class LoadBalancer (EventMixin):

  def __init__ (self,connection):
    # Switch we'll be adding L3 load-balancing capabilities to
    self.connection = connection
    self.listenTo(connection)
    

  def _handle_PacketIn (self, event):

    # parsing the input packet
    packet = event.parse()
    
    log.debug("%.2f::_handle_PacketIn(): src=%s,dst=%s,type=%x" % (time.clock(), packet.src, packet.dst, packet.type ))

    # updating out mac to port mapping
    if packet.type == packet.LLDP_TYPE or packet.type == packet.IPV6_TYPE:
      # Drop LLDP packets 
      # Drop IPv6 packets
      # send of command without actions

      msg = of.ofp_packet_out()
      msg.buffer_id = event.ofp.buffer_id
      msg.in_port = event.port
      self.connection.send(msg)
      return
    elif packet.type != packet.IP_TYPE:
      log.debug("%.2f::!!ERROR: Cannot handle eth type = %x\n" % packet.type)
      return

    l3packet = packet.next
    log.debug("%.2f::_handle_PacketIn(): srcip=%s,dstip=%s" % (time.clock(), l3packet.srcip, l3packet.dstip))

    log.debug("Port for %s unknown -- flooding" % (packet.dst,))
    msg = of.ofp_packet_out()
    msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
    msg.buffer_id = event.ofp.buffer_id
    msg.in_port = event.port
    self.connection.send(msg)

class load_balancer (EventMixin):

  def __init__(self):
    self.listenTo(core.openflow)

  def _handle_ConnectionUp (self, event):
    log.debug("\n\n######Connection %s\n" % (event.connection,))
    LoadBalancer(event.connection)


def launch ():
  #Starts an l3 load balancer switch.
  core.registerNew(load_balancer)


