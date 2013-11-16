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
class LoadBalancer (EventMixin):

  def __init__ (self,connection):
    # Switch we'll be adding L3 load-balancing capabilities to
    self.connection= connection
    self.listenTo(connection)
    

  def _handle_PacketIn (self, event):

    # parsing the input packet
    packet = event.parse()
    
    # updating out mac to port mapping
    
    if packet.type == packet.LLDP_TYPE or packet.type == 0x86DD:
      # Drop LLDP packets 
      # Drop IPv6 packets
      # send of command without actions

      msg = of.ofp_packet_out()
      msg.buffer_id = event.ofp.buffer_id
      msg.in_port = event.port
      self.connection.send(msg)
      return

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
    log.debug("Connection %s" % (event.connection,))
    LoadBalancer(event.connection)


def launch ():
  #Starts an l3 load balancer switch.
  core.registerNew(load_balancer)


