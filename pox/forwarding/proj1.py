"""
Author Muhammad Usman

This is an L2 learning switch written directly against the OpenFlow library.
It is derived from 
http://courses.cs.washington.edu/courses/csep561/13au/projects/L2LearningSwitch.txt.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
import time

log = core.getLogger()

HARD_TIMEOUT = 30
IDLE_TIMEOUT = 30
class L2LearningSwitch (EventMixin):

  def __init__ (self, connection):
    # Switch we'll be adding L2 learning switch capabilities to
    self.connection = connection

    # Our table
    self.macToPort = {}

    # We want to hear PacketIn messages, so we listen
    # to the connection
    connection.addListeners(self)


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

class l2_learning_switch (EventMixin):
  def __init__(self):
    self.listenTo(core.openflow)

#
# Event raised when the connection to an OpenFlow switch has been established
#
  def _handle_ConnectionUp (self, event):
    log.debug("Connection %s" % (event.connection,))
    L2LearningSwitch(event.connection)

#
# The launch function is called by POX to tell the component to initialize itself
# We don't use any command line parameters for now
#
def launch ():
  log.debug("*** L2 Learning Switch Started ***")

  # Register the L2 learning switch
  core.registerNew(l2_learning_switch)

