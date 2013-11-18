"""
Author Muhammad Usman

This is an L3 load balancer written directly against the OpenFlow library.
Derived from http://courses.cs.washington.edu/courses/csep561/13au/projects/LearningSwitch.txt
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.addresses import IPAddr, EthAddr

import time

log = core.getLogger()

HARD_TIMEOUT = 30
IDLE_TIMEOUT = 30

CONFIG_MAX_NODES = (2)
CONFIG_SERVER_NODES = (CONFIG_MAX_NODES / 2)
CONFIG_CLIENT_NODES = (CONFIG_MAX_NODES - CONFIG_SERVER_NODES)
CONFIG_IP_BASE = IPAddr("10.0.0.1")
CONFIG_MAC_BASE = EthAddr("00:00:00:00:00:01")
VIRTUAL_MAC = "00:00:00:00:ff:ff"

_virtual_ip = IPAddr("10.10.10.10")
_client_ip = ["10.0.0.1"]
_server_ip = ["10.0.0.2"]

class LoadBalancer (EventMixin):

  def __init__ (self,connection):
    # Switch we'll be adding L3 load-balancing capabilities to
    self.connection = connection
    self.listenTo(connection)
  
  def _print_IpPacket (self, ipp):

    log.debug("%.2f::RX IP packet: srcip=%s,dstip=%s" % (time.clock(), ipp.srcip, ipp.dstip))
    if ipp.dstip.toStr() in _server_ip:
      log.info("%.2f::\tIP packet for server" % time.clock())
    elif ipp.dstip.toStr() in _client_ip:
      log.info("%.2f::\tIP packet for client" % time.clock())
    elif ipp.dstip.toStr() == _virtual_ip:
      log.info("%.2f::\tIP packet for virtual ip" % time.clock())

    if ipp.srcip.toStr() in _server_ip:
      log.info("%.2f::\tIP packet from server" % time.clock())
    elif ipp.srcip.toStr() in _client_ip:
      log.info("%.2f::\tIP packet from client" % time.clock())
    elif ipp.srcip.toStr() == _virtual_ip:
      log.info("%.2f::\tIP packet from virtual ip" % time.clock())
    return



  def _print_ArpPacket (self, arpp):

    log.debug("%.2f:: RX ARP packet: hwsrc=%s,hwdst=%s,protosrc=%s,protodst=%s\n" % (time.clock(), arpp.hwsrc, arpp.hwdst, arpp.protosrc, arpp.protodst))
    if arpp.protodst.toStr() in _server_ip:
      log.info("%.2f::\tARP packet for server" % time.clock())
    elif arpp.protodst.toStr() in _client_ip:
      log.info("%.2f::\tARP packet for client" % time.clock())
    elif arpp.protodst.toStr() == _virtual_ip:
      log.info("%.2f::\tARP packet for virtual ip" % time.clock())

    if arpp.protosrc.toStr() in _server_ip:
      log.info("%.2f::\tARP packet from server" % time.clock())
    elif arpp.protosrc.toStr() in _client_ip:
      log.info("%.2f::\tARP packet from client" % time.clock())
    elif arpp.protosrc.toStr() == _virtual_ip:
      log.info("%.2f::\tARP packet from virtual ip" % time.clock())
    return


  def _handle_ArpPacket (self, arpp, event):

    self._print_ArpPacket(arpp)
    if arpp.protodst == _virtual_ip:
      if arpp.opcode == arpp.REQUEST:
        log.info("%.2f::ARP request" % time.clock())
        r = arp()
        r.hwtype = r.HW_TYPE_ETHERNET
        r.prototype = r.PROTO_TYPE_IP
        r.opcode = r.REPLY
        r.hwdst = arpp.hwsrc
        r.protodst = arpp.protosrc
        r.hwsrc = EthAddr(VIRTUAL_MAC)
        r.protosrc = arpp.protodst
        e = ethernet(type=ethernet.ARP_TYPE, src=r.hwsrc,
                     dst=r.hwdst)
        e.set_payload(r)

        msg = of.ofp_packet_out()
        msg.data = e.pack()
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        msg.in_port = of.OFPP_NONE
        self.connection.send(msg)

      elif arpp.opcode == arpp.REPLY:
        print ("TODO: ARP RESP")
      else:
        log.debug("%.2f::_handle_ArpPacket(): ERROR invalid ARP packet" % time.clock())
        return


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
    elif packet.type == packet.ARP_TYPE:
      self._handle_ArpPacket(packet.next, event)
      return
    elif packet.type == packet.IP_TYPE:
      self._handle_IpPacket(packet.next, event)
    else:
      log.debug("%.2f::!!ERROR: Cannot handle packet type = %x\n" % (time.clock(), packet.type))
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
    log.debug("\n\n###### Connection %s\n" % (event.connection,))
    LoadBalancer(event.connection)


def launch (vip):
  log.debug("###### CLI: vip=%s"  % vip)

  global _virtual_ip
  _virtual_ip = IPAddr(vip)

  log.debug("###### '_virtual_ip=%s"  % _virtual_ip.toStr())
  log.debug("###### 'CONFIG_MAX_NODES=%s"  % str(CONFIG_MAX_NODES))
  log.debug("###### 'CONFIG_SERVER_NODES=%s"  % str(CONFIG_SERVER_NODES))
  log.debug("###### 'CONFIG_CLIENT_NODES=%s"  % str(CONFIG_CLIENT_NODES))
  log.debug("###### 'CONFIG_IP_BASE=%s"  % CONFIG_IP_BASE.toStr())
  log.debug("###### 'CONFIG_MAC_BASE=%s"  % CONFIG_MAC_BASE.toStr())

  #Starts an l3 load balancer switch.
  core.registerNew(load_balancer)


