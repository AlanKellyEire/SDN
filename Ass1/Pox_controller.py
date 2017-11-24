"""
Simple POX script.

That detects when the switch is up, and listens for Packet_In events. When the switch comes up, the Pox script should print the dpid of the switch. When a Packet_In event is received, the Pox script should add a flow rule to the switch to forward all packets with the same source and destination IP addresses received on the port identified in the Packet_In event to the appropriate output port. You can assume that port numbers match the order in which hosts have been added in the Mininet script. Use pox/ext/skeleton.py as the starting point for your script.

Created By: Alan Kelly
Date: 27/10/2017
"""

"""
From home directory

Command to run on default port 6633

pox/./pox.py forward1.py 

run on specific port 

pox/./pox.py forward1.py openflow.of_01 --port=<portNumber>


"""


#!/usr/bin/python

from pox.core import core
import pox
log = core.getLogger()

from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.util import str_to_bool, dpid_to_str
from pox.lib.recoco import Timer

import pox.openflow.libopenflow_01 as of

from pox.lib.revent import *

import time

#creating the controller object.
class _pox_Controller (object):

  def __init__ (self):
    """
    Initialize
    """

    self.lost_buffers = {}

    self.arpTable = {}

    core.openflow.addListeners(self)  

  #function to print dpid of switch
  def _handle_ConnectionUp(self, event):
    #printing the dpid
    #log.info("Switch with DPID of %s has come up.",dpid_to_str(event.dpid))
    print("Switch with DPID of %s has come up." % (dpid_to_str(event.dpid)))
    
    # printing the dpid in hex
    #log.info("Switch with DPID in HEX format of %s has come up." % (hex(event.dpid)))
    print("Switch with DPID in HEX format of %s has come up." % (hex(event.dpid)))

  #handling the packet in function
  def _handle_PacketIn (self, event):
    dpid = event.connection.dpid
    #getting the switch in port of the packet
    inport = event.port
    #parsing the packet, used later to determine the outport and packet type
    packet = event.parsed
    if not packet.parsed:
      log.warning("%i %i ignoring unparsed packet", dpid, inport)
      return

    if dpid not in self.arpTable:
      # New switch -- create an empty table
      self.arpTable[dpid] = {}
      
    if isinstance(packet.next, ipv4):
      destinIP = packet.next.dstip
      log.info("%i %i IP %s => %s", dpid,inport,
                packet.next.srcip,packet.next.dstip)

      # Send any waiting packets...
      self._send_lost_buffers(dpid, packet.next.srcip, packet.src, inport)

      #converting the destination ip address to string for future modifying
      stringIPaddress = str(destinIP);
      #splitting the des ip to get the last octet of the ip address
      last_Oct = stringIPaddress.split('.') 
      intIP = int(last_Oct[-1]) 
      #used for testing
      log.info("%i %i installing flow for %s => %s out port %i"
                    % (dpid, inport, packet.next.srcip, destinIP, intIP))
      log.info("ip address last digit is  %s", intIP)

      #adding the output flow rule to forward the packet to the outport port got from the last octet of the des IP 
      actions = of.ofp_action_output(port = intIP)
          
      #creating the match structure for the rule to match on
      match = of.ofp_match.from_packet(packet, inport)
      #creating the flow mod 
      msg = of.ofp_flow_mod(command=of.OFPFC_ADD, idle_timeout=of.OFP_FLOW_PERMANENT, hard_timeout=of.OFP_FLOW_PERMANENT, buffer_id=event.ofp.buffer_id, actions=actions, match=match)
      #converting msg object to on-the-wire format and sending flow mod to the switch
      event.connection.send(msg.pack())

    elif isinstance(packet.next, arp):
      a = packet.next
      log.info("%i %i ARP %s %s => %s", dpid, inport,
       {arp.REQUEST:"request",arp.REPLY:"reply"}.get(a.opcode,
       'op:%i' % (a.opcode,)), a.protosrc, a.protodst)

      if a.prototype == arp.PROTO_TYPE_IP:
        if a.hwtype == arp.HW_TYPE_ETHERNET:
          if a.protosrc != 0:
            
            # Send any waiting packets...
            self._send_lost_buffers(dpid, a.protosrc, packet.src, inport)

            if a.opcode == arp.REQUEST:
              # Maybe we can answer

              if a.protodst in self.arpTable[dpid]:
                # We have an answer...

                  r = arp()
                  r.hwtype = a.hwtype
                  r.prototype = a.prototype
                  r.hwlen = a.hwlen
                  r.protolen = a.protolen
                  r.opcode = arp.REPLY
                  r.hwdst = a.hwsrc
                  r.protodst = a.protosrc
                  r.protosrc = a.protodst
                  r.hwsrc = self.arpTable[dpid][a.protodst].mac
                  e = ethernet(type=packet.type, src=EthAddr("%012x" % (dpid & 0xffFFffFFffFF,)),
                               dst=a.hwsrc)
                  e.set_payload(r)
                  log.info("%i %i answering ARP for %s" % (dpid, inport,
                   r.protosrc))
                  msg = of.ofp_packet_out()
                  msg.data = e.pack()
                  msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
                  msg.in_port = inport
                  event.connection.send(msg)
                  return

    
      msg = of.ofp_packet_out(in_port = inport, data = event.ofp,
          action = of.ofp_action_output(port = of.OFPP_FLOOD))
      event.connection.send(msg)

  def _send_lost_buffers (self, dpid, ipaddr, macaddr, port):
    """
    We may have "lost" buffers -- packets we got but didn't know
    where to send at the time.  We may know now.  Try and see.
    """
    if (dpid,ipaddr) in self.lost_buffers:
      
      bucket = self.lost_buffers[(dpid,ipaddr)]
      del self.lost_buffers[(dpid,ipaddr)]
      log.info("Sending %i buffered packets to %s from %s"
                % (len(bucket),ipaddr,dpid_to_str(dpid)))
      for _,buffer_id,in_port in bucket:
        po = of.ofp_packet_out(buffer_id=buffer_id,in_port=in_port)
        po.actions.append(of.ofp_action_dl_addr.set_dst(macaddr))
        po.actions.append(of.ofp_action_output(port = port))
        core.openflow.sendToDPID(dpid, po)

  def _handle_expiration (self):
    # Called by a timer so that we can remove old items.
    empty = []
    for k,v in self.lost_buffers.iteritems():
      dpid,ip = k

      for item in list(v):
        expires_at,buffer_id,in_port = item
        if expires_at < time.time():
          # This packet is old.  Tell this switch to drop it.
          v.remove(item)
          po = of.ofp_packet_out(buffer_id = buffer_id, in_port = in_port)
          core.openflow.sendToDPID(dpid, po)
      if len(v) == 0: empty.append(k)

    # Remove empty buffer bins
    for k in empty:
      del self.lost_buffers[k]

def launch ():  
  core.registerNew(_pox_Controller)