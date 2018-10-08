"""
SDN_POX script.

Created By: Alan Kelly
Date: 27/12/2017
"""

"""
this script need to be run with spanning tree as there is multiple paths and also needs to be run with no flood

This script should be in ~/pox/ext/

HOW TO RUN FROM HOME DIRECTORY

Command to run on default port 6633

sudo ~/pox/pox.py policy openflow.discovery --eat-early-packets openflow.spanning_tree --no-flood --hold-down 

run on port 6653

sudo ~/pox/pox.py policy openflow.discovery --eat-early-packets openflow.spanning_tree --no-flood --hold-down openflow.of_01 --port=6653


"""

from pox.core import core
import pox
log = core.getLogger()

from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.util import str_to_bool, dpid_to_str
from pox.lib.recoco import Timer
from random import randint

import pox.openflow.libopenflow_01 as of

from pox.lib.revent import *

import time

# Timeout for flows
FLOW_IDLE_TIMEOUT = 10

# Timeout for ARP entries
ARP_TIMEOUT = 60 * 2

# Maximum number of packet to buffer on a switch for an unknown IP
MAX_BUFFERED_PER_IP = 5

# Maximum time to hang on to a buffer for an unknown IP in seconds
MAX_BUFFER_TIME = 5




class Entry (object):
  """
  Not strictly an ARP entry.
  We use the port to determine which port to forward traffic out of.
  We use the MAC to answer ARP replies.
  We use the timeout so that if an entry is older than ARP_TIMEOUT, we
   flood the ARP request rather than try to answer it ourselves.
  """
  def __init__ (self, port, mac):
    self.timeout = time.time() + ARP_TIMEOUT
    self.port = port
    self.mac = mac

  def __eq__ (self, other):
    if type(other) == tuple:
      return (self.port,self.mac)==other
    else:
      return (self.port,self.mac)==(other.port,other.mac)
  def __ne__ (self, other):
    return not self.__eq__(other)

  def isExpired (self):
    if self.port == of.OFPP_NONE: return False
    return time.time() > self.timeout


def dpid_to_mac (dpid):
  return EthAddr("%012x" % (dpid & 0xffFFffFFffFF,))


class sdnPox2 (EventMixin):
  def __init__ (self, arp_for_unknowns = False):
    # TEST is used to hold the host which is currently in use
    self.TEST = 0
    # If this is true and we see a packet for an unknown
    # host, we'll ARP for it.
    self.arp_for_unknowns = arp_for_unknowns

    # (dpid,IP) -> expire_time
    # We use this to keep from spamming ARPs
    self.outstanding_arps = {}

    # (dpid,IP) -> [(expire_time,buffer_id,in_port), ...]
    # These are buffers we've gotten at this datapath for this IP which
    # we can't deliver because we don't know where they go.
    self.lost_buffers = {}

    # For each switch, we map IP addresses to Entries
    self.arpTable = {}

    # This timer handles expiring stuff
    self._expire_timer = Timer(5, self._handle_expiration, recurring=True)

    core.listen_to_dependencies(self)

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

  def _send_lost_buffers (self, dpid, ipaddr, macaddr, port):
    """
    We may have "lost" buffers -- packets we got but didn't know
    where to send at the time.  We may know now.  Try and see.
    """
    if (dpid,ipaddr) in self.lost_buffers:
      # Yup!
      bucket = self.lost_buffers[(dpid,ipaddr)]
      del self.lost_buffers[(dpid,ipaddr)]
      log.debug("Sending %i buffered packets to %s from %s"
                % (len(bucket),ipaddr,dpid_to_str(dpid)))
      for _,buffer_id,in_port in bucket:
        po = of.ofp_packet_out(buffer_id=buffer_id,in_port=in_port)
        po.actions.append(of.ofp_action_dl_addr.set_dst(macaddr))
        po.actions.append(of.ofp_action_output(port = port))
        core.openflow.sendToDPID(dpid, po)

  def _handle_openflow_PacketIn (self, event):
    dpid = event.connection.dpid
    inport = event.port
    packet = event.parsed
    if not packet.parsed:
      log.warning("%i %i ignoring unparsed packet", dpid, inport)
      return

    if dpid not in self.arpTable:
      # New switch -- create an empty table
      self.arpTable[dpid] = {}


    if packet.type == ethernet.LLDP_TYPE:
      # Ignore LLDP packets
      return


    if isinstance(packet.next, ipv4):
      destinIP = packet.next.dstip
      #log.info("switch number is %i inport is %i IP %s => %s desport number is %s", dpid, inport,
       #        packet.next.srcip, packet.next.dstip, packet.next.payload.dstport)
      '''''
      reactive rules
      '''''
      if dpid == 0x7:
        if destinIP == "10.0.0.6" and packet.next.srcip == "10.0.0.1":
          # rule to allow h1 and h6 for telnet
          if packet.next.payload.dstport == 23:
            event.connection.send(of.ofp_flow_mod(action=of.ofp_action_output(port=2),
                                                priority=42, idle_timeout=30, hard_timeout=0,
                                                match=of.ofp_match(dl_type=0x800, nw_proto=6, tp_dst=23,
                                                                   nw_dst="10.0.0.6", nw_src="10.0.0.1", )))
          # rules to allow h1 and h6 for ssh
          elif packet.next.payload.dstport == 22:
            event.connection.send(of.ofp_flow_mod(action=of.ofp_action_output(port=2),
                                                priority=42, idle_timeout=30, hard_timeout=0,
                                                match=of.ofp_match(dl_type=0x800, nw_proto=6, tp_dst=22,
                                                                   nw_dst="10.0.0.6", nw_src="10.0.0.1", )))
        # rule so any type of packets can be sent to h1 from h6
          elif destinIP == "10.0.0.1" and packet.next.srcip == "10.0.0.6":
            event.connection.send(of.ofp_flow_mod(action=of.ofp_action_output(port=3),
                                                priority=42, idle_timeout=30, hard_timeout=0,
                                                match=of.ofp_match(dl_type=0x800,
                                                                   nw_dst="10.0.0.1", nw_src="10.0.0.6")))
      elif dpid == 0x1:
        if destinIP == "10.0.0.6" and packet.next.srcip == "10.0.0.1":
          # rule to allow h1 and h6 for telnet
          if packet.next.payload.dstport == 23:
            event.connection.send(of.ofp_flow_mod(action=of.ofp_action_output(port=3),
                                                  priority=42, idle_timeout=30, hard_timeout=0,
                                                  match=of.ofp_match(dl_type=0x800, nw_proto=6,
                                                                     tp_dst=23,
                                                                     nw_dst="10.0.0.6",
                                                                     nw_src="10.0.0.1", )))
          # rule to allow h1 and h6 for ssh
          elif packet.next.payload.dstport == 22:
            event.connection.send(of.ofp_flow_mod(action=of.ofp_action_output(port=3),
                                                  priority=42, idle_timeout=30, hard_timeout=0,
                                                  match=of.ofp_match(dl_type=0x800, nw_proto=6,
                                                                     tp_dst=22,
                                                                     nw_dst="10.0.0.6",
                                                                     nw_src="10.0.0.1", )))
        # rule so any type of packets can be sent to h1 from h6
        elif destinIP == "10.0.0.1" and packet.next.srcip == "10.0.0.6":
          event.connection.send(of.ofp_flow_mod(action=of.ofp_action_output(port=1),
                                                priority=42, idle_timeout=30, hard_timeout=0,
                                                match=of.ofp_match(dl_type=0x800,
                                                                   nw_dst="10.0.0.1",
                                                                   nw_src="10.0.0.6")))
        # rule h1-> load bal server
        elif destinIP == "10.0.0.10" and packet.next.srcip == "10.0.0.1" and packet.next.payload.dstport == 80:
          actions = []
          actions.append(of.ofp_action_output(port=4))
          match = of.ofp_match.from_packet(packet, inport)

          msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                                idle_timeout=30,
                                hard_timeout=0,
                                data=event.ofp,
                                actions=actions,
                                match=match)
          event.connection.send(msg)
        elif destinIP == "10.0.0.1" and packet.next.srcip == "10.0.0.10" and packet.next.payload.srcport == 80:
          actions = []
          actions.append(of.ofp_action_output(port=1))
          match = of.ofp_match.from_packet(packet, inport)

          msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                                idle_timeout=30,
                                hard_timeout=0,
                                data=event.ofp,
                                actions=actions,
                                match=match)
          event.connection.send(msg)
      elif dpid == 0x5:
        if destinIP == "10.0.0.6" and packet.next.srcip == "10.0.0.1":
          # rule to allow h1 and h6 for telnet
          if packet.next.payload.dstport == 23:
            event.connection.send(of.ofp_flow_mod(action=of.ofp_action_output(port=3),
                                                  priority=42, idle_timeout=30, hard_timeout=0,
                                                  match=of.ofp_match(dl_type=0x800, nw_proto=6,
                                                                     tp_dst=23,
                                                                     nw_dst="10.0.0.6",
                                                                     nw_src="10.0.0.1", )))
          # rule to allow h1 and h6 for ssh
          elif packet.next.payload.dstport == 22:
            event.connection.send(of.ofp_flow_mod(action=of.ofp_action_output(port=3),
                                                  priority=42, idle_timeout=30, hard_timeout=0,
                                                  match=of.ofp_match(dl_type=0x800, nw_proto=6,
                                                                     tp_dst=22,
                                                                     nw_dst="10.0.0.6",
                                                                     nw_src="10.0.0.1", )))
        # rule so any type of packets can be sent to h1 from h6
        elif destinIP == "10.0.0.1" and packet.next.srcip == "10.0.0.6":
          event.connection.send(of.ofp_flow_mod(action=of.ofp_action_output(port=1),
                                                priority=42, idle_timeout=30, hard_timeout=0,
                                                match=of.ofp_match(dl_type=0x800,
                                                                   nw_dst="10.0.0.1",
                                                                   nw_src="10.0.0.6")))
          # rule h1-> load bal server
        elif destinIP == "10.0.0.10" and packet.next.srcip == "10.0.0.1" and packet.next.payload.dstport == 80:
          actions = []
          actions.append(of.ofp_action_output(port=3))
          match = of.ofp_match.from_packet(packet, inport)

          msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                                idle_timeout=30,
                                hard_timeout=0,
                                data=event.ofp,
                                actions=actions,
                                match=match)
          event.connection.send(msg)
          # rule load balancer server -> h1
        elif destinIP == "10.0.0.1" and packet.next.srcip == "10.0.0.10" and packet.next.payload.srcport == 80:
          actions = []
          actions.append(of.ofp_action_output(port=1))
          match = of.ofp_match.from_packet(packet, inport)

          msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                                idle_timeout=30,
                                hard_timeout=0,
                                data=event.ofp,
                                actions=actions,
                                match=match)
          event.connection.send(msg)
      elif dpid == 0x8:
        tcpp = packet.find('tcp')
        if tcpp:
          #testing if packet from one of the load balncer hosts
          if packet.next.srcip == "10.0.0.7" or packet.next.srcip == "10.0.0.8" and packet.next.payload.srcport == 80 and packet.next.dstip == "10.0.0.1":
            print ("changing info to server from %s to 10.0.0.10", packet.next.srcip)
            #checking where the packet came from and setting the variable to it
            if packet.next.srcip == "10.0.0.7":
                self.TEST = 1
            else:
                self.TEST = 2
            actions = []
            #adding flow rule to set mac/ip to the server mac/ip and set outport
            actions.append(of.ofp_action_dl_addr.set_src("00:00:00:11:22:33"))
            actions.append(of.ofp_action_nw_addr.set_src("10.0.0.10"))
            actions.append(of.ofp_action_output(port=3))
            match = of.ofp_match.from_packet(packet, inport)

            msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                                  idle_timeout=30,
                                  hard_timeout=0,
                                  data=event.ofp,
                                  actions=actions,
                                  match=match)
            event.connection.send(msg)
          elif destinIP == "10.0.0.10" and packet.next.srcip == "10.0.0.1" and packet.next.payload.dstport == 80:
            #h7 and h8 mac addresses and ips
            macArray = ["56:8a:3f:a2:ca:e4", "32:31:e4:5c:7b:d5"]
            ipArray = ["10.0.0.7", "10.0.0.8"]
            print "random number = ", self.TEST
            print "entered"
            actions = []
            #adding flow rule that sets the mac destination address, ip address and outport to either h7 or h8 depending on variable
            actions.append(of.ofp_action_dl_addr.set_dst(macArray[self.TEST-1]))
            actions.append(of.ofp_action_nw_addr.set_dst(ipArray[self.TEST-1]))
            actions.append(of.ofp_action_output(port=self.TEST))
            match = of.ofp_match.from_packet(packet, inport)

            msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                                  idle_timeout=30,
                                  hard_timeout=0,
                                  data=event.ofp,
                                  actions=actions,
                                  match=match)
            event.connection.send(msg)

      # Send any waiting packets...
      self._send_lost_buffers(dpid, packet.next.srcip, packet.src, inport)

      # Learn or update port/MAC info
      if packet.next.srcip in self.arpTable[dpid]:
        if self.arpTable[dpid][packet.next.srcip] != (inport, packet.src):
          log.info("%i %i RE-learned %s", dpid,inport,packet.next.srcip)

      else:
        log.debug("%i %i learned %s", dpid,inport,packet.next.srcip)
      self.arpTable[dpid][packet.next.srcip] = Entry(inport, packet.src)

      # Try to forward
      dstaddr = packet.next.dstip
      if dstaddr in self.arpTable[dpid]:
        # We have info about what port to send it out on...

        prt = self.arpTable[dpid][dstaddr].port
        mac = self.arpTable[dpid][dstaddr].mac
        if prt == inport:
          log.warning("%i %i not sending packet for %s back out of the "
                      "input port" % (dpid, inport, dstaddr))
          actions = []
          actions.append(of.ofp_action_dl_addr.set_dst(mac))
          #actions.append(of.ofp_action_output(port=3))

          match = of.ofp_match.from_packet(packet, inport)

          msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                                idle_timeout=FLOW_IDLE_TIMEOUT,
                                hard_timeout=of.OFP_FLOW_PERMANENT,
                                buffer_id=event.ofp.buffer_id,
                                actions=actions,
                                match=match)
          event.connection.send(msg.pack())
        else:
          log.debug("%i %i installing flow for %s => %s out port %i"
                    % (dpid, inport, packet.next.srcip, dstaddr, prt))

          actions = []
          actions.append(of.ofp_action_dl_addr.set_dst(mac))
          actions.append(of.ofp_action_output(port = prt))

          match = of.ofp_match.from_packet(packet, inport)

          msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                                idle_timeout=FLOW_IDLE_TIMEOUT,
                                hard_timeout=of.OFP_FLOW_PERMANENT,
                                buffer_id=event.ofp.buffer_id,
                                actions=actions,
                                match=match)
          event.connection.send(msg.pack())
      elif self.arp_for_unknowns:
        # We don't know this destination.
        # First, we track this buffer so that we can try to resend it later
        # if we learn the destination, second we ARP for the destination,
        # which should ultimately result in it responding and us learning
        # where it is

        # Add to tracked buffers
        if (dpid,dstaddr) not in self.lost_buffers:
          self.lost_buffers[(dpid,dstaddr)] = []
        bucket = self.lost_buffers[(dpid,dstaddr)]
        entry = (time.time() + MAX_BUFFER_TIME,event.ofp.buffer_id,inport)
        bucket.append(entry)
        while len(bucket) > MAX_BUFFERED_PER_IP: del bucket[0]

        # Expire things from our outstanding ARP list...
        self.outstanding_arps = {k:v for k,v in
         self.outstanding_arps.iteritems() if v > time.time()}

        # Check if we've already ARPed recently
        if (dpid,dstaddr) in self.outstanding_arps:
          # Oop, we've already done this one recently.
          return

        # And ARP...
        self.outstanding_arps[(dpid,dstaddr)] = time.time() + 4

        r = arp()
        r.hwtype = r.HW_TYPE_ETHERNET
        r.prototype = r.PROTO_TYPE_IP
        r.hwlen = 6
        r.protolen = r.protolen
        r.opcode = r.REQUEST
        r.hwdst = ETHER_BROADCAST
        r.protodst = dstaddr
        r.hwsrc = packet.src
        r.protosrc = packet.next.srcip
        e = ethernet(type=ethernet.ARP_TYPE, src=packet.src,
                     dst=ETHER_BROADCAST)
        e.set_payload(r)
        log.debug("%i %i ARPing for %s on behalf of %s" % (dpid, inport,
         r.protodst, r.protosrc))
        msg = of.ofp_packet_out()
        msg.data = e.pack()
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        msg.in_port = inport
        event.connection.send(msg)

    elif isinstance(packet.next, arp):
      a = packet.next
      log.debug("%i %i ARP %s %s => %s", dpid, inport,
       {arp.REQUEST:"request",arp.REPLY:"reply"}.get(a.opcode,
       'op:%i' % (a.opcode,)), a.protosrc, a.protodst)

      if a.prototype == arp.PROTO_TYPE_IP:
        if a.hwtype == arp.HW_TYPE_ETHERNET:
          if a.protosrc != 0:

            # Learn or update port/MAC info
            if a.protosrc in self.arpTable[dpid]:
              if self.arpTable[dpid][a.protosrc] != (inport, packet.src):
                log.info("%i %i RE-learned %s", dpid,inport,a.protosrc)

            else:
              log.debug("%i %i learned %s", dpid,inport,a.protosrc)
            self.arpTable[dpid][a.protosrc] = Entry(inport, packet.src)

            # Send any waiting packets...
            self._send_lost_buffers(dpid, a.protosrc, packet.src, inport)

            if a.opcode == arp.REQUEST:
              # Maybe we can answer

              if a.protodst in self.arpTable[dpid]:
                # We have an answer...

                if not self.arpTable[dpid][a.protodst].isExpired():
                  # .. and it's relatively current, so we'll reply ourselves

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
                  e = ethernet(type=packet.type, src=dpid_to_mac(dpid),
                               dst=a.hwsrc)
                  e.set_payload(r)
                  log.debug("%i %i answering ARP for %s" % (dpid, inport,
                   r.protosrc))
                  msg = of.ofp_packet_out()
                  msg.data = e.pack()
                  msg.actions.append(of.ofp_action_output(port =
                                                          of.OFPP_IN_PORT))
                  msg.in_port = inport
                  event.connection.send(msg)
                  return

      # Didn't know how to answer or otherwise handle this ARP, so just flood it
      log.debug("%i %i flooding ARP %s %s => %s" % (dpid, inport,
       {arp.REQUEST:"request",arp.REPLY:"reply"}.get(a.opcode,
       'op:%i' % (a.opcode,)), a.protosrc, a.protodst))

      msg = of.ofp_packet_out(in_port = inport, data = event.ofp,
          action = of.ofp_action_output(port = of.OFPP_FLOOD))
      event.connection.send(msg)

def _handle_ConnectionUp(event):
        #dpid = event.connection.dpid
        # printing the dpid
        # log.info("Switch with DPID of %s has come up.",dpid_to_str(event.dpid))
        print("Switch with DPID of %s has come up." % (dpid_to_str(event.dpid)))

        # printing the dpid in hex
        # log.info("Switch with DPID in HEX format of %s has come up." % (hex(event.dpid)))
        print("Switch with DPID in HEX format of %s has come up." % (hex(event.dpid)))

        """
        adding proactive flow rules to switches
        idle and hard timeouts set to 0 in all rules to make them permanent
        """
        if event.dpid == 0x5:
            """
            rules to allow h1 and h2 to communicate
            """
            #packet has to be IPv4, match h1/h2 source ip, match h1/h2 destination ip, match in port of either
            event.connection.send(
                of.ofp_flow_mod(action=of.ofp_action_output(port=2), priority=1000, idle_timeout=0, hard_timeout=0,
                                match=of.ofp_match(dl_type=0x800, nw_dst="10.0.0.2", nw_src="10.0.0.1", in_port=1)))
            event.connection.send(
                of.ofp_flow_mod(action=of.ofp_action_output(port=1), priority=1000, idle_timeout=0, hard_timeout=0,
                                match=of.ofp_match(dl_type=0x800, nw_dst="10.0.0.1", nw_src="10.0.0.2", in_port=2)))
            """
            rules to allow h1 and h5 for ssh/telnet
            """
            event.connection.send(of.ofp_flow_mod(action=of.ofp_action_output(port=3),
                                                  priority=1000, idle_timeout=0, hard_timeout=0,
                                                  match=of.ofp_match(dl_type=0x800, nw_proto=6, tp_dst=22,
                                                                     nw_dst="10.0.0.5", nw_src="10.0.0.1")))
            event.connection.send(of.ofp_flow_mod(action=of.ofp_action_output(port=1),
                                                  priority=1000, idle_timeout=0, hard_timeout=0,
                                                  match=of.ofp_match(dl_type=0x800, nw_proto=6, tp_src=22,
                                                                     nw_dst="10.0.0.1", nw_src="10.0.0.5")))
            event.connection.send(of.ofp_flow_mod(action=of.ofp_action_output(port=3),
                                                  priority=1000, idle_timeout=0, hard_timeout=0,
                                                  match=of.ofp_match(dl_type=0x800, nw_proto=6, tp_dst=23,
                                                                     nw_dst="10.0.0.5", nw_src="10.0.0.1")))
            event.connection.send(of.ofp_flow_mod(action=of.ofp_action_output(port=1),
                                                  priority=1000, idle_timeout=0, hard_timeout=0,
                                                  match=of.ofp_match(dl_type=0x800, nw_proto=6, tp_src=23,
                                                                     nw_dst="10.0.0.1", nw_src="10.0.0.5")))
            """
            rule to stop h1 -> h5 other than telnet/ssh
            """
            event.connection.send(of.ofp_flow_mod(priority=990, idle_timeout=0, hard_timeout=0,
                                                  match=of.ofp_match(dl_type=0x800,
                                                                     nw_dst="10.0.0.5", nw_src="10.0.0.1")))
            """
            redundant paths to other switches with lower priority
            """
            # s5 -> spine switch 2
            event.connection.send(of.ofp_flow_mod(action=of.ofp_action_output(port=4),
                                                  priority=950, idle_timeout=0, hard_timeout=0,
                                                  match=of.ofp_match(dl_type=0x800, nw_proto=6, tp_dst=22,
                                                                     nw_dst="10.0.0.5", nw_src="10.0.0.1")))
            event.connection.send(of.ofp_flow_mod(action=of.ofp_action_output(port=4),
                                                  priority=950, idle_timeout=0, hard_timeout=0,
                                                  match=of.ofp_match(dl_type=0x800, nw_proto=6, tp_dst=23,
                                                                     nw_dst="10.0.0.5", nw_src="10.0.0.1")))
            # s5 -> spine switch 3
            event.connection.send(of.ofp_flow_mod(action=of.ofp_action_output(port=5),
                                                  priority=900, idle_timeout=0, hard_timeout=0,
                                                  match=of.ofp_match(dl_type=0x800, nw_proto=6, tp_dst=22,
                                                                     nw_dst="10.0.0.5", nw_src="10.0.0.1")))
            event.connection.send(of.ofp_flow_mod(action=of.ofp_action_output(port=5),
                                                  priority=900, idle_timeout=0, hard_timeout=0,
                                                  match=of.ofp_match(dl_type=0x800, nw_proto=6, tp_dst=23,
                                                                     nw_dst="10.0.0.5", nw_src="10.0.0.1")))
            # s5 -> spine switch 4
            event.connection.send(of.ofp_flow_mod(action=of.ofp_action_output(port=6),
                                                  priority=850, idle_timeout=0, hard_timeout=0,
                                                  match=of.ofp_match(dl_type=0x800, nw_proto=6, tp_dst=22,
                                                                     nw_dst="10.0.0.5", nw_src="10.0.0.1")))
            event.connection.send(of.ofp_flow_mod(action=of.ofp_action_output(port=6),
                                                  priority=850, idle_timeout=0, hard_timeout=0,
                                                  match=of.ofp_match(dl_type=0x800, nw_proto=6, tp_dst=23,
                                                                     nw_dst="10.0.0.5", nw_src="10.0.0.1")))

            print("flow added to switch %s" % (dpid_to_str(event.dpid)))
        elif event.dpid == 0x1 or event.dpid == 0x2 or event.dpid == 0x3 or event.dpid == 0x4:
            """
            rules to allow h1 and h5 for ssh/telnet
            """
            event.connection.send(of.ofp_flow_mod(action=of.ofp_action_output(port=3),
                                                  priority=1000, idle_timeout=0, hard_timeout=0,
                                                  match=of.ofp_match(dl_type=0x800, nw_proto=6, tp_dst=22,
                                                                     nw_dst="10.0.0.5", nw_src="10.0.0.1")))
            event.connection.send(of.ofp_flow_mod(action=of.ofp_action_output(port=1),
                                                  priority=1000, idle_timeout=0, hard_timeout=0,
                                                  match=of.ofp_match(dl_type=0x800, nw_proto=6, tp_src=22,
                                                                     nw_dst="10.0.0.1", nw_src="10.0.0.5")))
            event.connection.send(of.ofp_flow_mod(action=of.ofp_action_output(port=3),
                                                  priority=1000, idle_timeout=0, hard_timeout=0,
                                                  match=of.ofp_match(dl_type=0x800, nw_proto=6, tp_dst=23,
                                                                     nw_dst="10.0.0.5", nw_src="10.0.0.1")))
            event.connection.send(of.ofp_flow_mod(action=of.ofp_action_output(port=1),
                                                  priority=1000, idle_timeout=0, hard_timeout=0,
                                                  match=of.ofp_match(dl_type=0x800, nw_proto=6, tp_src=23,
                                                                     nw_dst="10.0.0.1", nw_src="10.0.0.5")))
            print("flows added to switch %s" % (dpid_to_str(event.dpid)))
        elif event.dpid == 0x7:
            #rules to allow h1 and h5 for ssh/telnet
            event.connection.send(of.ofp_flow_mod(action=of.ofp_action_output(port=1),
                                                  priority=1000, idle_timeout=0, hard_timeout=0,
                                                  match=of.ofp_match(dl_type=0x800, nw_proto=6, tp_dst=22,
                                                                     nw_dst="10.0.0.5", nw_src="10.0.0.1")))
            event.connection.send(of.ofp_flow_mod(action=of.ofp_action_output(port=3),
                                                  priority=1000, idle_timeout=0, hard_timeout=0,
                                                  match=of.ofp_match(dl_type=0x800, nw_proto=6, tp_src=22,
                                                                     nw_dst="10.0.0.1", nw_src="10.0.0.5")))
            event.connection.send(of.ofp_flow_mod(action=of.ofp_action_output(port=1),
                                                  priority=1000, idle_timeout=0, hard_timeout=0,
                                                  match=of.ofp_match(dl_type=0x800, nw_proto=6, tp_dst=23,
                                                                     nw_dst="10.0.0.5", nw_src="10.0.0.1")))
            event.connection.send(of.ofp_flow_mod(action=of.ofp_action_output(port=3),
                                                  priority=1000, idle_timeout=0, hard_timeout=0,
                                                  match=of.ofp_match(dl_type=0x800, nw_proto=6, tp_src=23,
                                                                     nw_dst="10.0.0.1", nw_src="10.0.0.5")))
            """
            redundant paths to other switches with lower priority
            """
            # s7 -> spine switch 2
            event.connection.send(of.ofp_flow_mod(action=of.ofp_action_output(port=4),
                                                  priority=950, idle_timeout=0, hard_timeout=0,
                                                  match=of.ofp_match(dl_type=0x800, nw_proto=6, tp_src=22,
                                                                     nw_dst="10.0.0.1", nw_src="10.0.0.5")))
            event.connection.send(of.ofp_flow_mod(action=of.ofp_action_output(port=4),
                                                  priority=950, idle_timeout=0, hard_timeout=0,
                                                  match=of.ofp_match(dl_type=0x800, nw_proto=6, tp_src=23,
                                                                     nw_dst="10.0.0.1", nw_src="10.0.0.5")))
            # s7 -> spine switch 3
            event.connection.send(of.ofp_flow_mod(action=of.ofp_action_output(port=5),
                                                  priority=900, idle_timeout=0, hard_timeout=0,
                                                  match=of.ofp_match(dl_type=0x800, nw_proto=6, tp_src=22,
                                                                     nw_dst="10.0.0.1", nw_src="10.0.0.5")))
            event.connection.send(of.ofp_flow_mod(action=of.ofp_action_output(port=5),
                                                  priority=900, idle_timeout=0, hard_timeout=0,
                                                  match=of.ofp_match(dl_type=0x800, nw_proto=6, tp_src=23,
                                                                     nw_dst="10.0.0.1", nw_src="10.0.0.5")))
            # s7 -> spine switch 4
            event.connection.send(of.ofp_flow_mod(action=of.ofp_action_output(port=6),
                                                  priority=850, idle_timeout=0, hard_timeout=0,
                                                  match=of.ofp_match(dl_type=0x800, nw_proto=6, tp_src=22,
                                                                     nw_dst="10.0.0.1", nw_src="10.0.0.5")))
            event.connection.send(of.ofp_flow_mod(action=of.ofp_action_output(port=6),
                                                  priority=850, idle_timeout=0, hard_timeout=0,
                                                  match=of.ofp_match(dl_type=0x800, nw_proto=6, tp_src=23,
                                                                     nw_dst="10.0.0.1", nw_src="10.0.0.5")))
            print("flows added to switch %s" % (dpid_to_str(event.dpid)))
        elif event.dpid == 0x6:
            """
            rules to stop h3 and h4 to communicating by adding no action to rule
            """
            event.connection.send(
                of.ofp_flow_mod(priority=1000, idle_timeout=0, hard_timeout=0,
                                match=of.ofp_match(dl_type=0x800, nw_dst="10.0.0.4", in_port=1)))
            event.connection.send(
                of.ofp_flow_mod(priority=1000, idle_timeout=0, hard_timeout=0,
                                match=of.ofp_match(dl_type=0x800, nw_dst="10.0.0.3", in_port=2)))
            print("flows added to switch %s" % (dpid_to_str(event.dpid)))


def launch (arp_for_unknowns=None):
  core.registerNew(sdnPox2)
  core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
