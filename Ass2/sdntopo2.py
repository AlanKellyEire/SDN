#!/usr/bin/python

from optparse import OptionParser
import os
import sys
import time
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import irange,dumpNodeConnections
from mininet.log import setLogLevel
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.node import OVSSwitch, Controller, RemoteController

# Must run pox with spanning tree as the muliple paths causes no connectivity.
# sudo ~/pox_new/pox/pox.py policy openflow.discovery --eat-early-packets openflow.spanning_tree --no-flood --hold-down openflow.of_01 --port=6653

spineList = [ ]
leafList = [ ]
switchList = [ ]

#Data center Spine Leaf Network Topology
class dcSpineLeafTopo(Topo):
    "Linear topology of k switches, with one host per switch."

    def __init__(self, k, l, n, **opts):
        """Init.
        k: number of spine switches
        l: number of leaf switches
        n: number of switches"""

        super(dcSpineLeafTopo, self).__init__(**opts)

        self.k = k
        self.l = l
        self.n = n
        self.h = 1
        self.s = 1

        for i in irange(0, k-1):
            spineSwitch = self.addSwitch('s%s' % self.s)
            spineList.append(spineSwitch)
            self.s = (self.s + 1)

        for i in irange(0, l-1):
            leafSwitch = self.addSwitch('s%s' % self.s)
            self.s = (self.s + 1)
            leafList.append(leafSwitch)

            for x in range(0, n):
                host = self.addHost('h%s' % self.h)
                self.addLink(host, leafSwitch)
                print ("added Host %d" % self.h)
                self.h = (self.h + 1)
                print "link added between host %s and switch %s" % (host, leafSwitch)
        print "\n"
        for i in irange(0, k-1):
            for j in irange(0, l-1): #this is to go through the leaf switches
                self.addLink(spineList[i], leafList[j])
                print "link added between spine %s and leaf %s" % (spineList[i], leafList[j])

def simpleTest():

    #Creating topo
    topo = dcSpineLeafTopo(k=4, l=4, n=2)
    net = Mininet(topo, switch=OVSSwitch, controller=None, build=False)
    #default controller IP used is 127.0.0.1 / localhost address
    controllerIP = "127.0.0.1"
    #controller port used is 6653
    controllerPort = 6653
    # default port is 6633
    poxctrl = RemoteController("pox", ip=controllerIP, port=controllerPort)

    net.addController(poxctrl)
    net.build()
    net.start()
    print "Dumping host connections"
    dumpNodeConnections(net.hosts)

    CLI( net )
    net.stop()

if __name__ == '__main__':
    # Tell mininet to print useful information
    setLogLevel('info')
    simpleTest()
