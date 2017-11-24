#!/usr/bin/python

"""
Simple Mininet script to create a single switch network.

With 10 hosts attached and a remote controller.
The switch is an Open vSwitch instance.
The subclass build method takes the number of hosts in the topology as a parameter.
The remote controller will be Pox.
The script calls the Mininet CLI.

Created By: Alan Kelly
Date: 27/10/2017


"""

from mininet.topo import Topo
from mininet.util import irange
from mininet.node import OVSSwitch, RemoteController
from mininet.cli import CLI
from mininet.net import Mininet
from mininet.log import setLogLevel
from mininet.util import dumpNodeConnections

class SingleSwitchTopo(Topo):
    #print Topo
    def build(self, n,**opts):
        switch = self.addSwitch("s1")
        for x in range(0, n):
         host = self.addHost('h%s' % (x + 1))
         self.addLink(host, switch)
               print ("added Host %d" % (x + 1))

def simpleTest():
    "Create and test a simple network"
    topo = SingleSwitchTopo(n=10)
    net = Mininet(topo, switch=OVSSwitch, controller=None,)
    #default controller IP used is 127.0.0.1 / localhost address
    controllerIP = "127.0.0.1"
    #controller port used is 6653
    controllerPort = 6653 
    # default port is 6633
    poxctrl = RemoteController("poxctrl", ip=controllerIP, port=controllerPort)
    net.addController(poxctrl)
    net.start()
    #print "Dumping host connections"
    #dumpNodeConnections(net.hosts)
    #Testing the network by pinging all nodes
    #print "Testing network connectivity"
    #net.pingAll()
    #Starting the mininet CLI
    CLI(net)
    net.stop()



if __name__ == '__main__':
    # Tell mininet to print useful information
    setLogLevel('info')
simpleTest()