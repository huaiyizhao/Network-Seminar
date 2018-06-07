#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.cli import CLI

# Mininet will assign an IP address for each interface of a node 
# automatically, but hub or switch does not need IP address.
def clearIP(n):
    for iface in n.intfList():
        n.cmd('ifconfig %s 0.0.0.0' % (iface))

class BroadcastTopo(Topo):
    def build(self):
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        #h3 = self.addHost('h3')
        b1 = self.addHost('b1')
	b2 = self.addHost('b2')
	b3 = self.addHost('b3')

        self.addLink(h1, b1, bw=10)
        self.addLink(h2, b2, bw=10)
        #self.addLink(h3, b1, bw=10)
	self.addLink(b1, b2, bw=20)
	self.addLink(b2, b3, bw=20)
	self.addLink(b1, b3, bw=20)

if __name__ == '__main__':
    topo = BroadcastTopo()
    net = Mininet(topo = topo, link = TCLink, controller = None) 

    h1, h2, b1, b2, b3 = net.get('h1', 'h2', 'b1', 'b2', 'b3')
    h1.cmd('ifconfig h1-eth0 10.0.0.1/8')
    h2.cmd('ifconfig h2-eth0 10.0.0.2/8')
    b1.cmd('ifconfig b1-eth0 10.0.0.5/8')
    b2.cmd('ifconfig b2-eth0 10.0.0.6/8')
    b3.cmd('ifconfig b3-eth0 10.0.0.7/8')
    clearIP(b1)
    clearIP(b2)
    clearIP(b3)

    h1.cmd('./disable_offloading.sh')
    h2.cmd('./disable_offloading.sh')
    #h3.cmd('./disable_offloading.sh')
    b1.cmd('./hub &')
    b2.cmd('./hub &')
    b3.cmd('./hub &')

    net.start()
    CLI(net)
    net.stop()
