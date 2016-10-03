#!/usr/bin/python2
"""
Create a network and inject scanner agents.
"""

from __future__ import print_function, unicode_literals

from ipaddress import ip_interface
import os
import sys
import time

from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import Node
# Circular dependency
from mininet.link import Link

CELERY_PATH = os.environ['CELERY_PATH']
CONSOLE_IP = '10.1.0.10/24'
INTERNAL_BROKER_URL = 'amqp://guest@10.1.0.10/'
INTERNET_IP = '192.0.2.1'
EXTERNAL_SCANNER_IP = '198.51.100.2'
EXTERNAL_BROKER_URL = 'amqp://guest@192.0.2.1/'


def main():
    setLogLevel('info')
    args = sys.argv[1:]
    interactive = '-i' in args or '--interactive' in args
    run(interactive)


class LinuxRouter(Node):
    "A Node with IP forwarding enabled."

    def config(self, **params):
        super(LinuxRouter, self).config(**params)
        self.cmd('sysctl net.ipv4.ip_forward=1')

    def terminate(self):
        self.cmd('sysctl net.ipv4.ip_forward=0')
        super(LinuxRouter, self).terminate()


class ScannerNode(Node):

    def config(self, broker_url, **params):
        super(ScannerNode, self).config(**params)
        cmd = '{0} worker -A wanmap.tasks -b {1} -l INFO -n scanner@{2} -X console'     # noqa
        cmd = cmd.format(CELERY_PATH, broker_url, self.name)
        cmd = "runuser -c -u wanmap '{0}' &".format(cmd)
        self.cmd(cmd)


def run(interactive):
    "Test linux router"
    net = Mininet()  # controller is used by s1-s2
    net.addController('c0')

    dc_gateway = ip_interface(u'10.1.0.1/24')
    dc_subnet = dc_gateway.network
    branch_gateway = ip_interface(u'10.2.0.1/24')
    branch_subnet = branch_gateway.network

    dc_dist = net.addHost('r0', cls=LinuxRouter, ip=str(dc_gateway))
    branch_dist = net.addHost('r1', cls=LinuxRouter, ip=str(branch_gateway))
    external_scanner = net.addHost(
        'external',
        cls=ScannerNode, broker_url=EXTERNAL_BROKER_URL,
        ip='198.51.100.2/30')

    switches = tuple(net.addSwitch('s{:d}'.format(n)) for n in range(2))
    net.addLink(switches[0], dc_dist)
    net.addLink(switches[1], branch_dist)

    dc_to_branch = Link(
        dc_dist, branch_dist,
        intfName1='dc-to-branch', intfName2='branch-to-dc')
    dc_to_branch.intf1.setIP('192.168.0.1/30')
    dc_dist.cmd('ip route add {} via 192.168.0.2'.format(str(branch_subnet)))
    dc_to_branch.intf2.setIP('192.168.0.2/30')
    branch_dist.cmd('ip route add 10.0.0.0/8 via 192.168.0.1')
    branch_dist.cmd('iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT')
    branch_dist.cmd('iptables -A FORWARD -d 10.2.0.0/24 -j DROP')
    branch_dist.cmd('iptables -A INPUT ! -i r1-eth0 -d 10.2.0.1 -j DROP')

    dc_to_external = Link(
        dc_dist, external_scanner,
        intfName1='dc-to-external', intfName2='external-to-dc')
    dc_to_external.intf1.setIP(INTERNET_IP, prefixLen=30)
    dc_dist.setDefaultRoute('dc-to-external')
    dc_to_external.intf2.setIP('198.51.100.2', prefixLen=30)
    external_scanner.setDefaultRoute('external-to-dc')

    dc_dist.cmd('iptables -t nat -A PREROUTING -i dc-to-external -p tcp -m tcp --dport 5672 -j DNAT --to 10.1.0.10')

    scanner1 = net.addHost(
        'scanner1',
        cls=ScannerNode, broker_url=INTERNAL_BROKER_URL,
        ip='10.1.0.254/24', defaultRoute='via 10.1.0.1')
    net.addLink(scanner1, switches[0])

    scanner2 = net.addHost(
        'scanner2',
        cls=ScannerNode, broker_url=INTERNAL_BROKER_URL,
        ip='10.2.0.254/24', defaultRoute='via 10.2.0.1')
    net.addLink(scanner2, switches[1])

    console = net.addHost(
        'console', ip=CONSOLE_IP, defaultRoute='via 10.1.0.1',
        inNamespace=False)
    net.addLink(console, switches[0])

    if interactive:
        net.interact()
    else:
        net.run(_block_indefinitely)


def _block_indefinitely():
    while True:
        time.sleep(1)


if __name__ == '__main__':
    main()
