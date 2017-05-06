#!/usr/bin/python2
"""
Create a network and inject scanner agents.
"""

from __future__ import print_function, unicode_literals

from ipaddress import ip_network, IPv4Network
from itertools import count
import os
import sys
import time

from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import Node, OVSBridge
# Circular dependency
from mininet.link import Link, TCLink

CELERY_PATH = os.environ['CELERY_PATH']
CONSOLE_IP = '10.1.0.10/24'
INTERNAL_BROKER_URL = 'amqp://guest@10.1.0.10/'
INTERNET_IP = '192.0.2.1'
EXTERNAL_SCANNER_IP = '198.51.100.2'
EXTERNAL_BROKER_URL = 'amqp://guest@192.0.2.1/'
DMZ_BLOCK = u'203.0.113.0/24'


def main():
    setLogLevel('info')
    args = sys.argv[1:]
    interactive = '-i' in args or '--interactive' in args
    net = FakeWAN()
    net.run(interactive)


class FakeWAN(object):

    def __init__(self):
        self._net = Mininet(switch=OVSBridge)
        self._switch_id_sequence = count()
        self._switches = {}

    def run(self, interactive):
        net = self._net

        dc_subnet = ip_network(u'10.1.0.0/24')
        dmz_subnet = ip_network(u'203.0.113.0/24')
        branch_subnet = ip_network(u'10.2.0.0/24')

        dc_dist = self.add_router('r0', dc_subnet)
        dmz_fw = self.add_router('dmz', dmz_subnet)
        branch_dist = self.add_router('r1', branch_subnet)

        external_scanner = net.addHost(
            'external',
            cls=ScannerNode, broker_url=EXTERNAL_BROKER_URL,
            ip='198.51.100.2/30')

        dc_to_branch = TCLink(
            dc_dist, branch_dist,
            intfName1='dc-to-branch', intfName2='branch-to-dc',
            delay=50000, bw=1.544)
        dc_to_branch.intf1.setIP('192.168.0.1/30')
        dc_dist.cmd('ip route add {} via 192.168.0.2'.format(str(branch_subnet)))
        dc_to_branch.intf2.setIP('192.168.0.2/30')
        branch_dist.setDefaultRoute('via 192.168.0.1')

        dc_to_external = Link(
            dc_dist, external_scanner,
            intfName1='dc-to-external', intfName2='external-to-dc')
        dc_to_external.intf1.setIP(INTERNET_IP, prefixLen=30)
        dc_dist.setDefaultRoute('dc-to-external')
        dc_to_external.intf2.setIP('198.51.100.2', prefixLen=30)
        external_scanner.setDefaultRoute('external-to-dc')

        dc_dist.cmd('iptables -t nat -A PREROUTING -i dc-to-external -p tcp -m tcp --dport 5672 -j DNAT --to 10.1.0.10')

        dc_to_dmz = Link(
            dc_dist, dmz_fw,
            intfName1='dc-to-dmz', intfName2='dmz-to-dc')
        dc_to_dmz.intf1.setIP('192.168.0.5/30')
        dc_dist.cmd('ip route add {} via 192.168.0.6'.format(str(dmz_subnet)))
        dc_to_dmz.intf2.setIP('192.168.0.6/30')
        dmz_fw.setDefaultRoute('via 192.168.0.5')
        dmz_fw.cmd('iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT')
        dmz_fw.cmd('iptables -A FORWARD -d 10.1.0.10 -m tcp -p tcp --dport amqp --syn -j ACCEPT')
        dmz_fw.cmd('iptables -A FORWARD -j DROP')

        scanner1 = net.addHost(
            'scanner1',
            cls=ScannerNode, broker_url=INTERNAL_BROKER_URL,
            ip='10.1.0.254/24', defaultRoute='via 10.1.0.1')
        net.addLink(scanner1, self._switches[dc_subnet])

        dmz_scanner = net.addHost(
            'dmzscanner',
            cls=ScannerNode, broker_url=INTERNAL_BROKER_URL,
            ip='203.0.113.254/24', defaultRoute='via 203.0.113.1')
        net.addLink(dmz_scanner, self._switches[dmz_subnet])

        scanner2 = net.addHost(
            'scanner2',
            cls=ScannerNode, broker_url=INTERNAL_BROKER_URL,
            ip='10.2.0.254/24', defaultRoute='via 10.2.0.1')
        net.addLink(scanner2, self._switches[branch_subnet])

        console = net.addHost(
            'console', ip=CONSOLE_IP, defaultRoute='via 10.1.0.1',
            inNamespace=False)
        net.addLink(console, self._switches[dc_subnet])

        if interactive:
            net.interact()
        else:
            net.run(_block_indefinitely)

    def add_router(self, name, subnet):
        assert isinstance(subnet, IPv4Network)
        router = LinuxRouter(name)
        self._net.hosts.append(router)
        self._net.nameToNode[name] = router

        switch = self._new_switch(subnet)
        gateway_address = '{}/{}'.format(next(subnet.hosts()), subnet.prefixlen)
        gateway_link = Link(router, switch)
        gateway_link.intf1.setIP(gateway_address)

        return router

    def _new_switch(self, subnet):
        assert isinstance(subnet, IPv4Network)
        switch_id = 's{:d}'.format(next(self._switch_id_sequence))
        switch = self._net.addSwitch(switch_id)
        self._switches[subnet] = switch
        return switch


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


def _block_indefinitely():
    while True:
        time.sleep(1)


if __name__ == '__main__':
    main()
