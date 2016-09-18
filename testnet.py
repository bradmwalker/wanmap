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

CONSOLE_IP = '10.1.0.10/24'
BROKER_URL = 'amqp://guest@10.1.0.10/'


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


    scanners = tuple(
        net.addHost(
            'scanner{:d}'.format(n),
            ip='10.{:d}.0.254/24'.format(n),
            defaultRoute='via 10.{:d}.0.1'.format(n))
        for n in range(1, 3))

    for scanner, switch in zip(scanners, switches):
        net.addLink(scanner, switch)

    console = net.addHost(
        'console', ip=CONSOLE_IP, defaultRoute='via 10.1.0.1',
        inNamespace=False)
    net.addLink(console, switches[0])

    celery_bin = os.environ['CELERY_BIN']
    for host in net.hosts:
        if host.name.startswith('scanner'):
            cmd = '{0} worker -A wanmap.tasks -b {1} -l INFO -n scanner@{2} -Q scans.{2}'     # noqa
            cmd = cmd.format(celery_bin, BROKER_URL, host.name)
            cmd = "runuser -c -u wanmap '{0}' &".format(cmd)
            host.cmd(cmd)

    if interactive:
        net.interact()
    else:
        net.run(_block_indefinitely)


def _block_indefinitely():
    while True:
        time.sleep(1)


if __name__ == '__main__':
    main()
