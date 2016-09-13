#!/usr/bin/python2
"""
Create a network and inject scanner agents.
"""

from __future__ import print_function, unicode_literals

import os
import time

from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import Node

CONSOLE_IP = '172.16.1.10/24'
BROKER_URL = 'amqp://guest@172.16.1.10/'


class LinuxRouter(Node):
    "A Node with IP forwarding enabled."

    def config(self, **params):
        super(LinuxRouter, self).config(**params)
        self.cmd('sysctl net.ipv4.ip_forward=1')

    def terminate(self):
        self.cmd('sysctl net.ipv4.ip_forward=0')
        super(LinuxRouter, self).terminate()


def run():
    "Test linux router"
    net = Mininet()  # controller is used by s1-s3

    router = LinuxRouter('r0')

    scanners = tuple(
        net.addHost(
            'scanner{:d}'.format(n),
            ip='172.16.{:d}.254/24'.format(n),
            defaultRoute='via 172.16.{:d}.1'.format(n))
        for n in range(1, 4))

    switches = tuple(net.addSwitch('s{:d}'.format(n)) for n in range(1, 4))

    for switch, n in zip(switches, range(1, 4)):
        net.addLink(
            switch, router,
            intfName2='r0-eth{:d}'.format(n),
            params2={'ip': '172.16.{:d}.1/24'.format(n)})

    for scanner, switch in zip(scanners, switches):
        net.addLink(scanner, switch)

    console = net.addHost(
        'console', ip=CONSOLE_IP, defaultRoute='via 172.16.1.1',
        inNamespace=False)
    net.addLink(console, switches[0])

    net.addController('c0')
    celery_bin = os.environ['CELERY_BIN']
    for host in net.hosts:
        if host.name.startswith('scanner'):
            cmd = 'C_FORCE_ROOT=yes {0} worker -A wanmap.tasks -b {1} -l INFO -n scanner@{2} -Q scans.{2} &'     # noqa
            cmd = cmd.format(celery_bin, BROKER_URL, host.name)
            host.cmd(cmd)
    router.cmd('iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT')
    router.cmd('iptables -A FORWARD -d 172.16.3.0/24 -j DROP')
    router.cmd('iptables -A INPUT ! -i r0-eth3 -d 172.16.3.1 -j DROP')
    net.run(_block_indefinitely)


def _block_indefinitely():
    while True:
        time.sleep(1)


if __name__ == '__main__':
    setLogLevel('info')
    run()
