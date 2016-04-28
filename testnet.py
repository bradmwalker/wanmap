#!/usr/bin/python
"""
Create a network and inject scanner agents.
"""

from __future__ import print_function

from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.node import Node


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

    # root = Node('root', inNamespace=False)
    logical_address = '192.168.0.2/30'
    # router = LinuxRouter('r0', ip=logical_address)
    router = net.addHost('r0', cls=LinuxRouter, ip=logical_address)
    root = net.addHost('root', ip='192.168.0.1/30', inNamespace=False)
    net.addLink(root, router)

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

    net.addController('c0')
    net.start()
    for host in net.hosts:
        if host.name.startswith('scanner'):
            cmd = 'C_FORCE_ROOT=yes /home/user/.virtualenvs/wanmap/bin/celery worker -A wanmap.tasks -l INFO -n scanner@{0} -Q scans.{0} &'
            cmd = cmd.format(host.name)
            host.cmd(cmd)
    router.cmd('ip route add default via 192.168.0.1 dev r0-eth0')
    root.cmd('ip route add 172.16.0.0/12 via 192.168.0.2 dev root-eth0')
    CLI(net)
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    run()
