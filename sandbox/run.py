#!/usr/bin/python3
"""
Create a network and inject scanner agents.
"""

from ipaddress import ip_interface
import logging
from signal import signal, SIGINT, SIGTERM
import subprocess
import sys
from time import sleep
from typing import Sequence

import libvirt
import pexpect

CONSOLE_IP = '10.1.0.10/24'


def main():
    logging.basicConfig(level=logging.INFO)
    hypervisor = libvirt.open('qemu:///system')
    vwan = VirtualWAN(hypervisor)
    for bridge in ('dc-to-branch', 'dc-to-dmz', 'dc-to-external'):
        vwan.add_bridge(bridge)
    for bridge in ('branch', 'dmz'):
        vwan.add_bridge(bridge)
    dc_subnets = [f'dc{i:02d}' for i in range(16)]
    for bridge in dc_subnets:
        vwan.add_bridge(bridge)
    vwan.add_router('dc', ['dc-to-external', 'dc-to-branch', 'dc-to-dmz', *dc_subnets])
    vwan.add_router('branch', ['dc-to-branch', 'branch'])
    vwan.add_router('dmz', ['dc-to-dmz', 'dmz'])
    vwan.add_anchor('dc00', CONSOLE_IP)
    vwan.add_scanner('scanner1', 'dc00', '10.1.0.254/20')
    vwan.add_scanner('scanner2', 'branch', '10.2.0.254/20')
    vwan.add_scanner('dmzscanner', 'dmz', '203.0.113.254/24')
    vwan.add_scanner('external', 'dc-to-external', '198.51.100.2/30')
    vwan.run()
    while True:
        sleep(1)


class VirtualWAN:

    def __init__(self, hypervisor: libvirt.virConnect):
        self._hypervisor = hypervisor
        self._anchor = None
        self._bridges = {}
        self._routers = {}
        self._scanners = {}

        signal(SIGINT, self.signalled_exit)
        signal(SIGTERM, self.signalled_exit)

    def add_anchor(self, bridge: str, ip_address: str):
        self._anchor = Anchor(self._bridges[bridge], ip_address)

    def add_bridge(self, name: str):
        self._bridges[name] = Bridge(name)

    def add_router(self, name: str, bridges: Sequence[str] = ()):
        bridges = [self._bridges[bridge] for bridge in bridges]
        self._routers[name] = Router(name, bridges)

    def add_scanner(self, name: str, bridge: str, ip_address: str):
        bridge = self._bridges[bridge]
        self._scanners[name] = Scanner(name, bridge, ip_address)

    def run(self):
        for bridge in self._bridges.values():
            bridge.start(self._hypervisor)
        if self._anchor is not None:
            self._anchor.start()
        for scanner in self._scanners.values():
            scanner.start()
        for router in self._routers.values():
            router.start(self._hypervisor)
        logging.info('Virtual WAN initialization complete')

    def cleanup(self):
        for router in self._routers.values():
            router.stop()
        for scanner in self._scanners.values():
            scanner.stop()
        if self._anchor is not None:
            self._anchor.stop()
        for bridge in self._bridges.values():
            bridge.stop()

    def signalled_exit(self, signum, frame):
        assert signum in (SIGINT, SIGTERM)
        self.cleanup()
        sys.exit(0)


class Bridge:

    def __init__(self, name):
        self.name = name

    def start(self, hypervisor: libvirt.virConnect):
        self._network = hypervisor.networkCreateXML(self.xml)

    def stop(self):
        self._network.destroy()

    @property
    def xml(self) -> str:
        return f'''<network>
  <name>{self.name}</name>
  <bridge name="{self.name}"/>
</network>
'''


class Anchor:

    def __init__(self, bridge: Bridge, ip_address: str):
        self._bridge = bridge
        self._ip_address = ip_address

    def start(self):
        subprocess.call(
            'ip link add dev anchor type veth peer name rohcna', shell=True)
        subprocess.call(
            f'ip link set dev rohcna master {self._bridge.name}', shell=True)
        subprocess.call(
            f'ip addr add {self._ip_address} dev anchor', shell=True)
        subprocess.call('ip link set dev anchor up', shell=True)
        subprocess.call('ip link set dev rohcna up', shell=True)

    def stop(self):
        subprocess.call('ip link set dev anchor down', shell=True)
        subprocess.call('ip link set dev rohcna down', shell=True)
        subprocess.call('ip link del dev anchor', shell=True)


class Router:

    def __init__(self, name: str, bridges: Sequence[Bridge] = ()):
        self._name = name
        self._bridges = bridges

    def start(self, hypervisor: libvirt.virConnect):
        self._guest = hypervisor.createXML(self.xml, 0)
        # TODO: Parallelize router startup and configuration
        self.configure()

    def stop(self):
        self._guest.destroy()

    @property
    def xml(self) -> str:
        return f'''<domain type='kvm'>
  <name>{self._name}</name>
  <memory>524288</memory>
  <vcpu>1</vcpu>
  <os>
    <type arch='x86_64' machine='pc'>hvm</type>
    <boot dev='hd'/>
    <boot dev='cdrom'/>
  </os>
  <clock offset='utc'/>
  <on_poweroff>destroy</on_poweroff>
  <on_reboot>restart</on_reboot>
  <on_crash>destroy</on_crash>
  <devices>
    <emulator>/usr/bin/qemu-system-x86_64-spice</emulator>
    <disk type='file' device='cdrom'>
      <source file='/vyos-rolling-latest.iso'/>
      <target dev='hdc' bus='ide'/>
    </disk>
''' + self._interface_xml + '''
    <serial type='pty'/>
    <graphics type='vnc' port='-1' listen='127.0.0.1'/>
  </devices>
</domain>
'''

    @property
    def _interface_xml(self) -> str:
        return ''.join(
            f'''<interface type='bridge'>
  <source bridge='{bridge.name}'/>
</interface>'''
            for bridge in self._bridges)

    def configure(self):
        console = pexpect.spawn(
            f'virsh -c qemu:///system console {self._name}',
            # Allow bootup time
            timeout=60)
        console.sendline('')
        console.expect('.+ login: ')
        console.sendline('vyos')
        console.expect('Password: ')
        console.sendline('vyos')
        console.expect(r'vyos@.+:~\$ ')
        console.sendline('cat > vyos.config')
        with open(f'{self._name}.config', 'rt') as file_:
            for line in file_.readlines():
                console.send(line)
        console.send('')
        console.sendline('configure')
        console.expect('vyos@.+# ')
        console.sendline('load vyos.config')
        console.expect('vyos@.+# ')
        console.sendline('commit')
        console.expect('vyos@.+# ')
        console.sendline('exit')
        console.expect(r'vyos@.+:~\$ ')
        console.sendline('exit')
        console.sendline('exit')
        console.close()


class Scanner:

    def __init__(self, name: str, bridge: Bridge, ip_address: str):
        self.name = name
        self._bridge = bridge
        self._ip_address = ip_interface(ip_address)

    def start(self):
        self._guest = guest = pexpect.spawn('unshare -nu', timeout=None)
        logging.info('Running scanner %s with pid %d', self.name, self._guest.pid)
        host = pexpect.spawn('bash')
        host.sendline(
            f'ip link add dev eth0 netns {guest.pid} type veth '
            f'peer name {self.name}')
        host.sendline(
            f'ip link set dev {self.name} master {self._bridge.name}')
        host.sendline(f'ip link set dev {self.name} up')
        guest.sendline(f'ip addr add dev eth0 {self._ip_address}')
        guest.sendline(f'ip link set dev eth0 up')
        gateway = next(self._ip_address.network.hosts())
        guest.sendline(f'ip route add default via {gateway}')
        host.terminate()
        self.configure()

    def configure(self):
        self._guest.sendline(f'hostname {self.name}')
        # TODO: source file
        with open(f'{self.name}.sh', 'rt') as file_:
            for line in file_.readlines():
                self._guest.send(line)

    def stop(self):
        self._guest.sendintr()
        self._guest.terminate()


if __name__ == '__main__':
    main()
