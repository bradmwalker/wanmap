#!/usr/bin/python3
"""
Create a network and inject scanner agents.
"""

from typing import Sequence

import libvirt
import pexpect


def main():
    hypervisor = libvirt.open('qemu:///system')
    vwan = VirtualWAN(hypervisor)
    for bridge in ('dc-to-branch', 'branch'):
        vwan.add_bridge(bridge)
    dc_subnets = [f'dc{i:02d}' for i in range(16)]
    for bridge in dc_subnets:
        vwan.add_bridge(bridge)
    vwan.add_router('dc', ['dc-to-branch', *dc_subnets])
    vwan.add_router('branch', ['dc-to-branch', 'branch'])
    vwan.run()


class VirtualWAN:

    def __init__(self, hypervisor: libvirt.virConnect):
        self._hypervisor = hypervisor
        self._bridges = {}
        self._routers = {}

    def add_bridge(self, name: str):
        self._bridges[name] = Bridge(name)

    def add_router(self, name: str, bridges: Sequence[str] = ()):
        bridges = [self._bridges[bridge] for bridge in bridges]
        self._routers[name] = Router(name, bridges)

    def run(self):
        for bridge in self._bridges.values():
            bridge.start(self._hypervisor)
        for router in self._routers.values():
            router.start(self._hypervisor)
        input()
        self.cleanup()

    def cleanup(self):
        for router in self._routers.values():
            router.stop()
        for bridge in self._bridges.values():
            bridge.stop()


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


if __name__ == '__main__':
    main()
