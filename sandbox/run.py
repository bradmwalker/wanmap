#!/usr/bin/python3
"""
Create a network and inject scanner agents.
"""

import libvirt
import pexpect


def main():
    conn = libvirt.open('qemu:///system')
    dc_to_branch = Bridge('vw001')
    dc_to_branch.start(conn)
    dc = Router('dc')
    dc.start(conn)
    branch = Router('branch')
    branch.start(conn)
    input()
    branch.stop()
    dc.stop()
    dc_to_branch.stop()


class Router:

    def __init__(self, name: str):
        self._name = name

    def start(self, hypervisor: libvirt.virConnect):
        self._guest = hypervisor.createXML(self.xml, 0)
        # TODO: Parallelize router startup and configuration
        self.configure()

    def stop(self):
        self._guest.destroy()

    @property
    def xml(self):
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
    <interface type='bridge'>
      <source bridge='vw001'/>
    </interface>
    <serial type='pty'/>
    <graphics type='vnc' port='-1' listen='127.0.0.1'/>
  </devices>
</domain>
'''

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


if __name__ == '__main__':
    main()
