#!/usr/bin/python3
"""
Create a network and inject scanner agents.
"""

import libvirt
import pexpect
import subprocess
import sys


def main():
    try:
        conn = libvirt.open('qemu:///system')
    except libvirt.libvirtError:
        print('Failed to open connection to the hypervisor')
        sys.exit(1)

    network = bridge_xml('vw001')
    network = conn.networkCreateXML(network)
    guest = create_router('dc')
    guest = conn.createXML(guest, 0)
    upload_vyos_config('dc')
    input()
    guest.destroy()
    network.destroy()


def create_router(name: str):
    guest = f'''<domain type='kvm'>
  <name>{name}</name>
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
    return guest


def bridge_xml(name: str) -> str:
    return f'''<network>
  <name>{name}</name>
  <bridge name="{name}"/>
</network>
'''


def upload_vyos_config(name: str):
    # Timeout 60 for bootup
    console = pexpect.spawn(f'virsh -c qemu:///system console {name}', timeout=60)
    console.sendline('')
    console.expect('.+ login: ')
    console.sendline('vyos')
    console.expect('Password: ')
    console.sendline('vyos')
    console.expect(r'vyos@.+:~\$ ')
    console.sendline('cat > vyos.config')
    with open(f'{name}.config', 'rt') as file_:
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
