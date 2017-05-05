from invoke import task
import lxc
import os
import shutil
import sys
import time


WANMAP_DEPENDENCIES = '''
postgresql-server rabbitmq-server redis gcc redhat-rpm-config postgresql-devel
python3-devel python3-wheel nmap
'''.split()
MININET_DEPENDENCIES = '''
gcc make socat psmisc xterm openssh-clients iperf net-tools iproute telnet
python-setuptools libcgroup-tools ethtool help2man pyflakes pylint
python-pep8 python-pexpect git pkgconfig autoconf automake libtool glibc-devel
openvswitch python-ipaddress which
'''.split()
UTILITIES = '''tcpdump lsof strace bind-utils'''.split()


if not os.geteuid() == 0:
    sys.exit('Must be invoked as root')

# ctx.sudo('dnf install -y postgresql-devel')     # Wheel requirement

GUEST_NAME = 'wanmap-dev'


class WANMapGuest(lxc.Container):

    def create(self):
        super().create(
            template='download',
            args='-d fedora -r 24 -a amd64'.split(),
            bdevtype='best')

    def isolate_net_from_host(self):
        self.append_config_item('lxc.network', '')
        self.append_config_item('lxc.network.type', 'empty')

    @property
    def rootfs(self):
        return self.get_config_item('lxc.rootfs')

    def share_host_var_tmp(self):
        host_var_tmp_path = self.host_var_tmp_path
        os.makedirs(host_var_tmp_path, mode=0o1777, exist_ok=True)
        self.append_config_item(
            'lxc.mount.entry',
            '{} var/tmp none bind,create=dir 0 0'.format(host_var_tmp_path))

    @property
    def host_var_tmp_path(self):
        return '/var/tmp/{}'.format(self.name)

    def share_host_working_copy(self):
        self.append_config_item(
            'lxc.mount.entry',
            # Remap git repo to inside container
            '/wanmap wanmap none bind,create=dir 0 0')

    def run(self, command_string):
        self.run_args(command_string.split())

    def run_with_host_net(self, command_string):
        self.run_args_with_host_net(command_string.split())

    def run_args(self, args):
        self.attach_wait(lxc.attach_run_command, args)

    def run_args_with_host_net(self, args):
        container_resolv_conf = '{}/etc/resolv.conf'.format(self.rootfs)
        shutil.copy('/etc/resolv.conf', container_resolv_conf)
        self.attach_wait(
            lxc.attach_run_command, args,
            namespaces=(lxc.CLONE_NEWNS + lxc.CLONE_NEWIPC + lxc.CLONE_NEWPID + lxc.CLONE_NEWUTS),
        )
        shutil.copy('/dev/null', container_resolv_conf)


@task
def init_guest(ctx):
    guest = WANMapGuest(GUEST_NAME)
    guest.isolate_net_from_host()
    guest.share_host_var_tmp()
    guest.share_host_working_copy()
    guest.create()
    guest.start()
    time.sleep(3)


@task(init_guest)
def install_guest_rpms(ctx):
    guest = WANMapGuest(GUEST_NAME)

    guest.run_args_with_host_net(
        ['dnf', '-y', 'groupinstall', 'Minimal Install'])
    guest.run_args_with_host_net(
        ['dnf', '-y', 'install'] + WANMAP_DEPENDENCIES)
    guest.run_args_with_host_net(
        ['dnf', '-y', 'install'] + MININET_DEPENDENCIES)
    guest.run_args_with_host_net(
        ['dnf', '-y', 'install'] + UTILITIES)


@task(install_guest_rpms)
def install_guest_mininet(ctx):
    guest = WANMapGuest(GUEST_NAME)

    ctx.run('git submodule update --init')
    guest.run_args(['bash', '-c', 'cd /wanmap/vendor/mininet; make distclean; make install'])


@task(install_guest_rpms)
def install_guest_virtualenv(ctx):
    guest = WANMapGuest(GUEST_NAME)

    # Wheels workaround setuptools_scm pip<9.0 naming issue
    guest.run('adduser --system wanmap -m -d /opt/wanmap')
    guest.run('sudo -u wanmap pyvenv-3.5 /opt/wanmap')
    guest.run_with_host_net(
        'sudo -u wanmap '
        '/opt/wanmap/bin/pip install -r /wanmap/requirements.dev.txt')
    guest.run('mkdir -p /wanmap/wanmap.egg-info')
    guest.run('chmod 777 /wanmap/wanmap.egg-info')
    guest.run('chmod 666 /wanmap/wanmap.egg-info/*')
    guest.run('sudo -u wanmap /opt/wanmap/bin/pip install -e /wanmap')


@task(install_guest_mininet, install_guest_virtualenv)
def configure_guest(ctx):
    guest = WANMapGuest(GUEST_NAME)
    # Further steps to isolate the guest from any external network
    # Override unreachable DNS resolvers copied by the Fedora template
    guest.run('cp /dev/null /etc/resolv.conf')
    guest.run('systemctl mask NetworkManager firewalld')

    # Setup rabbitmq and postgresql
    guest.run_args(
        ['sed', '-re',
         's/%% \{loopback_users, \[\]\},/\{loopback_users, \[\]\}/',
         '-i', '/etc/rabbitmq/rabbitmq.config'])
    guest.run('postgresql-setup --initdb')
    guest.run('systemctl start postgresql')

    # Setup wanmap application
    guest.run('sudo -u postgres createuser -s wanmap')
    guest.run('sudo -u wanmap createdb wanmap')
    guest.run(
        'sudo -u wanmap '
        '/opt/wanmap/bin/initialize_wanmap_db /wanmap/development.ini')
    guest.run(
        'install -m 440 -o root -g root '
        '/wanmap/config/wanmap-agent /etc/sudoers.d')
    guest.run(
        'cp /wanmap/config/wanmap-console.service /etc/systemd/system')
    guest.run(
        'cp /wanmap/config/wanmap-fake-wan.service /etc/systemd/system')
    guest.run(
        'cp /wanmap/config/wanmap-task-queue.service /etc/systemd/system')
    guest.run('systemctl daemon-reload')

    # wanmap-fake-wan needs a delay after wanmap-console
    guest.run('systemctl start wanmap-console')
    time.sleep(15)
    guest.run('systemctl start wanmap-fake-wan')


@task
def clean_guest(ctx):
    guest = WANMapGuest(GUEST_NAME)
    guest.stop()
    guest.destroy()
