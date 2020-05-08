from invoke import task
import lxc
import os
import shutil
import sys
import time


# TODO: Install chromedriver
WANMAP_DEPENDENCIES = '''
gcc libpq-dev postgresql postgresql-client redis
libffi-dev libssl-dev nmap python3-dev python3-pip python3-venv
'''.split()
MININET_DEPENDENCIES = '''
gcc make socat psmisc xterm openssh-client openssh-server iperf net-tools
iproute2 telnet python-setuptools cgroup-tools ethtool help2man pyflakes pylint
pep8 python-pexpect git pkg-config autoconf automake libtool libc6-dev
python-ipaddress debianutils
'''.split()
UTILITIES = '''curl tcpdump lsof strace bind9-utils'''.split()


if not os.geteuid() == 0:
    sys.exit('Must be invoked as root')

GUEST_NAME = 'wanmap-dev'


class WANMapGuest(lxc.Container):

    def create(self):
        super().create(
            template='download',
            args='-d ubuntu -r focal -a amd64'.split(),
            bdevtype='best')

    def isolate_net_from_host(self):
        self.append_config_item('lxc.network', '')
        self.append_config_item('lxc.network.type', 'empty')

    @property
    def rootfs(self):
        return self.get_config_item('lxc.rootfs.path')

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
    # Further steps to isolate the guest from any external network
    guest.run('rm -f /etc/resolv.conf')     # Clear out unreachable resolvers
    guest.run('systemctl mask NetworkManager firewalld')


@task(init_guest)
def install_guest_rpms(ctx):
    guest = WANMapGuest(GUEST_NAME)

    guest.run_args_with_host_net(['apt-get', 'update'])
    guest.run_args_with_host_net(
        ['apt-get', 'install', '-y'] + WANMAP_DEPENDENCIES)
    guest.run_args_with_host_net(
        ['apt-get', 'install', '-y'] + MININET_DEPENDENCIES)
    guest.run_args_with_host_net(
        ['apt-get', 'install', '-y'] + UTILITIES)


@task(install_guest_rpms)
def install_guest_mininet(ctx):
    guest = WANMapGuest(GUEST_NAME)

    ctx.run('git submodule update --init')
    guest.run_args(['bash', '-c', 'cd /wanmap/vendor/mininet; make distclean; make install'])


@task(install_guest_rpms)
def install_guest_virtualenv(ctx):
    guest = WANMapGuest(GUEST_NAME)

    # Wheels workaround setuptools_scm pip<9.0 naming issue
    guest.run('addgroup --system wanmap')
    guest.run('adduser --system --home /opt/wanmap --ingroup wanmap wanmap')
    guest.run('sudo -u wanmap python3 -m venv /opt/wanmap')
    guest.run_with_host_net(
        'sudo -u wanmap '
        '/opt/wanmap/bin/pip install --upgrade pip wheel')
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

    # Setup redis and postgresql
    guest.run('systemctl start redis')
    guest.run_args(
        ['sed', '-i', 's/port = 5433/port = 5432/',
         '/etc/postgresql/12/main/postgresql.conf'])
    guest.run('systemctl restart postgresql')
    guest.run('sudo -u postgres createuser -s wanmap')

    # Setup wanmap test suite
    guest.run('sudo -u wanmap createdb wanmap_test')
    guest.run(
        'sudo -u wanmap '
        '/opt/wanmap/bin/initialize_wanmap_db /wanmap/test.ini')

    # Setup wanmap application
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

    guest.run('systemctl start wanmap-console wanmap-fake-wan')


@task
def clean_guest(ctx):
    guest = WANMapGuest(GUEST_NAME)
    guest.stop()
    guest.destroy()
