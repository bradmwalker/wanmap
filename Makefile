clean: cleandb cleanmb

cleandb:
	systemctl stop wanmap-console wanmap-task-queue
	sudo -u wanmap dropdb wanmap; sudo -u wanmap createdb wanmap;
	sudo -u wanmap venv/bin/initialize_wanmap_db development.ini
	sudo -u wanmap dropdb test_wanmap; sudo -u wanmap createdb test_wanmap;
	-chown wanmap:wanmap pytest_run.log
	sudo -u wanmap venv/bin/initialize_wanmap_db test.ini
	systemctl start wanmap-console wanmap-task-queue

cleanmb:
	rabbitmqctl stop_app
	rabbitmqctl reset
	rabbitmqctl start_app

container_run=lxc-attach -n wanmap-dev --
container_run_with_host_net=lxc-attach -n wanmap-dev -s 'MOUNT|PID|UTSNAME|IPC' --
container_root=/var/lib/lxc/wanmap-dev/rootfs
dev-base:
	mkdir -p /var/tmp/wanmap-dev
	chmod 1777 /var/tmp/wanmap-dev
	lxc-create -t fedora -n wanmap-dev -f lxc.config -B best -- -R 24
	lxc-start -n wanmap-dev
	sleep 3
	$(container_run_with_host_net) dnf -y groupinstall 'Minimal Install'
	# WANmap dependencies
	$(container_run_with_host_net) dnf -y install \
		postgresql-server rabbitmq-server redis \
		gcc redhat-rpm-config postgresql-devel python3-devel \
		nmap
	# Mininet dependencies
	$(container_run_with_host_net) dnf -y install \
		gcc make socat psmisc xterm openssh-clients iperf net-tools \
		iproute telnet python-setuptools libcgroup-tools \
		ethtool help2man pyflakes pylint python-pep8 python-pexpect \
		git pkgconfig autoconf automake libtool glibc-devel \
		openvswitch python-ipaddress which
	# Useful
	$(container_run_with_host_net) dnf -y install \
		tcpdump lsof strace bind-utils

	dnf install -y nginx
	-nginx -c $(shell realpath nginx.dev.conf)
	modprobe openvswitch

dev-virtualenv: dev-base
	$(container_run) adduser --system wanmap -d /opt/wanmap
	$(container_run) mkdir -p /opt/wanmap/venv
	$(container_run) chown -R wanmap:wanmap /opt/wanmap/venv
	$(container_run) runuser wanmap -c 'pyvenv-3.5 /opt/wanmap/venv'
	$(container_run_with_host_net) runuser wanmap -c '/opt/wanmap/venv/bin/pip install -r requirements.dev.txt'
	$(container_run) mkdir -p /opt/wanmap/wanmap.egg-info
	$(container_run) chmod 777 /opt/wanmap/wanmap.egg-info
	$(container_run) runuser wanmap -c '/opt/wanmap/venv/bin/pip install -e /opt/wanmap'

dev-image: dev-virtualenv
	$(container_run) dnf install -y make
	$(container_run) make develop -C /opt/wanmap

dev-install:
	# Override unreachable DNS resolvers copied by the Fedora template
	cp /dev/null /etc/resolv.conf
	(cd /opt/wanmap/vendor/openflow; ./boot.sh; ./configure; make install)
	(cd /opt/wanmap/vendor/mininet; make install)
	sed -re 's/%% \{loopback_users, \[\]\},/\{loopback_users, \[\]\}/'\
		-i /etc/rabbitmq/rabbitmq.config
	postgresql-setup --initdb
	systemctl start postgresql
	sudo -u postgres createuser -s wanmap
	systemctl mask NetworkManager firewalld

distclean:
	lxc-destroy -f -n wanmap-dev


develop: dev-install
	sudo -u wanmap createdb wanmap
	cp config/*.service -t /etc/systemd/system
	install -m 440 -o root -g root config/wanmap-agent /etc/sudoers.d
	systemctl daemon-reload
	sudo -u wanmap venv/bin/initialize_wanmap_db development.ini
	systemctl start wanmap-console wanmap-fake-wan
