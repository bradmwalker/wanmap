import ipaddress
import os.path
import re
from subprocess import PIPE, Popen

from celery import Celery
from celery.signals import celeryd_after_setup, worker_process_init
from celery.utils.log import get_task_logger
from paste.deploy.loadwsgi import appconfig
from pyramid.paster import setup_logging
import transaction

from .schema import DBSession, get_engine, Scan, Scanner, Subscan

__all__ = ['scan_workflow']

DB_URI = 'postgresql://wanmap@/wanmap'

Background = Celery()
Background.config_from_object('wanmap.celeryconfig')

SUDO = '/usr/bin/sudo'
NMAP = '/usr/bin/nmap'
NMAP_OUTPUT_OPTIONS = '-oG -'.split()

_logger = get_task_logger(__name__)


# TODO: Register Queue for hostname, and only initialize DB if console node
@worker_process_init.connect
def _init(signal, sender):
    here = os.path.dirname(__file__)
    settings_path = os.path.join(here, '../', 'development.ini')
    setup_logging(settings_path)
    config_uri = 'config:' + settings_path
    settings = appconfig(config_uri)
    get_engine(settings)


# TODO: Make a group/chord out of launching subscans
@Background.task(ignore_results=True)
def scan_workflow(scan_time):
    _logger.info('Dispatching Scan: {}'.format(scan_time))
    scan = DBSession.query(Scan).get(scan_time)
    nmap_options = scan.parameters.split(' ')
    for subscan in scan.subscans:
        subscan_targets = [target.target for target in subscan.targets]
        scanner_name = subscan.scanner.name
        queue_name = 'scans.{}'.format(scanner_name)

        exec_nmap_scan.apply_async(
            (nmap_options, subscan_targets), queue=queue_name,
            link=record_subscan.s(scan_time, scanner_name))


@Background.task
def exec_nmap_scan(nmap_options, targets):
    nmap_options, targets = list(nmap_options), list(targets)
    nmap_command = [SUDO, NMAP] + NMAP_OUTPUT_OPTIONS + nmap_options + targets
    _logger.info('Executing {!r}'.format(' '.join(nmap_command)))
    nmap = Popen(nmap_command, stdout=PIPE, universal_newlines=True)
    scan_result, err = nmap.communicate()
    return scan_result


# Need a transaction for each subscan. Scans can be written incrementally.
@Background.task(ignore_results=True)
def record_subscan(subscan_result, scan_time, scanner_name):
    subscan = DBSession.query(Subscan).get((scan_time, scanner_name))
    subscan.xml_results = subscan_result
    with transaction.manager:
        DBSession.add(subscan)


def get_scanner_interfaces():
    """Returns a list of routable interface IP addresses."""
    cmd = Popen(
        'ip -o -f inet address',
        stdout=PIPE, shell=True, universal_newlines=True)
    out, _ = cmd.communicate()

    addresses = []
    address_regex = re.compile(r'inet ([.\d/]+) ')
    for match in address_regex.finditer(out):
        address = ipaddress.ip_interface(match.group(1))
        if (not address.is_link_local and not address.is_loopback and
            not address.is_multicast):
            addresses.append(match.group(1))
    return addresses


@celeryd_after_setup.connect
def setup_direct_queue(sender, instance, **kwargs):
    queue_name = 'scans.{0}'.format(sender)
    instance.app.amqp.queues.select_add(queue_name)


@celeryd_after_setup.connect
def register_scanner(sender, instance, **kwargs):
    role, name = sender.split('@')
    if role == 'scanner':
        interfaces = get_scanner_interfaces()
        persist_scanner.delay(name, interfaces)


@Background.task(ignore_results=True)
def persist_scanner(name, interfaces):
    scanner = Scanner.create(name=name, interface_address=interfaces[0])
    with transaction.manager:
        DBSession.merge(scanner)
