import ipaddress
import os.path
import re
from subprocess import check_output

from celery import Celery
from celery.signals import celeryd_after_setup, worker_process_init
from celery.utils.log import get_task_logger
from pyramid.paster import get_appsettings, setup_logging

from .schema import Scan, Scanner, Subscan

__all__ = ['scan_workflow']

Background = Celery()
Background.config_from_object('wanmap.celeryconfig')

engine = None
dbsession_factory = None

SUDO = '/usr/bin/sudo'
NMAP = '/usr/bin/nmap'
NMAP_OUTPUT_OPTIONS = '-oX -'.split()

_logger = get_task_logger(__name__)


# TODO: Register Queue for hostname, and only initialize DB if console node
@worker_process_init.connect
def _init(signal, sender, **kwargs):
    from .schema import get_engine, get_session_factory
    global engine
    global dbsession_factory
    here = os.path.dirname(__file__)
    settings_path = os.path.join(here, '../', 'development.ini')
    setup_logging(settings_path)
    settings = get_appsettings(settings_path, name='wanmap')
    engine = get_engine(settings)
    dbsession_factory = get_session_factory(engine)


# TODO: Make a group/chord out of launching subscans
@Background.task(ignore_results=True)
def scan_workflow(scan_id):
    _logger.info('Dispatching Scan: {}'.format(scan_id))
    dbsession = dbsession_factory()
    scan = dbsession.query(Scan).get(scan_id)
    nmap_options = scan.parameters.split(' ')
    for subscan in scan.subscans:
        subscan_targets = [target.target for target in subscan.targets]
        scanner_name = subscan.scanner.name

        exec_nmap_scan.apply_async(
            (scan_id, scanner_name, nmap_options, subscan_targets),
            link=record_subscan.s(scan_id, scanner_name))


@Background.task
def exec_nmap_scan(scan_id, scanner_name, nmap_options, targets):
    nmap_options, targets = list(nmap_options), list(targets)
    nmap_command = [SUDO, NMAP] + NMAP_OUTPUT_OPTIONS + nmap_options + targets
    _logger.info('Executing {!r}'.format(' '.join(nmap_command)))
    return check_output(nmap_command, universal_newlines=True)


# Need a transaction for each subscan. Scans can be written incrementally.
@Background.task(ignore_results=True)
def record_subscan(subscan_result, scan_id, scanner_name):
    import transaction
    from .schema import get_tm_session
    with transaction.manager:
        dbsession = get_tm_session(dbsession_factory, transaction.manager)
        subscan = dbsession.query(Subscan).get((scan_id, scanner_name))
        subscan.xml_results = subscan_result
        dbsession.add(subscan)


def get_scanner_interfaces():
    """Returns a list of routable interface IP addresses."""
    out = check_output(
        'ip -o -f inet address'.split(), universal_newlines=True)

    addresses = []
    address_regex = re.compile(r'inet ([.\d/]+) ')
    for match in address_regex.finditer(out):
        address = ipaddress.ip_interface(match.group(1))
        if (not address.is_link_local and not address.is_loopback and
            not address.is_multicast):
            addresses.append(match.group(1))
    return addresses


@celeryd_after_setup.connect
def register_scanner(sender, instance, **kwargs):
    role, name = sender.split('@')
    if role == 'scanner':
        interfaces = get_scanner_interfaces()
        persist_scanner.delay(name, interfaces)


@Background.task(ignore_results=True)
def persist_scanner(name, interfaces):
    import transaction
    from .schema import get_tm_session
    with transaction.manager:
        dbsession = get_tm_session(dbsession_factory, transaction.manager)
        scanner = Scanner.create(name=name, interface_address=interfaces[0])
        dbsession.merge(scanner)
