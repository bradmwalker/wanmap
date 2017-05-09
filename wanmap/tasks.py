import ipaddress
import os.path
import re
from subprocess import check_output

import arrow
from celery import Celery
from celery.app import app_or_default
from celery.signals import celeryd_after_setup, worker_process_init
from celery.utils.log import get_task_logger
from pyramid.paster import get_appsettings, setup_logging
from pyramid_transactional_celery import TransactionalTask

from .scanners import Scanner
from .scans import Scan, Subscan

__all__ = ['scan_workflow']

Background = Celery()
Background.config_from_object('wanmap.celeryconfig')

SUDO = '/usr/bin/sudo'
NMAP = '/usr/bin/nmap'
NMAP_OUTPUT_OPTIONS = '-oX -'.split()

_logger = get_task_logger(__name__)


class PersistenceTask(TransactionalTask):

    def __call__(self, *args, **kwargs):
        import transaction
        from .schema import get_tm_session
        with transaction.manager as _transaction:
            try:
                self.dbsession = get_tm_session(
                    self.app.dbsession_factory, transaction.manager)
                super().__call__(*args, **kwargs)
            except:
                _logger.warning('Aborting transaction.')
                _transaction.abort()
                raise


# TODO: Only initialize DB if console node.
@worker_process_init.connect
def _init(signal, sender, **kwargs):
    from . import schema
    app = app_or_default()
    here = os.path.dirname(__file__)
    settings_path = os.path.join(here, '../', 'development.ini')
    setup_logging(settings_path)
    settings = get_appsettings(settings_path, name='wanmap')
    app.dbsession_factory = schema.get_session_factory(settings)


# TODO: Make a group/chord out of launching subscans
@Background.task(base=PersistenceTask, bind=True)
def scan_workflow(self, scan_id):
    _logger.info('Dispatching Scan: {}'.format(scan_id))
    scan = self.dbsession.query(Scan).get(scan_id)
    nmap_options = scan.parameters.split(' ')
    for subscan in scan.subscans:
        # TODO: Serialize ipaddress types?
        subscan_targets = [str(target.target) for target in subscan.targets]
        scanner_name = subscan.scanner.name
        subscan_key = (scan_id, scanner_name)
        exec_nmap_scan.delay(subscan_key, nmap_options, subscan_targets)


@Background.task(base=TransactionalTask)
def exec_nmap_scan(subscan_key, nmap_options, targets):
    started_at = arrow.now().datetime
    import transaction
    with transaction.manager:
        mark_subscan_started.delay(subscan_key, started_at)
    nmap_options, targets = list(nmap_options), list(targets)
    nmap_command = [SUDO, NMAP] + NMAP_OUTPUT_OPTIONS + nmap_options + targets
    _logger.info('Executing {!r}'.format(' '.join(nmap_command)))
    finished_at = arrow.now().datetime
    results_xml = check_output(nmap_command, universal_newlines=True)
    duration = (started_at, finished_at)
    with transaction.manager:
        record_subscan_results.delay(subscan_key, results_xml, duration)


@Background.task(base=PersistenceTask, bind=True)
def mark_subscan_started(self, subscan_key, started_at):
    subscan = self.dbsession.query(Subscan).get(subscan_key)
    subscan.started_at = started_at


# Need a transaction for each subscan. Scans can be written incrementally.
@Background.task(base=PersistenceTask, bind=True)
def record_subscan_results(self, subscan_key, subscan_result, duration):
    subscan = self.dbsession.query(Subscan).get(subscan_key)
    subscan.complete(subscan_result, duration)


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
        import transaction
        with transaction.manager:
            interfaces = get_scanner_interfaces()
            persist_scanner.delay(name, interfaces)


@Background.task(base=PersistenceTask, bind=True)
def persist_scanner(self, name, interfaces):
    scanner = Scanner.create(name=name, interface_address=interfaces[0])
    self.dbsession.merge(scanner)
