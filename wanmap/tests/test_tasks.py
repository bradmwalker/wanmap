import logging

import pytest

PING_SWEEP = '-sn -PE -n'

_logger = logging.getLogger(__name__)


@pytest.fixture
def scan_user():
    from ..schema import User
    user = User(name='test')
    _logger.info('User: {!r}'.format(user))
    return user


@pytest.fixture
def scanners():
    from ..schema import Scanner, ScannerSubnet
    scanner_a = Scanner.create(
        name='scanner-a', interface_address='10.0.0.2/24')
    scanner_a.subnets.append(
        ScannerSubnet(scanner=scanner_a, subnet='192.168.0.0/24'))
    scanner_b = Scanner.create(
        name='scanner-b', interface_address='10.0.1.2/24')
    return {scanner_a, scanner_b}


@pytest.fixture
def persisted_scanners(dbsession, scanners):
    dbsession.add_all(scanners)
    dbsession.flush()
    return scanners


def test_split_scan(dbsession, scan_user, persisted_scanners):
    from ..schema import Scan
    scan = Scan.create_split(
        session=dbsession, user=scan_user, parameters=PING_SWEEP,
        targets=('10.0.0.0/8',))
    subscans = scan.subscans
    scanners = {subscan.scanner for subscan in subscans}
    assert persisted_scanners == scanners
    subscan_targets = {
        target.target
        for subscan in subscans
        for target in subscan.targets
    }
    scanner_subnets = {'10.0.0.0/24', '10.0.1.0/24'}
    assert subscan_targets == scanner_subnets


def test_create_split_scan_errors_on_no_targets(dbsession, scan_user):
    from ..schema import Scan
    with pytest.raises(ValueError):
        Scan.create_split(
            session=dbsession, user=scan_user, parameters=PING_SWEEP,
            targets=())


def test_create_split_scan_errors_on_no_subnet_matches(dbsession, scan_user):
    from ..schema import Scan
    with pytest.raises(Exception):
        Scan.create_split(
            session=dbsession, user=scan_user, parameters=PING_SWEEP,
            targets=('0.0.0.0/0',))


def test_create_split_host_match(dbsession, scan_user, persisted_scanners):
    from ..schema import Scan
    scan = Scan.create_split(
        session=dbsession, user=scan_user, parameters=PING_SWEEP,
        targets=('10.0.1.1',))
    subscan_targets = {
        target.target
        for subscan in scan.subscans
        for target in subscan.targets
    }
    assert subscan_targets == {'10.0.1.1/32'}
