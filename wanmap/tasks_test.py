import logging

import pytest

from .schema import DeltaScan, SplittingScan

PING_SWEEP = '-sn -PE -n'

_logger = logging.getLogger(__name__)


def test_splitting_scan(dbsession, fake_wan_scanners):
    scan = SplittingScan.create(
        session=dbsession, parameters=PING_SWEEP,
        targets=('10.0.0.0/8',))
    subscan_targets = {
        target.target
        for subscan in scan.subscans
        for target in subscan.targets
    }
    scanner_subnets = {'10.1.0.0/24', '10.2.0.0/24'}
    assert subscan_targets == scanner_subnets


def test_create_splitting_scan_errors_on_no_targets(dbsession):
    with pytest.raises(ValueError):
        SplittingScan.create(
            session=dbsession, parameters=PING_SWEEP,
            targets=())


def test_create_splitting_scan_errors_on_no_subnet_matches(dbsession):
    with pytest.raises(Exception):
        SplittingScan.create(
            session=dbsession, parameters=PING_SWEEP,
            targets=('0.0.0.0/0',))


def test_create_splitting_host_match(dbsession, fake_wan_scanners):
    scan = SplittingScan.create(
        session=dbsession, parameters=PING_SWEEP,
        targets=('10.1.0.1',))
    subscan_targets = {
        target.target
        for subscan in scan.subscans
        for target in subscan.targets
    }
    assert subscan_targets == {'10.1.0.1/32'}


def test_create_delta_scan(dbsession, fake_wan_scanners):
    scanner_a, scanner_b, *_ = (scanner.name for scanner in fake_wan_scanners)
    scan = DeltaScan.create(
        session=dbsession, parameters=PING_SWEEP,
        scanner_names=(scanner_a, scanner_b,), targets=('10.1.0.1',))
    subscan_targets = {
        target.target
        for subscan in scan.subscans
        for target in subscan.targets
    }
    assert subscan_targets == {'10.1.0.1/32'}


def test_create_delta_scan_errors_on_no_targets(dbsession, fake_wan_scanners):
    scanner_names = tuple(scanner.name for scanner in fake_wan_scanners)
    with pytest.raises(ValueError):
        DeltaScan.create(
            session=dbsession, parameters=PING_SWEEP,
            scanner_names=scanner_names, targets=())
