import pytest

from .scans import SplittingScan, PING_SWEEP


def test_splitting_scan_finds_multiple_subnets_on_a_scanner(
    dbsession, fake_wan_scanners, fake_wan_routers):

    scan = SplittingScan.create(
        session=dbsession, parameters=PING_SWEEP,
        targets=('10.1.0.0/19',))
    subscan_targets = {
        target.target
        for subscan in scan.subscans
        for target in subscan.targets
    }
    scanner_subnets = {'10.1.0.0/20', '10.1.16.0/20'}
    assert subscan_targets == scanner_subnets


def test_splitting_scan_finds_subnets_across_multiple_scanners(
    dbsession, fake_wan_scanners, fake_wan_routers):

    scan = SplittingScan.create(
        session=dbsession, parameters=PING_SWEEP,
        targets=('10.1.0.0/24', '10.2.0.0/24'))
    subscan_targets = {
        target.target
        for subscan in scan.subscans
        for target in subscan.targets
    }
    scanner_subnets = {'10.1.0.0/24', '10.2.0.0/24'}
    assert subscan_targets == scanner_subnets


@pytest.mark.xfail(reason='Need multiple scanners adjacent to one router')
def test_splitting_scan_picks_one_scanner_when_multiple_matches():
    assert False


@pytest.mark.xfail(reason='Needs latency mapping of the network.')
def test_splitting_scan_picks_a_close_scanner_when_none_directly_connected():
    assert False


@pytest.mark.xfail(reason='Needs example in Fake WAN')
def test_splitting_scan_picks_gateway_behind_firewall():
    assert False


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


def test_create_splitting_host_match(
    dbsession, fake_wan_scanners, fake_wan_routers):

    scan = SplittingScan.create(
        session=dbsession, parameters=PING_SWEEP,
        targets=('10.1.0.1',))
    subscan_targets = {
        target.target
        for subscan in scan.subscans
        for target in subscan.targets
    }
    assert subscan_targets == {'10.1.0.1/32'}
