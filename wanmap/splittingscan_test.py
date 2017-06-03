import pytest

from .scans import (
    SplittingScan, PING_SWEEP,
    NO_KNOWN_SUBNETS_ALERT_MESSAGE, NO_SCANNERS_ALERT_MESSAGE,
)


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


@pytest.mark.parametrize('method', ('GET', 'POST'))
def test_new_splitting_scan_without_subnets_has_no_form(
    monkeypatch, fresh_app, method):
    monkeypatch.setattr(
        'wanmap.scans.get_scannable_subnets',
        lambda _: set())
    monkeypatch.setattr(
        'wanmap.scans.get_scanner_names',
        lambda: {'scanner1'})
    response = fresh_app.request('/scans/new', method=method)
    assert not response.forms


@pytest.mark.parametrize('method', ('GET', 'POST'))
def test_new_splitting_scan_without_subnets_alerts(
    monkeypatch, fresh_app, method):
    monkeypatch.setattr(
        'wanmap.scans.get_scannable_subnets',
        lambda _: set())
    monkeypatch.setattr(
        'wanmap.scans.get_scanner_names',
        lambda: {'scanner1'})
    response = fresh_app.request('/scans/new', method=method)
    alert_div = response.html.find('div', class_='alert')
    assert NO_KNOWN_SUBNETS_ALERT_MESSAGE in alert_div.text


@pytest.mark.parametrize('method', ('GET', 'POST'))
def test_new_splitting_scan_without_scanners_has_no_form(
    monkeypatch, fresh_app, method):
    monkeypatch.setattr(
        'wanmap.scans.get_scannable_subnets',
        lambda _: {'10.1.0.0/24'})
    monkeypatch.setattr(
        'wanmap.scans.get_scanner_names',
        lambda _: set())
    response = fresh_app.request('/scans/new', method=method)
    assert not response.forms


@pytest.mark.parametrize('method', ('GET', 'POST'))
def test_new_splitting_scan_without_scanners_alerts(
    monkeypatch, fresh_app, method):
    monkeypatch.setattr(
        'wanmap.scans.get_scannable_subnets',
        lambda _: {'10.1.0.0/24'})
    monkeypatch.setattr(
        'wanmap.scans.get_scanner_names',
        lambda _: set())
    response = fresh_app.request('/scans/new', method=method)
    alert_div = response.html.find('div', class_='alert')
    assert NO_SCANNERS_ALERT_MESSAGE in alert_div.text


@pytest.mark.parametrize('method', ('GET', 'POST'))
def test_new_splitting_scan_with_scanners_and_subnets_has_form(
    monkeypatch, fresh_app, method):
    monkeypatch.setattr(
        'wanmap.scans.get_scannable_subnets',
        lambda _: {'10.1.0.0/24'})
    monkeypatch.setattr(
        'wanmap.scans.get_scanner_names',
        lambda _: {'scanner1'})
    response = fresh_app.request('/scans/new', method=method)
    assert response.forms['scan']


@pytest.mark.xfail(
    reason="Need to integrate sessions and attach scan to user in view")
def test_post_new_splitting_scan(fresh_app):
    response = fresh_app.get('/scans/new')
    scan_form = response.forms['scan']
    scan_form['scan_target'] = '127.0.0.1'
    response = scan_form.submit('submit')
    assert response.status_code != 302
    response.follow()
