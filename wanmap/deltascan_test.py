import pytest

from .deltascan import (
    DeltaScan,
    NO_SCANNERS_ALERT_MESSAGE, ONLY_ONE_SCANNER_ALERT_MESSAGE,
    NO_KNOWN_SUBNETS_ALERT_MESSAGE,
)
from .scans import PING_SWEEP


def test_create_delta_scan(dbsession, fake_wan_scanners, fake_wan_routers):
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


@pytest.mark.parametrize('method', ('GET', 'POST'))
def test_new_delta_scan_without_subnets_has_no_form(
    monkeypatch, fresh_app, method):
    monkeypatch.setattr(
        'wanmap.deltascan.get_scannable_subnets',
        lambda _: set())
    monkeypatch.setattr(
        'wanmap.deltascan.get_scanner_names',
        lambda _: {'dc'})
    response = fresh_app.request('/scans/new-delta', method=method)
    assert not response.forms


@pytest.mark.parametrize('method', ('GET', 'POST'))
def test_new_delta_scan_without_subnets_alerts(
    monkeypatch, fresh_app, method):
    monkeypatch.setattr(
        'wanmap.deltascan.get_scannable_subnets',
        lambda _: set())
    monkeypatch.setattr(
        'wanmap.deltascan.get_scanner_names',
        lambda _: {'dc'})
    response = fresh_app.request('/scans/new-delta', method=method)
    alert_div = response.html.find('div', class_='alert')
    assert NO_KNOWN_SUBNETS_ALERT_MESSAGE in alert_div.text


@pytest.mark.parametrize('method', ('GET', 'POST'))
def test_new_delta_scan_without_scanners_has_no_form(
    monkeypatch, fresh_app, method):
    monkeypatch.setattr(
        'wanmap.deltascan.get_scannable_subnets',
        lambda _: {'10.1.0.0/24'})
    monkeypatch.setattr(
        'wanmap.deltascan.get_scanner_names',
        lambda _: set())
    response = fresh_app.request('/scans/new-delta', method=method)
    assert not response.forms


@pytest.mark.parametrize('method', ('GET', 'POST'))
def test_new_delta_scan_without_scanners_alerts(
    monkeypatch, fresh_app, method):
    monkeypatch.setattr(
        'wanmap.deltascan.get_scannable_subnets',
        lambda _: {'10.1.0.0/24'})
    monkeypatch.setattr(
        'wanmap.deltascan.get_scanner_names',
        lambda _: set())
    response = fresh_app.request('/scans/new-delta', method=method)
    alert_div = response.html.find('div', class_='alert')
    assert NO_SCANNERS_ALERT_MESSAGE in alert_div.text


@pytest.mark.parametrize('method', ('GET', 'POST'))
def test_new_delta_scan_with_one_scanner_has_no_form(
    monkeypatch, fresh_app, method):
    monkeypatch.setattr(
        'wanmap.deltascan.get_scannable_subnets',
        lambda _: {'10.1.0.0/24'})
    monkeypatch.setattr(
        'wanmap.deltascan.get_scanner_names',
        lambda _: {'dc'})
    response = fresh_app.request('/scans/new-delta', method=method)
    assert not response.forms


@pytest.mark.parametrize('method', ('GET', 'POST'))
def test_new_delta_scan_with_one_scanner_alerts(
    monkeypatch, fresh_app, method):
    monkeypatch.setattr(
        'wanmap.deltascan.get_scannable_subnets',
        lambda _: {'10.1.0.0/24'})
    monkeypatch.setattr(
        'wanmap.deltascan.get_scanner_names',
        lambda _: {'dc'})
    response = fresh_app.request('/scans/new-delta', method=method)
    alert_div = response.html.find('div', class_='alert')
    assert ONLY_ONE_SCANNER_ALERT_MESSAGE in alert_div.text


@pytest.mark.parametrize('method', ('GET', 'POST'))
def test_new_delta_scan_with_two_scanners_has_form(
    monkeypatch, fresh_app, method):
    monkeypatch.setattr(
        'wanmap.deltascan.get_scannable_subnets',
        lambda _: {'10.1.0.0/24'})
    monkeypatch.setattr(
        'wanmap.deltascan.get_scanner_names',
        lambda _: {'dc', 'branch'})
    response = fresh_app.request('/scans/new-delta', method=method)
    assert response.forms['scan']
