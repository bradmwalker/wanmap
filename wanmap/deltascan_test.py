from deform import ValidationFailure
import pytest

from .deltascan import DeltaScanSchema
from .scans import (
    NO_SCANNERS_ALERT_MESSAGE, ONLY_ONE_SCANNER_ALERT_MESSAGE, PING_SWEEP,
)
from .schema import DeltaScan


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


@pytest.fixture
def delta_scan_form():
    scanner_names = {'scanner-a', 'scanner-b'}
    subnets = ('10.1.0.0/24', 'fd12:3456:789a:1::/64')
    return DeltaScanSchema.form(scanner_names, subnets)


def test_delta_scan_form_requires_scanner_a_choice(delta_scan_form):
    with pytest.raises(ValidationFailure) as exc:
        appstruct = {
            'nmap_options': PING_SWEEP,
            'scanners': {'scanner_a': '', 'scanner_b': 'scanner-b'},
            'scan_targets': ['10.0.0.1']
        }
        delta_scan_form.validate_pstruct(appstruct)
    assert 'Required' in exc.value.render()


def test_delta_scan_form_requires_scanner_b_choice(delta_scan_form):
    with pytest.raises(ValidationFailure) as exc:
        appstruct = {
            'nmap_options': PING_SWEEP,
            'scanners': {'scanner_a': 'scanner-a', 'scanner_b': ''},
            'scan_targets': ['10.0.0.1']
        }
        delta_scan_form.validate_pstruct(appstruct)
    assert 'Required' in exc.value.render()


def test_delta_scan_form_requires_distinct_scanner_choices(delta_scan_form):
    with pytest.raises(ValidationFailure) as exc:
        appstruct = {
            'nmap_options': PING_SWEEP,
            'scanners': {'scanner_a': 'scanner-a', 'scanner_b': 'scanner-a'},
            'scan_targets': ['10.0.0.1']
        }
        delta_scan_form.validate_pstruct(appstruct)
    form_html = exc.value.render()
    assert 'Required' not in form_html
    assert 'Must be different from Scanner A' in form_html


def test_delta_scan_form_simultaneous_scanner_validation(delta_scan_form):
    with pytest.raises(ValidationFailure) as exc:
        appstruct = {
            'nmap_options': PING_SWEEP,
            'scanners': {'scanner_a': 'scanner-a', 'scanner_b': 'scanner-a'},
            'scan_targets': ['']
        }
        delta_scan_form.validate_pstruct(appstruct)
    form_html = exc.value.render()
    assert 'Required' in form_html
    assert 'Must be different from Scanner A' in form_html


@pytest.mark.parametrize('method', ('GET', 'POST'))
def test_new_delta_scan_without_scanners_has_no_form(
    monkeypatch, fresh_app, method):
    monkeypatch.setattr(
        'wanmap.deltascan.get_scanner_names',
        lambda _: set())
    response = fresh_app.request('/scans/new-delta', method=method)
    assert not response.forms


@pytest.mark.parametrize('method', ('GET', 'POST'))
def test_new_delta_scan_without_scanners_alerts(
    monkeypatch, fresh_app, method):
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
        'wanmap.deltascan.get_scanner_names',
        lambda _: {'dc'})
    response = fresh_app.request('/scans/new-delta', method=method)
    assert not response.forms


@pytest.mark.parametrize('method', ('GET', 'POST'))
def test_new_delta_scan_with_one_scanner_alerts(
    monkeypatch, fresh_app, method):
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
        'wanmap.deltascan.get_scanner_names',
        lambda _: {'dc', 'branch'})
    response = fresh_app.request('/scans/new-delta', method=method)
    assert response.forms['delta-scan']
