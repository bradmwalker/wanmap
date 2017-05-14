from deform import ValidationFailure
import pytest

from .scans import PING_SWEEP
from .splittingscan import (
    SplittingScan,
    SplittingScanSchema, NO_MAPPED_SUBNETS_ALERT_MESSAGE,
)


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


@pytest.fixture
def splitting_scan_form():
    subnets = ('10.1.0.0/24', 'fd12:3456:789a:1::/64')
    return SplittingScanSchema.form(subnets)


def test_splitting_scan_form_requires_nmap_options(splitting_scan_form):
    with pytest.raises(ValidationFailure) as exc:
        appstruct = {'nmap_options': '', 'scan_targets': ['10.1.0.0/24']}
        splitting_scan_form.validate_pstruct(appstruct)
    assert 'Required' in exc.value.render()


def test_splitting_scan_form_requires_a_scan_target(splitting_scan_form):
    with pytest.raises(ValidationFailure) as exc:
        appstruct = {'nmap_options': PING_SWEEP}
        splitting_scan_form.validate_pstruct(appstruct)
    assert 'Must submit at least one Scan Target' in exc.value.render()


def test_splitting_scan_form_targets_not_empty(splitting_scan_form):
    with pytest.raises(ValidationFailure) as exc:
        appstruct = {'nmap_options': PING_SWEEP, 'scan_targets': ['']}
        splitting_scan_form.validate_pstruct(appstruct)
    assert 'Required' in exc.value.render()


def test_splitting_scan_form_allows_ipv4_address(splitting_scan_form):
    appstruct = {'nmap_options': PING_SWEEP, 'scan_targets': ['10.1.0.1']}
    splitting_scan_form.validate_pstruct(appstruct)


def test_splitting_scan_form_allows_ipv4_network(splitting_scan_form):
    appstruct = {'nmap_options': PING_SWEEP, 'scan_targets': ['10.1.0.0/24']}
    splitting_scan_form.validate_pstruct(appstruct)


def test_splitting_scan_form_allows_ipv6_address(splitting_scan_form):
    appstruct = {
        'nmap_options': PING_SWEEP,
        'scan_targets': ['fd12:3456:789a:1::1']
    }
    splitting_scan_form.validate_pstruct(appstruct)


def test_splitting_scan_form_allows_ipv6_network(splitting_scan_form):
    appstruct = {
        'nmap_options': PING_SWEEP,
        'scan_targets': ['fd12:3456:789a:1::/64']
    }
    splitting_scan_form.validate_pstruct(appstruct)


def test_splitting_scan_form_allows_resolvable_hostname(
    splitting_scan_form, fake_dns):
    appstruct = {
        'nmap_options': PING_SWEEP,
        'scan_targets': ['wanmap.local']
    }
    splitting_scan_form.validate_pstruct(appstruct)


def test_splitting_scan_form_does_not_allow_unresolvable(
    splitting_scan_form, fake_dns):
    with pytest.raises(ValidationFailure) as exc:
        appstruct = {'nmap_options': PING_SWEEP, 'scan_targets': ['*']}
        splitting_scan_form.validate_pstruct(appstruct)
    assert 'Unable to resolve hostname' in exc.value.render()


def test_splitting_scan_subnets_allows_non_overlapping_targets(
    splitting_scan_form, fake_dns):
    appstruct = {
        'nmap_options': PING_SWEEP,
        'scan_targets': ['10.0.0.0/8', 'fd12:3456:789a:1::/64'],
    }
    splitting_scan_form.validate_pstruct(appstruct)


def test_splitting_scan_subnets_restricts_overlapping_targets(
    splitting_scan_form, fake_dns):
    with pytest.raises(ValidationFailure) as exc:
        appstruct = {
            'nmap_options': PING_SWEEP,
            'scan_targets': ['10.0.0.0/8', '10.1.0.0/24'],
        }
        splitting_scan_form.validate_pstruct(appstruct)
    assert 'Target cannot overlap' in exc.value.render()


def test_splitting_scan_subnets_restricts_multiple_overlapping_targets(
    splitting_scan_form, fake_dns):
    with pytest.raises(ValidationFailure) as exc:
        appstruct = {
            'nmap_options': PING_SWEEP,
            'scan_targets': ['10.0.0.0/8', '10.1.0.0/24', '10.1.0.1'],
        }
        splitting_scan_form.validate_pstruct(appstruct)
    assert exc.value.render().count('Target cannot overlap') == 3


def test_splitting_scan_subnets_restricts_overlapping_host(
    splitting_scan_form, fake_dns):
    with pytest.raises(ValidationFailure) as exc:
        appstruct = {
            'nmap_options': PING_SWEEP,
            'scan_targets': ['10.0.0.0/8', 'wanmap.local'],
        }
        splitting_scan_form.validate_pstruct(appstruct)
    assert 'Target cannot overlap' in exc.value.render()


@pytest.mark.parametrize('method', ('GET', 'POST'))
def test_new_splitting_scan_without_subnets_has_no_form(
    monkeypatch, fresh_app, method):
    monkeypatch.setattr(
        'wanmap.splittingscan.get_scanner_subnets',
        lambda _: set())
    response = fresh_app.request('/scans/new-splitting', method=method)
    assert not response.forms


@pytest.mark.parametrize('method', ('GET', 'POST'))
def test_new_splitting_scan_without_subnets_alerts(
    monkeypatch, fresh_app, method):
    monkeypatch.setattr(
        'wanmap.splittingscan.get_scanner_subnets',
        lambda _: set())
    response = fresh_app.request('/scans/new-splitting', method=method)
    alert_div = response.html.find('div', class_='alert')
    assert NO_MAPPED_SUBNETS_ALERT_MESSAGE in alert_div.text


@pytest.mark.parametrize('method', ('GET', 'POST'))
def test_new_splitting_scan_with_subnets_has_form(
    monkeypatch, fresh_app, method):
    monkeypatch.setattr(
        'wanmap.splittingscan.get_scanner_subnets',
        lambda _: {'10.1.0.0/24'})
    response = fresh_app.request('/scans/new-splitting', method=method)
    assert response.forms['splitting-scan']


@pytest.mark.xfail(
    reason="Need to integrate sessions and attach scan to user in view")
def test_post_new_splitting_scan(fresh_app):
    response = fresh_app.get('/scans/new-splitting')
    scan_form = response.forms['splitting-scan']
    scan_form['scan_target'] = '127.0.0.1'
    response = scan_form.submit('submit')
    assert response.status_code != 302
    response.follow()
