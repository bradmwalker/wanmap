import logging

import arrow
from deform import ValidationFailure
from pyramid.httpexceptions import HTTPNotFound
import pytest

from .scans import (
    DeltaScanSchema, SplittingScanSchema, show_scan, show_scans,
    NO_MAPPED_SUBNETS_ALERT_MESSAGE, NO_SCANNERS_ALERT_MESSAGE,
    ONLY_ONE_SCANNER_ALERT_MESSAGE,
)
from .schema import RemoteUser, SplittingScan

PING_SWEEP = '-sn -PE -n'
_logger = logging.getLogger(__name__)


@pytest.fixture
def splitting_scan_form():
    subnets = ('10.1.0.0/24', 'fd12:3456:789a:1::/64')
    return SplittingScanSchema.form(subnets)


@pytest.fixture
def delta_scan_form():
    scanner_names = {'scanner-a', 'scanner-b'}
    subnets = ('10.1.0.0/24', 'fd12:3456:789a:1::/64')
    return DeltaScanSchema.form(scanner_names, subnets)


@pytest.fixture
def persisted_scan(dbsession):
    user = RemoteUser(name='test', role='user')
    datetime = arrow.now().datetime
    scan = SplittingScan(created_at=datetime, user=user, parameters=PING_SWEEP)
    dbsession.add(scan)
    dbsession.flush()
    return scan


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


@pytest.mark.parametrize('method', ('GET', 'POST'))
def test_new_splitting_scan_without_subnets_has_no_form(
    monkeypatch, fresh_app, method):
    monkeypatch.setattr(
        'wanmap.scans.get_scanner_subnets',
        lambda _: set())
    response = fresh_app.request('/scans/new-splitting', method=method)
    assert not response.forms


@pytest.mark.parametrize('method', ('GET', 'POST'))
def test_new_splitting_scan_without_subnets_alerts(
    monkeypatch, fresh_app, method):
    monkeypatch.setattr(
        'wanmap.scans.get_scanner_subnets',
        lambda _: set())
    response = fresh_app.request('/scans/new-splitting', method=method)
    alert_div = response.html.find('div', class_='alert')
    assert NO_MAPPED_SUBNETS_ALERT_MESSAGE in alert_div.text


@pytest.mark.parametrize('method', ('GET', 'POST'))
def test_new_splitting_scan_with_subnets_has_form(
    monkeypatch, fresh_app, method):
    monkeypatch.setattr(
        'wanmap.scans.get_scanner_subnets',
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
        'wanmap.scans.get_scanner_names',
        lambda _: set())
    response = fresh_app.request('/scans/new-delta', method=method)
    assert not response.forms


@pytest.mark.parametrize('method', ('GET', 'POST'))
def test_new_delta_scan_without_scanners_alerts(
    monkeypatch, fresh_app, method):
    monkeypatch.setattr(
        'wanmap.scans.get_scanner_names',
        lambda _: set())
    response = fresh_app.request('/scans/new-delta', method=method)
    alert_div = response.html.find('div', class_='alert')
    assert NO_SCANNERS_ALERT_MESSAGE in alert_div.text


@pytest.mark.parametrize('method', ('GET', 'POST'))
def test_new_delta_scan_with_one_scanner_has_no_form(
    monkeypatch, fresh_app, method):
    monkeypatch.setattr(
        'wanmap.scans.get_scanner_names',
        lambda _: {'dc'})
    response = fresh_app.request('/scans/new-delta', method=method)
    assert not response.forms


@pytest.mark.parametrize('method', ('GET', 'POST'))
def test_new_delta_scan_with_one_scanner_alerts(
    monkeypatch, fresh_app, method):
    monkeypatch.setattr(
        'wanmap.scans.get_scanner_names',
        lambda _: {'dc'})
    response = fresh_app.request('/scans/new-delta', method=method)
    alert_div = response.html.find('div', class_='alert')
    assert ONLY_ONE_SCANNER_ALERT_MESSAGE in alert_div.text


@pytest.mark.parametrize('method', ('GET', 'POST'))
def test_new_delta_scan_with_two_scanners_has_form(
    monkeypatch, fresh_app, method):
    monkeypatch.setattr(
        'wanmap.scans.get_scanner_names',
        lambda _: {'dc', 'branch'})
    response = fresh_app.request('/scans/new-delta', method=method)
    assert response.forms['delta-scan']


def test_show_scan_non_timestamp_fails(view_request):
    view_request.matchdict['time'] = 'space'
    with pytest.raises(HTTPNotFound):
        show_scan(view_request)


def test_show_scan_nonexistent_timestamp_fails(view_request):
    time = arrow.now().datetime
    view_request.matchdict['time'] = time
    with pytest.raises(HTTPNotFound):
        show_scan(view_request)


def test_show_scan_with_valid_timestamp(view_request, persisted_scan):
    time = persisted_scan.created_at
    view_request.matchdict['time'] = time
    response = show_scan(view_request)
    assert response['scan'] is not None


def test_list_scans_empty(view_request):
    result = show_scans(view_request)
    assert result['scans'] == ()


def test_list_scans_exist(view_request, persisted_scan):
    result = show_scans(view_request)
    assert result['scans'] == (persisted_scan,)


@pytest.mark.xfail(reason='Pagination not yet implemented.')
def test_list_scans_pagination(view_request):
    from .scans import SCAN_LISTING_PAGE_LENGTH
    result = show_scans(view_request)
    assert len(result['scans']) == SCAN_LISTING_PAGE_LENGTH
