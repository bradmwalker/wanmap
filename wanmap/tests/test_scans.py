import logging
import time

import arrow
from deform import Form, ValidationFailure
from pyramid.httpexceptions import HTTPNotFound
import pytest
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import Select


PING_SWEEP = '-sn -PE -n'
_logger = logging.getLogger(__name__)


@pytest.fixture
def splitting_scan_form():
    from ..scans import SplittingScanSchema
    return Form(SplittingScanSchema())


@pytest.fixture
def persisted_scan(dbsession):
    from ..schema import RemoteUser, Scan
    user = RemoteUser(name='test', role='user')
    datetime = arrow.now().datetime
    scan = Scan(
        created_at=datetime, user=user, type='splitting',
        parameters=PING_SWEEP)
    dbsession.add(scan)
    dbsession.flush()
    return scan


def test_splitting_scan_form_requires_a_scan_target(splitting_scan_form):
    with pytest.raises(ValidationFailure) as exc:
        appstruct = {'nmap_options': PING_SWEEP}
        splitting_scan_form.validate_pstruct(appstruct)
        assert exc.msg == 'Must submit at least one Scan Target.'


def test_splitting_scan_form_targets_not_empty(splitting_scan_form):
    with pytest.raises(ValidationFailure) as exc:
        appstruct = {'nmap_options': PING_SWEEP, 'scan_targets': ('',)}
        splitting_scan_form.validate_pstruct(appstruct)
        assert exc.msg == 'Must submit at least one Scan Target.'


def test_splitting_scan_form_allows_ipv4_address(splitting_scan_form):
    appstruct = {'nmap_options': PING_SWEEP, 'scan_targets': ('127.0.0.1',)}
    splitting_scan_form.validate_pstruct(appstruct)


def test_splitting_scan_form_allows_ipv4_network(splitting_scan_form):
    appstruct = {'nmap_options': PING_SWEEP, 'scan_targets': ('127.0.0.0/8',)}
    splitting_scan_form.validate_pstruct(appstruct)


def test_splitting_scan_form_allows_ipv6_address(splitting_scan_form):
    appstruct = {'nmap_options': PING_SWEEP, 'scan_targets': ('::1',)}
    splitting_scan_form.validate_pstruct(appstruct)


def test_splitting_scan_form_allows_ipv6_network(splitting_scan_form):
    appstruct = {'nmap_options': PING_SWEEP, 'scan_targets': ('FE80::/10',)}
    splitting_scan_form.validate_pstruct(appstruct)


@pytest.mark.skip
def test_splitting_scan_form_allows_resolvable_hostname(splitting_scan_form):
    appstruct = {'nmap_options': PING_SWEEP, 'scan_targets': ('localhost',)}
    splitting_scan_form.validate_pstruct(appstruct)


@pytest.mark.skip
def test_splitting_scan_form_unresolvable_not_allowed(splitting_scan_form):
    appstruct = {'nmap_options': PING_SWEEP, 'scan_targets': ('*',)}
    splitting_scan_form.validate_pstruct(appstruct)


def test_new_splitting_scan_has_rendered_form(fresh_app):
    response = fresh_app.get('/scans/new-splitting')
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


def test_show_scan_non_timestamp_fails(view_request):
    from ..scans import show_scan
    view_request.matchdict['time'] = 'space'
    with pytest.raises(HTTPNotFound):
        show_scan(view_request)


def test_show_scan_nonexistent_timestamp_fails(view_request):
    from ..scans import show_scan
    time = arrow.now().datetime
    view_request.matchdict['time'] = time
    with pytest.raises(HTTPNotFound):
        show_scan(view_request)


def test_show_scan_with_valid_timestamp(view_request, persisted_scan):
    from ..scans import show_scan
    time = persisted_scan.created_at
    view_request.matchdict['time'] = time
    response = show_scan(view_request)
    assert response['scan'] is not None


def test_list_scans_empty(view_request):
    from ..scans import show_scans
    result = show_scans(view_request)
    assert result['scans'] == ()


def test_list_scans_exist(view_request, persisted_scan):
    from ..scans import show_scans
    result = show_scans(view_request)
    assert result['scans'] == (persisted_scan,)


@pytest.mark.xfail(reason='Pagination not yet implemented.')
def test_list_scans_pagination(view_request):
    from ..scans import show_scans, SCAN_LISTING_PAGE_LENGTH
    result = show_scans(view_request)
    assert len(result['scans']) == SCAN_LISTING_PAGE_LENGTH


@pytest.mark.selenium
def test_splitting_scan_live(base_url, selenium):
    selenium.implicitly_wait(3)
    selenium.get(base_url)

    new_scan_link = selenium.find_element_by_id('new-splitting-scan')
    new_scan_link.click()

    time.sleep(2)
    # TODO: Rename field buttons
    add_scan_target = selenium.find_element_by_id('deformField2-seqAdd')
    add_scan_target.click()
    nmap_options = selenium.find_element_by_name('nmap_options')
    nmap_options.send_keys(PING_SWEEP)
    scan_targets = selenium.find_elements_by_name('scan_target')
    scan_targets[0].send_keys('172.16.1.1')
    scan_targets[1].send_keys('172.16.2.1')
    scan_targets[1].send_keys(Keys.ENTER)

    time.sleep(5)
    selenium.refresh()
    scan_results = selenium.find_element_by_id('scanner1-results')
    assert 'Host: 172.16.1.1 () Status: Up' in scan_results.text
    scan_results = selenium.find_element_by_id('scanner2-results')
    assert 'Host: 172.16.2.1 () Status: Up' in scan_results.text


@pytest.mark.selenium
def test_delta_scan_live(base_url, selenium):
    """Quickly test a delta scan."""
    selenium.get(base_url)

    new_scan_link = selenium.find_element_by_id('new-delta-scan')
    new_scan_link.click()

    time.sleep(3)
    # TODO: Rename field buttons
    nmap_options = selenium.find_element_by_name('nmap_options')
    nmap_options.send_keys(PING_SWEEP)
    scanner_a = Select(selenium.find_element_by_name('scanner_a'))
    scanner_a.select_by_value('scanner1')
    scanner_b = Select(selenium.find_element_by_name('scanner_b'))
    scanner_b.select_by_value('scanner3')
    scan_target = selenium.find_element_by_name('scan_target')
    scan_target.send_keys('172.16.3.1')
    scan_target.submit()

    time.sleep(5)
    selenium.refresh()
    scan_results = selenium.find_element_by_id('scanner1-results')
    assert 'Host: 172.16.3.1 () Status: Up' not in scan_results.text
    scan_results = selenium.find_element_by_id('scanner3-results')
    assert 'Host: 172.16.3.1 () Status: Up' in scan_results.text
