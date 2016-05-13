import logging
import time

import arrow
from deform import Form, ValidationFailure
from pyramid.httpexceptions import HTTPNotFound
from pyramid.testing import DummyRequest
import pytest
from selenium.webdriver.common.keys import Keys


PING_SWEEP = '-sn -PE -n'
_logger = logging.getLogger(__name__)


@pytest.fixture
def new_scan_form():
    """The form for creating new scans."""
    from ..scans import SplitScanSchema
    return Form(SplitScanSchema())


@pytest.fixture
def persisted_scan(db_session):
    from ..schema import RemoteUser, Scan
    user = RemoteUser(name='test', role='user')
    datetime = arrow.now().datetime
    scan = Scan(
        created_at=datetime, user=user, type='split', parameters=PING_SWEEP)
    db_session.add(scan)
    db_session.flush()
    return scan


def test_new_split_scan_form_requires_a_scan_target(new_scan_form):
    with pytest.raises(ValidationFailure) as exc:
        appstruct = {'nmap_options': PING_SWEEP}
        new_scan_form.validate_pstruct(appstruct)
        assert exc.msg == 'Must submit at least one Scan Target.'


def test_new_split_scan_form_targets_not_empty(new_scan_form):
    with pytest.raises(ValidationFailure) as exc:
        appstruct = {'nmap_options': PING_SWEEP, 'scan_targets': ('',)}
        new_scan_form.validate_pstruct(appstruct)
        assert exc.msg == 'Must submit at least one Scan Target.'


def test_new_split_scan_form_allows_ipv4_address(new_scan_form):
    appstruct = {'nmap_options': PING_SWEEP, 'scan_targets': ('127.0.0.1',)}
    new_scan_form.validate_pstruct(appstruct)


def test_new_split_scan_form_allows_ipv4_network(new_scan_form):
    appstruct = {'nmap_options': PING_SWEEP, 'scan_targets': ('127.0.0.0/8',)}
    new_scan_form.validate_pstruct(appstruct)


def test_new_split_scan_form_allows_ipv6_address(new_scan_form):
    appstruct = {'nmap_options': PING_SWEEP, 'scan_targets': ('::1',)}
    new_scan_form.validate_pstruct(appstruct)


def test_new_split_scan_form_allows_ipv6_network(new_scan_form):
    appstruct = {'nmap_options': PING_SWEEP, 'scan_targets': ('FE80::/10',)}
    new_scan_form.validate_pstruct(appstruct)


@pytest.mark.skip
def test_new_split_scan_form_allows_resolvable_hostname(new_scan_form):
    appstruct = {'nmap_options': PING_SWEEP, 'scan_targets': ('localhost',)}
    new_scan_form.validate_pstruct(appstruct)


@pytest.mark.skip
def test_new_split_scan_form_unresolvable_not_allowed(new_scan_form):
    appstruct = {'nmap_options': PING_SWEEP, 'scan_targets': ('*',)}
    new_scan_form.validate_pstruct(appstruct)


def test_new_split_scan_has_rendered_form(fresh_app):
    response = fresh_app.get('/scans/new_split')
    assert response.forms['scan']


@pytest.mark.xfail(
    reason="Need to integrate sessions and attach scan to user in view")
def test_post_new_split_scan(fresh_app):
    response = fresh_app.get('/scans/new_split')
    scan_form = response.forms['scan']
    scan_form['scan_target'] = '127.0.0.1'
    response = scan_form.submit('submit')
    assert response.status_code != 302
    response.follow()


def test_show_scan_non_timestamp_fails():
    from ..scans import show_scan
    request = DummyRequest()
    request.matchdict['time'] = 'space'
    with pytest.raises(HTTPNotFound):
        show_scan(request)


def test_show_scan_nonexistent_timestamp_fails():
    from ..scans import show_scan
    time = arrow.now().datetime
    request = DummyRequest()
    request.matchdict['time'] = time
    with pytest.raises(HTTPNotFound):
        show_scan(request)


def test_show_scan_with_valid_timestamp(persisted_scan):
    from ..scans import show_scan
    time = persisted_scan.created_at
    request = DummyRequest()
    request.matchdict['time'] = time
    response = show_scan(request)
    assert response['scan'] is not None


def test_list_scans_empty(db_session):
    from ..scans import show_scans
    request = DummyRequest()
    result = show_scans(request)
    assert result['scans'] == ()


def test_list_scans_exist(persisted_scan):
    from ..scans import show_scans
    request = DummyRequest()
    result = show_scans(request)
    assert result['scans'] == (persisted_scan,)


@pytest.mark.xfail(reason='Pagination not yet implemented.')
def test_list_scans_pagination(db_session):
    from ..scans import show_scans
    request = DummyRequest()
    result = show_scans(request)
    assert len(result['scans']) == 20


@pytest.mark.selenium
def test_split_scan_live(base_url, selenium):
    """Quickly test a multi-scanner split scan. """
    selenium.implicitly_wait(3)
    selenium.get(base_url)

    new_scan_link = selenium.find_element_by_id('new-split-scan')
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
