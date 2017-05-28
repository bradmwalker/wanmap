from ipaddress import ip_network
import logging
import uuid

import arrow
from datetime import timedelta
from pyramid.httpexceptions import HTTPNotFound
import pytest

from .scans import (
    get_scannable_subnets, Scan, show_scan, show_scans, PING_SWEEP,
)
from .splittingscan import SplittingScan

FAKE_SCAN_RESULT_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<!DOCTYPE nmaprun>'
    '<?xml-stylesheet href="file:///usr/bin/../share/nmap/nmap.xsl" type="text/xsl"?>'   # noqa
    '<nmaprun/>'
)


_logger = logging.getLogger(__name__)


@pytest.fixture
def persisted_scan(dbsession, fake_wan_scanners, fake_wan_routers):
    scan = SplittingScan.create(
        dbsession, parameters=PING_SWEEP, targets=('10.0.0.0/8',))
    dbsession.add(scan)
    dbsession.flush()
    return scan


def test_show_scan_non_uuid_fails(view_request):
    view_request.matchdict['id'] = '🐢'
    with pytest.raises(HTTPNotFound):
        show_scan(view_request)


def test_show_scan_nonexistent_timestamp_fails(view_request):
    view_request.matchdict['id'] = str(uuid.uuid4())
    with pytest.raises(HTTPNotFound):
        show_scan(view_request)


def test_show_scan_with_valid_id(view_request, persisted_scan):
    view_request.matchdict['id'] = str(persisted_scan.id)
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


def test_scan_initially_scheduled(persisted_scan):
    assert persisted_scan.status == Scan.States.SCHEDULED


def test_scan_starting_subscan_marks_scan_progressing(persisted_scan):
    persisted_scan.subscans[0].started_at = arrow.now().datetime
    assert persisted_scan.status == Scan.States.PROGRESSING


def test_scan_all_subscans_finished_marks_scan_completed(persisted_scan):
    for subscan in persisted_scan.subscans:
        started_at = arrow.now().datetime
        finished_at = started_at + timedelta(seconds=1)
        subscan.complete(FAKE_SCAN_RESULT_XML, (started_at, finished_at))
    assert persisted_scan.status == Scan.States.COMPLETED


def test_scan_not_all_subscans_finished_marks_scan_progressing(persisted_scan):
    for subscan in persisted_scan.subscans:
        subscan.started_at = arrow.now().datetime
    for subscan in persisted_scan.subscans[:-1]:
        started_at = arrow.now().datetime
        finished_at = started_at + timedelta(seconds=1)
        subscan.complete(FAKE_SCAN_RESULT_XML, (started_at, finished_at))
    assert persisted_scan.status == Scan.States.PROGRESSING


@pytest.fixture
def subscan(persisted_scan):
    return persisted_scan.subscans[0]


def test_subscan_time_information_initially_null(subscan):
    assert subscan.started_at is None
    assert subscan.finished_at is None


def test_subscan_complete_sets_duration_timestamps(subscan):
    started_at = arrow.now().datetime
    finished_at = started_at + timedelta(seconds=1)
    subscan.complete(FAKE_SCAN_RESULT_XML, (started_at, finished_at))
    assert subscan.started_at is not None
    assert subscan.finished_at is not None


def test_subscan_complete_sets_xml_result(subscan):
    started_at = arrow.now().datetime
    finished_at = started_at + timedelta(seconds=1)
    subscan.complete(FAKE_SCAN_RESULT_XML, (started_at, finished_at))
    assert len(subscan.xml_results)


def test_get_scannable_subnets_includes_glue_nets(dbsession, fake_wan_routers):
    assert ip_network('192.168.0.0/30') in get_scannable_subnets(dbsession)
