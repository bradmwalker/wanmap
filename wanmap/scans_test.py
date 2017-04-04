import logging
import uuid

import arrow
from pyramid.httpexceptions import HTTPNotFound
import pytest

from .scans import (
    show_scan, show_scans, PING_SWEEP,
)
from .schema import SplittingScan

_logger = logging.getLogger(__name__)


@pytest.fixture
def persisted_scan(dbsession):
    datetime = arrow.now().datetime
    # TODO: Use constructor
    scan = SplittingScan(
        id=uuid.uuid4(), created_at=datetime, parameters=PING_SWEEP)
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
