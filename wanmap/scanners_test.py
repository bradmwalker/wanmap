import logging

from pyramid.httpexceptions import HTTPNotFound
import pytest

from .scanners import Scanner, show_scanner, show_scanners

logger = logging.getLogger(__name__)


@pytest.fixture
def scanner():
    return Scanner.create('test', '10.0.0.2/24')


@pytest.fixture
def persisted_scanner(dbsession, scanner):
    dbsession.add(scanner)
    dbsession.flush()
    return scanner


def test_show_scanner_found(view_request, persisted_scanner):
    view_request.matchdict['name'] = persisted_scanner.name
    response = show_scanner(view_request)
    assert response['scanner'] == persisted_scanner


def test_show_scanner_not_found(view_request, persisted_scanner):
    view_request.matchdict['name'] = 'not' + persisted_scanner.name
    with pytest.raises(HTTPNotFound):
        show_scanner(view_request)


def test_show_scanner_has_form(view_request, persisted_scanner):
    view_request.matchdict['name'] = persisted_scanner.name
    response = show_scanner(view_request)
    assert response['scanner'] == persisted_scanner


def test_show_scanners_without_scanners(view_request):
    response = show_scanners(view_request)
    assert response['scanners'] == []


def test_show_scanners_with_scanners(view_request, persisted_scanner):
    response = show_scanners(view_request)
    assert (
        response['scanners'] and
        all(
            isinstance(scanner, Scanner)
            for scanner in response['scanners']))
