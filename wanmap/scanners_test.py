import logging

from pyramid.httpexceptions import HTTPNotFound
import pytest

from .scanners import Scanner, show_scanners

logger = logging.getLogger(__name__)


@pytest.fixture
def scanner():
    return Scanner.create('test', '10.0.0.2/24')


@pytest.fixture
def persisted_scanner(dbsession, scanner):
    dbsession.add(scanner)
    dbsession.flush()
    return scanner


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
