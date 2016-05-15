import ipaddress
import logging

from pyramid.httpexceptions import HTTPNotFound
from pyramid.testing import DummyRequest
import pytest


logger = logging.getLogger(__name__)


@pytest.fixture
def scanner():
    from ..schema import Scanner
    return Scanner.create('test', '10.0.0.2/24')


@pytest.fixture
def persisted_scanner(dbsession, scanner):
    dbsession.add(scanner)
    dbsession.flush()
    return scanner


def test_scanner_has_connected_subnet(scanner):
    network = ipaddress.ip_interface(scanner.interface).network
    subnets = {subnet.subnet for subnet in scanner.subnets}
    assert str(network) in subnets


def test_show_scanner_found(persisted_scanner):
    from ..scanners import show_scanner
    request = DummyRequest()
    request.matchdict['name'] = persisted_scanner.name
    response = show_scanner(request)
    assert response['scanner'] == persisted_scanner


def test_show_scanner_not_found(persisted_scanner):
    from ..scanners import show_scanner
    request = DummyRequest()
    request.matchdict['name'] = 'not' + persisted_scanner.name
    with pytest.raises(HTTPNotFound):
        show_scanner(request)


def test_show_scanner_has_form(persisted_scanner):
    from ..scanners import show_scanner
    request = DummyRequest()
    request.matchdict['name'] = persisted_scanner.name
    response = show_scanner(request)
    assert response['scanner'] == persisted_scanner


def test_show_scanners_without_scanners():
    from ..scanners import show_scanners
    request = DummyRequest()
    response = show_scanners(request)
    assert response['scanners'] == []


def test_show_scanners_with_scanners(persisted_scanner):
    from ..schema import Scanner
    from ..scanners import show_scanners
    request = DummyRequest()
    response = show_scanners(request)
    assert (
        response['scanners'] and
        all(
            isinstance(scanner, Scanner)
            for scanner in response['scanners']))
