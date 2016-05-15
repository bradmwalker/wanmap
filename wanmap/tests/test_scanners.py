import ipaddress
import logging

from pyramid.httpexceptions import HTTPNotFound
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


def test_show_scanner_found(view_request, persisted_scanner):
    from ..scanners import show_scanner
    view_request.matchdict['name'] = persisted_scanner.name
    response = show_scanner(view_request)
    assert response['scanner'] == persisted_scanner


def test_show_scanner_not_found(view_request, persisted_scanner):
    from ..scanners import show_scanner
    view_request.matchdict['name'] = 'not' + persisted_scanner.name
    with pytest.raises(HTTPNotFound):
        show_scanner(view_request)


def test_show_scanner_has_form(view_request, persisted_scanner):
    from ..scanners import show_scanner
    view_request.matchdict['name'] = persisted_scanner.name
    response = show_scanner(view_request)
    assert response['scanner'] == persisted_scanner


def test_show_scanners_without_scanners(view_request):
    from ..scanners import show_scanners
    response = show_scanners(view_request)
    assert response['scanners'] == []


def test_show_scanners_with_scanners(view_request, persisted_scanner):
    from ..schema import Scanner
    from ..scanners import show_scanners
    response = show_scanners(view_request)
    assert (
        response['scanners'] and
        all(
            isinstance(scanner, Scanner)
            for scanner in response['scanners']))
