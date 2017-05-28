from ipaddress import ip_interface
from itertools import starmap
import logging
import os
from unittest.mock import patch
from uuid import UUID

from pyramid.paster import get_appsettings, setup_logging
from pyramid.testing import DummyRequest
import pytest
from webtest import TestApp

from wanmap.network import Router
from wanmap.scanners import Scanner
import wanmap.schema

FAKE_DNS_MAP = {
    'wanmap.local': '10.1.0.10',
    'example.com': '93.184.216.34',
}

_logger = logging.getLogger(__name__)


# https://gist.github.com/inklesspen/4504383
def pytest_addoption(parser):
    parser.addoption(
        '--ini', action='store', metavar='INI_FILE',
        help='use INI_FILE to configure SQLAlchemy')


# https://gist.github.com/inklesspen/4504383
@pytest.fixture(scope='session')
def appsettings(request):
    config_uri = os.path.abspath(request.config.option.ini)
    setup_logging(config_uri)
    return get_appsettings(config_uri, name='wanmap')


@pytest.fixture
def view_request(dbsession):
    return DummyRequest(dbsession=dbsession)


# Is this redundant w/o making app session-scope?
@pytest.fixture
def fresh_app(app):
    app.reset()
    return app


@pytest.fixture
def app(dbsession, appsettings):
    from wanmap import make_wsgi_app
    return TestApp(make_wsgi_app(appsettings))


@pytest.fixture(scope='session')
def session_factory(appsettings):
    factory = wanmap.schema.get_session_factory(appsettings)
    with patch('wanmap.schema.get_session_factory', return_value=factory):
        yield factory


@pytest.fixture
def dbsession(session_factory):
    _dbsession = session_factory()
    yield _dbsession
    _dbsession.close()


@pytest.fixture
def fake_dns(monkeypatch):

    def _fake_dns(hostname):
        import socket
        ip_address = FAKE_DNS_MAP.get(hostname)
        if ip_address is None:
            raise socket.gaierror
        return ip_address

    monkeypatch.setattr('socket.gethostbyname', _fake_dns)


@pytest.fixture
def fake_wan_scanners(dbsession):
    """Scanner instances representing those in the E2E fake WAN environment."""
    scanners = {
        'dmzscanner': '203.0.113.254/24',
        'external': '198.51.100.2/30',
        'scanner1': '10.1.0.254/24',
        'scanner2': '10.2.0.254/24',
    }
    scanners = tuple(starmap(Scanner.create, scanners.items()))
    dbsession.add_all(scanners)
    return scanners


@pytest.fixture
def fake_wan_routers(dbsession):
    """Router instances representing those in the E2E fake WAN environment."""
    routers = {
        UUID('35c1bb78-bbe4-43cc-a50c-5af77c0a8af6'): (     # r0
            '10.1.32.1/20 10.1.0.1/20 10.1.80.1/20 10.1.96.1/20 10.1.112.1/20 '
            '10.1.128.1/20 10.1.144.1/20 192.168.0.1/30 10.1.208.1/20 '
            '10.1.224.1/20 10.1.176.1/20 10.1.192.1/20 10.1.160.1/20 '
            '10.1.240.1/20 10.1.48.1/20 192.168.0.5/30 10.1.64.1/20 '
            '10.1.16.1/20 192.0.2.1/30'),
        UUID('7a406613-2162-4a00-8dbb-40f88b90021a'): (     # r1
            '10.2.0.1/24 192.168.0.2/30'),
        UUID('a2564094-5973-4d43-9a89-2fcd86d972e0'): (     # dmz
            '203.0.113.1/24 192.168.0.6/30'),
    }
    routers = (
        (name, map(ip_interface, interfaces.split()))
        for name, interfaces in routers.items()
    )
    routers = tuple(starmap(Router.create, routers))
    dbsession.add_all(routers)
    return routers
