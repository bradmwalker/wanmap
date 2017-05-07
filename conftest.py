from itertools import starmap
import logging
import os
from unittest.mock import patch

from pyramid.paster import get_appsettings, setup_logging
from pyramid.testing import DummyRequest
import pytest
from webtest import TestApp

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
