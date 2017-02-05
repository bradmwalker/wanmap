import logging
import os

from pyramid.paster import get_appsettings, setup_logging
from pyramid.testing import DummyRequest
import pytest
from webtest import TestApp


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
def engine(appsettings):
    from wanmap.schema import get_engine
    return get_engine(appsettings)


@pytest.yield_fixture
def dbsession(engine):
    from wanmap.schema import get_session_factory
    connection = engine.connect()
    trans = connection.begin()
    session_factory = get_session_factory(connection)
    _dbsession = session_factory()
    yield _dbsession
    _dbsession.close()
    trans.rollback()
    connection.close()


@pytest.fixture
def fake_dns(monkeypatch):

    def _fake_dns(hostname):
        import socket
        ip_address = FAKE_DNS_MAP.get(hostname)
        if ip_address is None:
            raise socket.gaierror
        return ip_address

    monkeypatch.setattr('socket.gethostbyname', _fake_dns)
