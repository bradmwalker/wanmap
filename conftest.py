import logging
import os

from paste.deploy.loadwsgi import appconfig
from pyramid.paster import setup_logging
from pyramid.testing import DummyRequest
import pytest
from webtest import TestApp


FAKE_DNS_MAP = {
    'wanmap.local': '10.0.0.254',
    'example.com': '93.184.216.34',
}

here = os.path.dirname(__file__)
settings_path = os.path.join(here, 'test.ini')
setup_logging(settings_path)

config_uri = 'config:' + settings_path
settings = appconfig(config_uri)

_logger = logging.getLogger(__name__)


@pytest.fixture
def view_request(dbsession):
    return DummyRequest(dbsession=dbsession)


# Is this redundant w/o making app session-scope?
@pytest.fixture
def fresh_app(app):
    app.reset()
    return app


@pytest.fixture
def app(dbsession):
    from wanmap import make_wsgi_app
    return TestApp(make_wsgi_app(settings))


@pytest.fixture(scope='session')
def engine():
    from wanmap.schema import get_engine
    return get_engine(settings)


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
#    connection.invalidate()


@pytest.fixture
def fake_dns(monkeypatch):

    def _fake_dns(hostname):
        import socket
        ip_address = FAKE_DNS_MAP.get(hostname)
        if ip_address is None:
            raise socket.gaierror
        return ip_address

    monkeypatch.setattr('socket.gethostbyname', _fake_dns)
