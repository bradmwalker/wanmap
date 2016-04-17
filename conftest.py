import logging
import os

from paste.deploy.loadwsgi import appconfig
from pyramid.paster import setup_logging
import pytest
from webtest import TestApp


here = os.path.dirname(__file__)
settings_path = os.path.join(here, 'test.ini')
setup_logging(settings_path)

config_uri = 'config:' + settings_path
settings = appconfig(config_uri)

_logger = logging.getLogger(__name__)


# Is this redundant w/o making app session-scope?
@pytest.fixture
def fresh_app(app):
    app.reset()
    return app


@pytest.fixture
def app(db_session):
    from wanmap import make_wsgi_app
    return TestApp(make_wsgi_app(settings))


@pytest.fixture(scope='session')
def engine():
    from wanmap.schema import init_engine
    return init_engine(settings, keep_session=True)


@pytest.yield_fixture
def db_session(engine):
    from wanmap.schema import DBSession
    connection = engine.connect()
    trans = connection.begin()
    DBSession.configure(bind=connection)
    _db_session = DBSession()
    yield _db_session
    _db_session.close()
    trans.rollback()
#    connection.invalidate()
