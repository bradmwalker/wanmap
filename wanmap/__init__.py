import logging

from pyramid.config import Configurator
from pyramid.session import SignedCookieSessionFactory
from sqlalchemy.orm import configure_mappers

from .schema import Persistable
# Import persistable subclasses without cycles.
from . import (     # noqa
    network, scans,
)

# run configure_mappers after defining all of the models to ensure
# all relationships can be setup
configure_mappers()

_logger = logging.getLogger(__name__)


def setup_shell(env):
    env['dbsession'] = env['request'].dbsession
    env.update({
        name: class_ for name, class_
        in Persistable._decl_class_registry.items()
        if name != '_sa_module_registry'
    })


def main(global_config, **settings):
    """Standard web server entry point."""
    return make_wsgi_app(settings)


def make_wsgi_app(settings):
    """Configure and create a Pyramid WSGI application."""
    config = Configurator(settings=settings)
    config.include('pyramid_jinja2')
    session_factory = SignedCookieSessionFactory('secret')
    config.set_session_factory(session_factory)
    config.include('.schema')
    config.include('.console')
    config.include('.network')
    config.include('.scans')
    config.include('.scanners')
    config.scan()
    return config.make_wsgi_app()
