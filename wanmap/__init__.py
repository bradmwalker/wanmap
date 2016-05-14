import logging

from pyramid.config import Configurator
from pyramid.session import SignedCookieSessionFactory


_logger = logging.getLogger(__name__)


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
    config.include('.scans')
    config.include('.scanners')
    config.include('.users')

    config.scan(ignore='wanmap.tests')
    return config.make_wsgi_app()
