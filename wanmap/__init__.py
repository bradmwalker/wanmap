import logging

from pyramid.config import Configurator
from pyramid.events import BeforeRender, subscriber
from pyramid.renderers import get_renderer
from pyramid.session import SignedCookieSessionFactory

from .schema import init_engine


_logger = logging.getLogger(__name__)


@subscriber(BeforeRender)
def config_base_template(event):
    base = get_renderer('templates/base.pt').implementation()
    event.update({'base': base})


def main(global_config, **settings):
    """Standard web server entry point."""
    init_engine(settings)
    return make_wsgi_app(settings)


def make_wsgi_app(settings):
    """Configure and create a Pyramid WSGI application."""
    config = Configurator(settings=settings)
    config.include('pyramid_chameleon')
    session_factory = SignedCookieSessionFactory('secret')
    config.set_session_factory(session_factory)
    config.include('.console')
    config.include('.scans')
    config.include('.scanners')

    config.scan(ignore='wanmap.tests')
    return config.make_wsgi_app()
