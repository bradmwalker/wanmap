import logging

from pyramid.config import Configurator
from pyramid.events import BeforeRender, subscriber
from pyramid.httpexceptions import HTTPFound
from pyramid.renderers import get_renderer
from pyramid.session import SignedCookieSessionFactory
from pyramid.view import view_config

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
    config.add_static_view('static', 'static', cache_max_age=3600)
    config.add_static_view('deform', 'deform:static')
    config.add_route('root', '/')
    config.include('.scans')
    config.include('.scanners')

    config.scan(ignore='wanmap.tests')
    return config.make_wsgi_app()


@view_config(route_name='root')
def root_view(request):
    return HTTPFound(request.route_url('show_scans'))
