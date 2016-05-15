from pyramid.httpexceptions import HTTPFound
from pyramid.view import notfound_view_config, view_config


def includeme(config):
    config.add_static_view('static', 'static', cache_max_age=3600)
    config.add_static_view('deform', 'deform:static')
    config.add_route('root', '/')


@view_config(route_name='root')
def root_view(request):
    return HTTPFound(request.route_url('show_scans'))


@notfound_view_config(renderer='templates/404.jinja2')
def notfound_view(request):
    request.response.status = 404
    return {}
