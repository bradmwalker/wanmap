# from ipaddress import ip_network
# import socket

# import arrow
import colander
from deform import Form, ValidationFailure  # , widget
from pyramid.httpexceptions import HTTPFound
from pyramid.view import view_config
import transaction

from .scans import (
    get_scanner_subnets, ScanTargets, NO_MAPPED_SUBNETS_ALERT_MESSAGE
)
from .schema import (
    User, SplittingScan
)
from .tasks import scan_workflow
# from .util import to_ip_network

SPLITTING_SCAN_FORM_TITLE = 'Splitting Network Scan'


class SplittingScanSchema(colander.Schema):
    nmap_options = colander.SchemaNode(colander.String())
    scan_targets = ScanTargets()

    @classmethod
    def form(cls, subnets):
        schema = cls().bind(subnets=subnets)
        return Form(schema, formid='splitting-scan', buttons=('submit',))


@view_config(
    route_name='new_splitting_scan', request_method='GET',
    renderer='templates/new-scan.jinja2')
def get_new_splitting_scan(request):
    subnets = get_scanner_subnets(request.dbsession)
    if not subnets:
        return {'error_message': NO_MAPPED_SUBNETS_ALERT_MESSAGE}
    scan_form = SplittingScanSchema.form(subnets=subnets)
    scan_form = scan_form.render({'scan_targets': ('',)})
    return {'form_title': SPLITTING_SCAN_FORM_TITLE, 'scan_form': scan_form}


@view_config(
    route_name='new_splitting_scan', request_method='POST',
    renderer='templates/new-scan.jinja2')
def post_new_splitting_scan(request):
    subnets = get_scanner_subnets(request.dbsession)
    if not subnets:
        return {'error_message': NO_MAPPED_SUBNETS_ALERT_MESSAGE}
    scan_form = SplittingScanSchema.form(subnets=subnets)
    controls = request.POST.items()
    try:
        appstruct = scan_form.validate(controls)
    except ValidationFailure as e:
        return {
            'form_title': SPLITTING_SCAN_FORM_TITLE,
            'scan_form': e.render()
        }
    with transaction.manager:
        scan_id = schedule_splitting_scan(
            request.dbsession,
            appstruct['nmap_options'],
            *appstruct['scan_targets'])
    scan_redirect = request.route_url('show_scan', time=scan_id.isoformat())
    return HTTPFound(location=scan_redirect)


def schedule_splitting_scan(dbsession, nmap_options, *targets):
    # TODO: Add user from session
    # TODO: Add guest access
    user = dbsession.query(User).get('admin')
    scan = SplittingScan.create(
        dbsession, user=user, parameters=nmap_options, targets=targets)
    # Look into using zope transaction manager for celery tasks that depend on
    # database records. Then mock out transactions.
    dbsession.add(scan)
    dbsession.flush()
    scan_time = scan.created_at
    scan_workflow.apply_async((scan_time,), countdown=1)
    return scan_time