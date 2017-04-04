import colander
from deform import Form, ValidationFailure
from pyramid.httpexceptions import HTTPFound
from pyramid.view import view_config
import transaction

from .scans import (
    ScanTargets, ScannerPair,
    get_scanner_names, get_scanner_subnets,
    NO_SCANNERS_ALERT_MESSAGE, ONLY_ONE_SCANNER_ALERT_MESSAGE,
)
from .schema import DeltaScan
from .tasks import scan_workflow
# from .util import to_ip_network

DELTA_SCAN_FORM_TITLE = 'Delta Network Scan'


class DeltaScanSchema(colander.Schema):
    nmap_options = colander.SchemaNode(colander.String())
    scanners = ScannerPair()
    scan_targets = ScanTargets()

    @classmethod
    def form(cls, scanner_names, subnets):
        schema = cls().bind(scanner_names=scanner_names, subnets=subnets)
        return Form(schema, formid='delta-scan', buttons=('submit',))


@view_config(
    route_name='new_delta_scan', request_method='GET',
    renderer='templates/new-scan.jinja2')
def get_new_delta_scan(request):
    scanner_names = get_scanner_names(request.dbsession)
    if not scanner_names:
        return {'error_message': NO_SCANNERS_ALERT_MESSAGE}
    elif len(scanner_names) == 1:
        return {'error_message': ONLY_ONE_SCANNER_ALERT_MESSAGE}
    subnets = get_scanner_subnets(request.dbsession)
    scan_form = DeltaScanSchema.form(scanner_names, subnets)
    scan_form = scan_form.render({'scan_targets': ('',)})
    return {'form_title': DELTA_SCAN_FORM_TITLE, 'scan_form': scan_form}


@view_config(
    route_name='new_delta_scan', request_method='POST',
    renderer='templates/new-scan.jinja2')
def post_new_delta_scan(request):
    scanner_names = get_scanner_names(request.dbsession)
    if not scanner_names:
        return {'error_message': NO_SCANNERS_ALERT_MESSAGE}
    elif len(scanner_names) == 1:
        return {'error_message': ONLY_ONE_SCANNER_ALERT_MESSAGE}
    subnets = get_scanner_subnets(request.dbsession)
    scan_form = DeltaScanSchema.form(scanner_names, subnets)
    controls = request.POST.items()
    try:
        appstruct = scan_form.validate(controls)
    except ValidationFailure as e:
        return {
            'form_title': DELTA_SCAN_FORM_TITLE,
            'scan_form': e.render()
        }
    with transaction.manager:
        scan_id = schedule_delta_scan(
            request.dbsession,
            appstruct['nmap_options'],
            (appstruct['scanners']['scanner_a'],
             appstruct['scanners']['scanner_b']),
            *appstruct['scan_targets'])
    scan_redirect = request.route_url('show_scan', id=scan_id)
    return HTTPFound(location=scan_redirect)


def schedule_delta_scan(dbsession, nmap_options, scanner_names, *targets):
    # TODO: Add user from session
    # TODO: Add guest access
    scan = DeltaScan.create(
        dbsession, parameters=nmap_options,
        scanner_names=scanner_names, targets=targets)
    # Look into using zope transaction manager for celery tasks that depend on
    # database records. Then mock out transactions.
    scan_id = scan.id
    dbsession.add(scan)
    dbsession.flush()
    scan_workflow.apply_async((scan_id,), countdown=1)
    return scan_id
