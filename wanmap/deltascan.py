from deform import ValidationFailure
from pyramid.httpexceptions import HTTPFound
from pyramid.view import view_config
import transaction

from .scans import (
    DeltaScan, ScanSchema,
    get_scanner_names, get_scannable_subnets,
    NO_KNOWN_SUBNETS_ALERT_MESSAGE,
)
from .tasks import scan_workflow


NO_SCANNERS_ALERT_MESSAGE = (
    'There are no available scanners. Start two or more scanners to enable '
    'Delta Scan.')
ONLY_ONE_SCANNER_ALERT_MESSAGE = (
    'There is only one available scanner. Start two or more scanners to '
    'enable Delta Scan.')
DELTA_SCAN_FORM_TITLE = 'Delta Network Scan'


@view_config(
    route_name='new_delta_scan', request_method='GET',
    renderer='templates/new-scan.jinja2')
def get_new_delta_scan(request):
    subnets = get_scannable_subnets(request.dbsession)
    if not subnets:
        return {'error_message': NO_KNOWN_SUBNETS_ALERT_MESSAGE}
    scanner_names = get_scanner_names(request.dbsession)
    if not scanner_names:
        return {'error_message': NO_SCANNERS_ALERT_MESSAGE}
    elif len(scanner_names) == 1:
        return {'error_message': ONLY_ONE_SCANNER_ALERT_MESSAGE}
    scan_form = ScanSchema.form(scanner_names, subnets)
    scan_form = scan_form.render({'scan_targets': ('',)})
    return {'form_title': DELTA_SCAN_FORM_TITLE, 'scan_form': scan_form}


@view_config(
    route_name='new_delta_scan', request_method='POST',
    renderer='templates/new-scan.jinja2')
def post_new_delta_scan(request):
    subnets = get_scannable_subnets(request.dbsession)
    if not subnets:
        return {'error_message': NO_KNOWN_SUBNETS_ALERT_MESSAGE}
    scanner_names = get_scanner_names(request.dbsession)
    if not scanner_names:
        return {'error_message': NO_SCANNERS_ALERT_MESSAGE}
    elif len(scanner_names) == 1:
        return {'error_message': ONLY_ONE_SCANNER_ALERT_MESSAGE}
    scan_form = ScanSchema.form(scanner_names, subnets)
    controls = request.POST.items()
    try:
        appstruct = scan_form.validate(controls)
    except ValidationFailure as e:
        return {
            'form_title': DELTA_SCAN_FORM_TITLE,
            'scan_form': e.render()
        }
    with transaction.manager:
        scan_id = schedule_delta_scan(request.dbsession, appstruct)
    scan_redirect = request.route_url('show_scan', id=scan_id)
    return HTTPFound(location=scan_redirect)


def schedule_delta_scan(dbsession, appstruct):
    # TODO: Add user from session
    # TODO: Add guest access
    scan = DeltaScan.from_appstruct(dbsession, appstruct)
    scan_id = scan.id
    dbsession.add(scan)
    dbsession.flush()
    scan_workflow.delay(scan_id)
    return scan_id
