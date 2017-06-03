from deform import ValidationFailure
from pyramid.httpexceptions import HTTPFound
from pyramid.view import view_config
import transaction

from .scans import (
    get_scanner_names, get_scannable_subnets, schedule_scan,
    SplittingScan, ScanSchema,
    NO_KNOWN_SUBNETS_ALERT_MESSAGE,
)


NO_SCANNERS_ALERT_MESSAGE = (
    'There are no available scanners. Start one or more scanners to enable '
    'Splitting Scan.')
SPLITTING_SCAN_FORM_TITLE = 'Splitting Network Scan'


@view_config(
    route_name='new_splitting_scan', request_method='GET',
    renderer='templates/new-scan.jinja2')
def get_new_splitting_scan(request):
    subnets = get_scannable_subnets(request.dbsession)
    if not subnets:
        return {'error_message': NO_KNOWN_SUBNETS_ALERT_MESSAGE}
    scanner_names = get_scanner_names(request.dbsession)
    if not scanner_names:
        return {'error_message': NO_SCANNERS_ALERT_MESSAGE}
    scan_form = ScanSchema.form(scanner_names=scanner_names, subnets=subnets)
    scan_form = scan_form.render({'scan_targets': ('',)})
    return {'form_title': SPLITTING_SCAN_FORM_TITLE, 'scan_form': scan_form}


@view_config(
    route_name='new_splitting_scan', request_method='POST',
    renderer='templates/new-scan.jinja2')
def post_new_splitting_scan(request):
    subnets = get_scannable_subnets(request.dbsession)
    if not subnets:
        return {'error_message': NO_KNOWN_SUBNETS_ALERT_MESSAGE}
    scanner_names = get_scanner_names(request.dbsession)
    if not scanner_names:
        return {'error_message': NO_SCANNERS_ALERT_MESSAGE}
    scan_form = ScanSchema.form(scanner_names=scanner_names, subnets=subnets)
    controls = request.POST.items()
    try:
        appstruct = scan_form.validate(controls)
    except ValidationFailure as e:
        return {
            'form_title': SPLITTING_SCAN_FORM_TITLE,
            'scan_form': e.render()
        }
    with transaction.manager:
        scan_id = schedule_scan(request.dbsession, SplittingScan, appstruct)
    scan_redirect = request.route_url('show_scan', id=scan_id)
    return HTTPFound(location=scan_redirect)
