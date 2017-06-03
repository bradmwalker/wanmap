from uuid import uuid4

import arrow
import colander
from deform import Form, ValidationFailure, widget
from pyramid.httpexceptions import HTTPFound
from pyramid.view import view_config
from sqlalchemy import Column, ForeignKey
from sqlalchemy.dialects import postgresql
import transaction

from .scanners import Scanner
from .scans import (
    Scan, ScanTarget, Subscan,
    ScanTargets, ScannerPair,
    get_scanner_names, get_scannable_subnets,
    NO_KNOWN_SUBNETS_ALERT_MESSAGE,
)
from .tasks import scan_workflow
from .util import intersect_network_sets


NO_SCANNERS_ALERT_MESSAGE = (
    'There are no available scanners. Start two or more scanners to enable '
    'Delta Scan.')
ONLY_ONE_SCANNER_ALERT_MESSAGE = (
    'There is only one available scanner. Start two or more scanners to '
    'enable Delta Scan.')
DELTA_SCAN_FORM_TITLE = 'Delta Network Scan'


class DeltaScan(Scan):
    __tablename__ = 'delta_scans'
    id = Column(
        postgresql.UUID(as_uuid=True), ForeignKey('scans.id'),
        primary_key=True)

    __mapper_args__ = {'polymorphic_identity': 'delta'}

    @classmethod
    def create(cls, session, parameters, scanner_names, targets):
        if not targets:
            raise ValueError('Must specify at least one scanning target.')
        created_at = arrow.now().datetime
        scan = cls(id=uuid4(), created_at=created_at, parameters=parameters)
        scan.targets.extend(ScanTarget.from_fields(targets))
        scannable_subnets = get_scannable_subnets(session)
        scan_targets = {target.net_block for target in scan.targets}
        subscan_targets = intersect_network_sets(
            scan_targets, scannable_subnets)

        scanner_a = session.query(Scanner).get(scanner_names[0])
        scanner_b = session.query(Scanner).get(scanner_names[1])

        scan.subscans += [
            Subscan.create(scanner_a, subscan_targets),
            Subscan.create(scanner_b, subscan_targets),
        ]
        return scan


class DeltaScanSchema(colander.Schema):
    nmap_options = colander.SchemaNode(colander.String())
    scanners = ScannerPair(
        widget=widget.MappingWidget(template='mapping_accordion', open=False))
    scan_targets = ScanTargets()

    @classmethod
    def form(cls, scanner_names, subnets):
        schema = cls().bind(scanner_names=scanner_names, subnets=subnets)
        return Form(schema, formid='delta-scan', buttons=('submit',))


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
    scan_form = DeltaScanSchema.form(scanner_names, subnets)
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
    scan_workflow.delay(scan_id)
    return scan_id
