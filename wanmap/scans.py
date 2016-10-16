from ipaddress import ip_network
import logging
import socket

import arrow
import colander
from deform import Form, ValidationFailure, widget
from pyramid.httpexceptions import HTTPFound, HTTPNotFound
from pyramid.view import view_config
import transaction

from .schema import User, Scan, Scanner, ScannerSubnet
from .tasks import scan_workflow
from .util import to_ip_network


SPLITTING_SCAN_FORM_TITLE = 'Splitting Network Scan'
DELTA_SCAN_FORM_TITLE = 'Delta Network Scan'
SCAN_LISTING_PAGE_LENGTH = 20
NO_MAPPED_SUBNETS_ALERT_MESSAGE = 'There are no subnets mapped. The Splitting Scan distributes scan jobs to scanners according to assigned subnets. Start scanners and/or assign subnets to the scanners.'


logger = logging.getLogger(__name__)


def includeme(config):
    config.add_route('show_scans', '/scans/')
    config.add_route('show_scan', '/scans/{time}/')
    config.add_route('new_splitting_scan', '/scans/new-splitting')
    config.add_route('new_delta_scan', '/scans/new-delta')


class ScanTarget(colander.SchemaNode):
    schema_type = colander.String

    def validator(self, node, cstruct):
        subnets = self.bindings['subnets']
        try:
            target = to_ip_network(cstruct)
        except socket.gaierror:
            raise colander.Invalid(node, 'Unable to resolve hostname')
        if not does_target_match_subnets(target, subnets):
            raise colander.Invalid(
                node, 'Must overlap a subnet assigned to a scanner')


class ScanTargets(colander.SequenceSchema):
    scan_target = ScanTarget()
    validator = colander.Length(
        min=1, min_err='Must submit at least one Scan Target')


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


def get_scanner_names(dbsession):
    return {name for name, in dbsession.query(Scanner.name)}


def get_scanner_subnets(dbsession):
    return {subnet for subnet, in dbsession.query(ScannerSubnet.subnet)}


def does_target_match_subnets(target, subnets):
    target = ip_network(target)
    subnets = tuple(map(ip_network, subnets))
    return any(map(target.overlaps, subnets))


@colander.deferred
def deferred_scanner_select_widget(node, kw):
    scanner_names = sorted(kw.get('scanner_names', set()))
    scanner_values = (
        (('', '- Select -'),) +
        tuple(zip(scanner_names, scanner_names)))
    return widget.SelectWidget(values=scanner_values)


@colander.deferred
def deferred_scanner_select_validator(node, kw):
    scanner_names = kw.get('scanner_names', set())
    return colander.OneOf(scanner_names)


class ScannerPair(colander.Schema):
    scanner_a = colander.SchemaNode(
        colander.String(),
        widget=deferred_scanner_select_widget,
        validator=deferred_scanner_select_validator)
    scanner_b = colander.SchemaNode(
        colander.String(),
        widget=deferred_scanner_select_widget,
        validator=deferred_scanner_select_validator)

    def validator(self, node, cstruct):
        scanner_a, scanner_b = cstruct['scanner_a'], cstruct['scanner_b']
        if scanner_a and scanner_b and scanner_a == scanner_b:
            exc = colander.Invalid(node)
            exc['scanner_b'] = 'Must be different from Scanner A'
            raise exc


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
    subnets = get_scanner_subnets(request.dbsession)
    scan_form = DeltaScanSchema.form(scanner_names, subnets)
    scan_form = scan_form.render({'scan_targets': ('',)})
    return {'form_title': DELTA_SCAN_FORM_TITLE, 'scan_form': scan_form}


@view_config(
    route_name='new_delta_scan', request_method='POST',
    renderer='templates/new-scan.jinja2')
def post_new_delta_scan(request):
    scanner_names = get_scanner_names(request.dbsession)
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
    scan_redirect = request.route_url('show_scan', time=scan_id.isoformat())
    return HTTPFound(location=scan_redirect)


@view_config(route_name='show_scan', renderer='templates/scan.jinja2')
def show_scan(request):
    try:
        time = arrow.get(request.matchdict['time'])
    except arrow.parser.ParserError:
        raise HTTPNotFound()
    scan = request.dbsession.query(Scan).get(time.datetime)
    if not scan:
        raise HTTPNotFound()
    return {'scan': scan}


@view_config(route_name='show_scans', renderer='templates/scans.jinja2')
def show_scans(request):
    scans = tuple(
        request.dbsession.query(Scan).
        order_by(Scan.created_at.desc())
        [:SCAN_LISTING_PAGE_LENGTH])
    return {'scans': scans}


def schedule_splitting_scan(dbsession, nmap_options, *targets):
    # TODO: Add user from session
    # TODO: Add guest access
    user = dbsession.query(User).get('admin')
    scan = Scan.create_splitting(
        dbsession, user=user, parameters=nmap_options, targets=targets)
    # Look into using zope transaction manager for celery tasks that depend on
    # database records. Then mock out transactions.
    dbsession.add(scan)
    dbsession.flush()
    scan_time = scan.created_at
    scan_workflow.apply_async((scan_time,), countdown=1)
    return scan_time


def schedule_delta_scan(dbsession, nmap_options, scanner_names, *targets):
    # TODO: Add user from session
    # TODO: Add guest access
    user = dbsession.query(User).get('admin')
    scan = Scan.create_delta(
        dbsession, user=user, parameters=nmap_options,
        scanner_names=scanner_names, targets=targets)
    # Look into using zope transaction manager for celery tasks that depend on
    # database records. Then mock out transactions.
    dbsession.add(scan)
    dbsession.flush()
    scan_time = scan.created_at
    scan_workflow.apply_async((scan_time,), countdown=1)
    return scan_time
