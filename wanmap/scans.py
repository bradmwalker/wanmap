import ipaddress
import logging

import arrow
import colander
from deform import Form, ValidationFailure, widget
from pyramid.httpexceptions import HTTPFound, HTTPNotFound
from pyramid.view import view_config
import transaction

from .schema import DBSession, User, Scan, Scanner
from .tasks import scan_workflow


SCAN_LISTING_PAGE_LENGTH = 20


logger = logging.getLogger(__name__)


def includeme(config):
    config.add_route('show_scans', '/scans/')
    config.add_route('show_scan', '/scans/{time}/')
    config.add_route('new_split_scan', '/scans/new_split')
    config.add_route('new_delta_scan', '/scans/new_delta')


def is_scan_target(node, value):
    try:
        ipaddress.ip_network(value)
    except ValueError:
        raise colander.Invalid(
            node, 'Not an IP Address or Network'.format(value))


class ScanTargets(colander.SequenceSchema):
    scan_target = colander.SchemaNode(
        colander.String(), validator=is_scan_target)


class SplitScanSchema(colander.Schema):
    nmap_options = colander.SchemaNode(colander.String())
    scan_targets = ScanTargets(
        validator=colander.Length(
            min=1, min_err='Must submit at least one Scan Target.'))
    title = 'Distributed Network Scan'

    @classmethod
    def form(cls):
        return Form(cls(), formid='scan', buttons=('submit',))


@view_config(
    route_name='new_split_scan', request_method='GET',
    renderer='templates/new-scan.pt')
def get_new_split_scan(request):
    scan_form = SplitScanSchema.form()
    scan_form = scan_form.render({'scan_targets': ('',)})
    return {'scan_form': scan_form}


@view_config(
    route_name='new_split_scan', request_method='POST',
    renderer='templates/new-scan.pt')
def post_new_split_scan(request):
    scan_form = SplitScanSchema.form()
    controls = request.POST.items()
    try:
        appstruct = scan_form.validate(controls)
    except ValidationFailure as e:
        return {'scan_form': e.render()}
    with transaction.manager:
        scan_id = schedule_split_scan(
            appstruct['nmap_options'], *appstruct['scan_targets'])
    scan_redirect = request.route_url('show_scan', time=scan_id.isoformat())
    return HTTPFound(location=scan_redirect)


@colander.deferred
def deferred_scanner_select_widget(node, kw):
    scanner_names = kw.get('scanner_names', ())
    return widget.SelectWidget(values=scanner_names)


class DeltaScanSchema(colander.Schema):
    nmap_options = colander.SchemaNode(colander.String())
    scanner_a = colander.SchemaNode(
        colander.String(), widget=deferred_scanner_select_widget)
    scanner_b = colander.SchemaNode(
        colander.String(), widget=deferred_scanner_select_widget)
    scan_targets = ScanTargets(
        validator=colander.Length(
            min=1, min_err='Must submit at least one Scan Target.'))
    title = 'Delta Network Scan'

    @classmethod
    def form(cls, scanner_names):
        scanner_names.insert(0, ('select', 'Select Scanner'))
        schema = cls().bind(scanner_names=scanner_names)
        return Form(schema, formid='delta-scan', buttons=('submit',))


@view_config(
    route_name='new_delta_scan', request_method='GET',
    renderer='templates/new-scan.pt')
def get_new_delta_scan(request):
    scanner_names = (
        DBSession.query(Scanner.name, Scanner.name).
        order_by(Scanner.name).
        all())
    scan_form = DeltaScanSchema.form(scanner_names)
    scan_form = scan_form.render({'scan_targets': ('',)})
    return {'scan_form': scan_form}


@view_config(
    route_name='new_delta_scan', request_method='POST',
    renderer='templates/new-scan.pt')
def post_new_delta_scan(request):
    scanner_names = (
        DBSession.query(Scanner.name, Scanner.name).
        order_by(Scanner.name).
        all())
    scan_form = DeltaScanSchema.form(scanner_names)
    controls = request.POST.items()
    try:
        appstruct = scan_form.validate(controls)
    except ValidationFailure as e:
        return {'scan_form': e.render()}
    with transaction.manager:
        scan_id = schedule_delta_scan(
            appstruct['nmap_options'],
            (appstruct['scanner_a'], appstruct['scanner_b']),
            *appstruct['scan_targets'])
    scan_redirect = request.route_url('show_scan', time=scan_id.isoformat())
    return HTTPFound(location=scan_redirect)


@view_config(route_name='show_scan', renderer='templates/scan.pt')
def show_scan(request):
    try:
        time = arrow.get(request.matchdict['time'])
    except arrow.parser.ParserError:
        raise HTTPNotFound()
    scan = DBSession.query(Scan).get(time.datetime)
    if not scan:
        raise HTTPNotFound()
    return {'scan': scan}


@view_config(route_name='show_scans', renderer='templates/scans.pt')
def show_scans(request):
    scans = tuple(
        DBSession.query(Scan).
        order_by(Scan.created_at.desc())
        [:SCAN_LISTING_PAGE_LENGTH])
    return {'scans': scans}


def schedule_split_scan(nmap_options, *targets):
    # TODO: Add user from session
    # TODO: Add guest access
    user = DBSession.query(User).get('admin')
    scan = Scan.create_split(
        DBSession, user=user, parameters=nmap_options, targets=targets)
    # Look into using zope transaction manager for celery tasks that depend on
    # database records. Then mock out transactions.
    DBSession.add(scan)
    DBSession.flush()
    scan_time = scan.created_at
    scan_workflow.apply_async((scan_time,), countdown=1)
    return scan_time


def schedule_delta_scan(nmap_options, scanner_names, *targets):
    # TODO: Add user from session
    # TODO: Add guest access
    user = DBSession.query(User).get('admin')
    scan = Scan.create_delta(
        DBSession, user=user, parameters=nmap_options,
        scanner_names=scanner_names, targets=targets)
    # Look into using zope transaction manager for celery tasks that depend on
    # database records. Then mock out transactions.
    DBSession.add(scan)
    DBSession.flush()
    scan_time = scan.created_at
    scan_workflow.apply_async((scan_time,), countdown=1)
    return scan_time
