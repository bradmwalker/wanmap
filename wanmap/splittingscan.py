from uuid import uuid4
from ipaddress import ip_network
# import socket

import arrow
import colander
from deform import Form, ValidationFailure  # , widget
from pyramid.httpexceptions import HTTPFound
from pyramid.view import view_config
from sqlalchemy import Column, ForeignKey
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import joinedload
import transaction

from .scanners import Scanner
from .scans import (
    get_scanner_subnets, Scan, ScanTarget, ScanTargets, Subscan,
    NO_MAPPED_SUBNETS_ALERT_MESSAGE,
)
from .tasks import scan_workflow

SPLITTING_SCAN_FORM_TITLE = 'Splitting Network Scan'


class SplittingScan(Scan):
    __tablename__ = 'splitting_scans'
    id = Column(
        postgresql.UUID(as_uuid=True), ForeignKey('scans.id'),
        primary_key=True)

    __mapper_args__ = {'polymorphic_identity': 'splitting'}

    @classmethod
    def create(cls, session, parameters, targets):
        if not targets:
            raise ValueError('Must specify at least one scanning target.')
        created_at = arrow.now().datetime
        scan = cls(id=uuid4(), created_at=created_at, parameters=parameters)
        scan.targets.extend(ScanTarget.from_fields(targets))
        scanners = session.query(Scanner).options(joinedload('subnets'))
        scan_targets = {
            ip_network(target.net_block) for target in scan.targets
        }

        scanners_and_matching_targets = {
            scanner: scanner.intersect_scan_targets(scan_targets)
            for scanner in scanners
        }

        if not any(scanners_and_matching_targets.values()):
            raise Exception('No scanners have matching subnets assigned.')

        scan.subscans += [
            Subscan.create(scanner, matched_targets)
            for scanner, matched_targets
            in scanners_and_matching_targets.items()
            if matched_targets
        ]
        return scan


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
    scan_redirect = request.route_url('show_scan', id=scan_id)
    return HTTPFound(location=scan_redirect)


def schedule_splitting_scan(dbsession, nmap_options, *targets):
    # TODO: Add user from session
    # TODO: Add guest access
    scan = SplittingScan.create(
        dbsession, parameters=nmap_options, targets=targets)
    # Look into using zope transaction manager for celery tasks that depend on
    # database records. Then mock out transactions.
    scan_id = scan.id
    dbsession.add(scan)
    dbsession.flush()
    scan_workflow.delay(scan_id)
    return scan_id
