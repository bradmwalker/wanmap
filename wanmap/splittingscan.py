from itertools import product
from uuid import uuid4

import arrow
from deform import ValidationFailure
from pyramid.httpexceptions import HTTPFound
from pyramid.view import view_config
from sqlalchemy import Column, ForeignKey
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import joinedload
import transaction

from .deltascan import ScanSchema
from .network import Router
from .scanners import Scanner
from .scans import (
    get_scanner_names, get_scannable_subnets,
    Scan, ScanTarget, Subscan,
    NO_KNOWN_SUBNETS_ALERT_MESSAGE,
)
from .tasks import scan_workflow


NO_SCANNERS_ALERT_MESSAGE = (
    'There are no available scanners. Start one or more scanners to enable '
    'Splitting Scan.')
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
        scan_targets = {target.net_block for target in scan.targets}
        scanners = session.query(Scanner).all()
        routers = (
            session.query(Router).
            options(joinedload('_interfaces')).all())
        router_scanner_map = {
            router: scanner for router, scanner in product(routers, scanners)
            if router.is_scanner_link_local(scanner)
        }

        routers_and_matching_targets = {
            router: router.intersect_scan_targets(scan_targets)
            for router in routers
        }
        # intersect_network_sets(scan_targets, self.subnet_blocks)
        if not any(routers_and_matching_targets.values()):
            raise Exception('No routers have scan targets directly attached.')

        scan.subscans += [
            Subscan.create(router_scanner_map[router], matched_targets)
            for router, matched_targets
            in routers_and_matching_targets.items()
            if matched_targets
        ]
        return scan


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
