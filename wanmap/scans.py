import enum
from ipaddress import ip_network
from itertools import combinations, product
import logging
from uuid import uuid4, UUID

import arrow
import colander
from deform import Form, widget
from pyramid.httpexceptions import HTTPNotFound
from pyramid.view import view_config

from sqlalchemy import (
    Column, DateTime, ForeignKey, ForeignKeyConstraint, String
)
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import joinedload, relationship

from .network import Router, RouterInterface
from .scanners import Scanner
from .schema import Persistable
from .util import intersect_network_sets, to_ip_network


PING_SWEEP = '-sn -PE -n'
SCAN_LISTING_PAGE_LENGTH = 20
NO_KNOWN_SUBNETS_ALERT_MESSAGE = (
    'WANmap does not know any scannable networks. Scan targets are '
    'constrained to known routeable subnets to optimize scanning. Discover '
    'the network to enable network scanning.')
NO_SCANNERS_ALERT_MESSAGE = (
    'There are no available scanners. Start two or more scanners to enable '
    'Delta Scan.')
ONLY_ONE_SCANNER_ALERT_MESSAGE = (
    'There is only one available scanner. Start two or more scanners to '
    'enable Delta Scan.')

logger = logging.getLogger(__name__)


def includeme(config):
    config.add_route('show_scans', '/scans/')
    config.add_route('show_scan', '/scans/{id}/')
    config.add_route('new_splitting_scan', '/scans/new-splitting')
    config.add_route('new_delta_scan', '/scans/new-delta')


# Maps to a form submission that could potentially run multiple scans on
# multiple scanners
class Scan(Persistable):
    """Top-level construct for a user-submitted network scan task."""

    @enum.unique
    class States(enum.Enum):
        """Possible overall states of an abstract scan."""
        SCHEDULED = 1
        PROGRESSING = 2
        COMPLETED = 3

    __tablename__ = 'scans'
    id = Column(postgresql.UUID(as_uuid=True), primary_key=True)
    created_at = Column(DateTime(timezone=True), nullable=False)
    parameters = Column(String, nullable=False)
    _type = Column('type', String, nullable=False)

    targets = relationship('ScanTarget', backref='scan')
    subscans = relationship('Subscan', backref='scan')

    __mapper_args__ = {
        'polymorphic_identity': 'scan',
        'polymorphic_on': '_type'
    }

    # TODO: Encapsulate Subscan status in Subscan class while implementing
    # Scan cancellation.
    @property
    def status(self):
        """The aggregate status of the Scan's subscans."""
        if all(subscan.finished_at for subscan in self.subscans):
            return Scan.States.COMPLETED
        elif any(subscan.started_at for subscan in self.subscans):
            return Scan.States.PROGRESSING
        else:
            return Scan.States.SCHEDULED


class DeltaScan(Scan):
    __tablename__ = 'delta_scans'
    id = Column(
        postgresql.UUID(as_uuid=True), ForeignKey('scans.id'),
        primary_key=True)

    __mapper_args__ = {'polymorphic_identity': 'delta'}

    @classmethod
    def from_appstruct(cls, dbsession, appstruct):
        nmap_options = appstruct['nmap_options'],
        scanner_names = (
            appstruct['scanners']['scanner_a'],
            appstruct['scanners']['scanner_b']
        )
        targets = appstruct['scan_targets']
        return cls.create(
            dbsession, parameters=nmap_options,
            scanner_names=scanner_names, targets=targets)

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


class SplittingScan(Scan):
    __tablename__ = 'splitting_scans'
    id = Column(
        postgresql.UUID(as_uuid=True), ForeignKey('scans.id'),
        primary_key=True)

    __mapper_args__ = {'polymorphic_identity': 'splitting'}

    @classmethod
    def from_appstruct(cls, dbsession, appstruct):
        nmap_options = appstruct['nmap_options'],
        targets = appstruct['scan_targets']
        return cls.create(dbsession, parameters=nmap_options, targets=targets)

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


class ScanTarget(Persistable):
    """Scan task targets as initially specified."""

    __tablename__ = 'scan_targets'
    scan_id = Column(
        postgresql.UUID(as_uuid=True), ForeignKey('scans.id'),
        primary_key=True)
    net_block = Column(postgresql.CIDR, primary_key=True)
    hostname = Column(String(255))
    # Maps to multiple targets of one nmap instance

    @classmethod
    def from_fields(cls, targets):
        return map(cls.from_field, targets)

    @classmethod
    def from_field(cls, target):
        hostname, net_block = target, to_ip_network(target)
        if hostname != net_block:
            return cls(net_block=net_block, hostname=hostname)
        else:
            return cls(net_block=net_block)


class Subscan(Persistable):
    """
    A scan subtask pinned to a distributed scanner.

    The subtask may run as multiple nmap processes, particularly in the case of
    both IPv4 and IPv6 targets.
    """

    __tablename__ = 'subscans'
    scan_id = Column(
        postgresql.UUID(as_uuid=True), ForeignKey('scans.id'),
        primary_key=True)
    scanner_name = Column(
        String(64), ForeignKey('scanners.name'), primary_key=True)
    started_at = Column(DateTime(timezone=True))
    finished_at = Column(DateTime(timezone=True))
    xml_results = Column(String)

    targets = relationship('SubscanTarget', backref='subscan')

    @classmethod
    def create(cls, scanner, targets):
        subscan = cls(scanner=scanner)
        targets = map(str, targets)
        subscan.targets += [
            SubscanTarget(target=target) for target in targets
        ]
        return subscan

    # TODO: Make symmetric start method?
    def complete(self, xml_results, duration):
        self.xml_results = xml_results
        self.started_at, self.finished_at = duration


class SubscanTarget(Persistable):
    """A target of a scan subtask, after pruning to scanner's subnets."""

    __tablename__ = 'subscan_targets'
    scan_id = Column(postgresql.UUID(as_uuid=True), primary_key=True)
    scanner_name = Column(String(64), primary_key=True)
    target = Column(postgresql.CIDR, primary_key=True)

    __table_args__ = (
        ForeignKeyConstraint(
            ('scan_id', 'scanner_name'),
            ('subscans.scan_id', 'subscans.scanner_name'),
        ),
    )


class ScanTargetNode(colander.SchemaNode):
    schema_type = colander.String

    def validator(self, node, cstruct):
        subnets = self.bindings['subnets']
        try:
            target = to_ip_network(cstruct)
        except ValueError as exc:
            raise colander.Invalid(node, exc.args[0])
        if not does_target_match_subnets(target, subnets):
            raise colander.Invalid(
                node, 'Must overlap a subnet assigned to a scanner')


class ScanTargets(colander.SequenceSchema):
    scan_target = ScanTargetNode()

    def validator(self, node, cstruct):
        targets = cstruct
        if not targets:
            raise colander.Invalid(
                node, 'Must submit at least one Scan Target')
        resolved_targets = tuple(map(to_ip_network, targets))
        overlapping_target_indices = self._collect_overlapping_targets(
            resolved_targets)
        if overlapping_target_indices:
            self._raise_overlapping_exception(
                node, overlapping_target_indices)

    def _collect_overlapping_targets(self, targets):
        indexed_targets = enumerate(targets)
        target_pairs = combinations(indexed_targets, 2)
        overlapping_indices = set()
        for (index_a, target_a), (index_b, target_b) in target_pairs:
            if target_a.overlaps(target_b):
                overlapping_indices |= {index_a, index_b}
        return overlapping_indices

    def _raise_overlapping_exception(self, node, overlapping_indices):
        exc = colander.Invalid(node)
        scan_target_node = node.children[0]
        for index in overlapping_indices:
            sub_exc = colander.Invalid(
                scan_target_node,
                'Target cannot overlap other targets')
            exc.add(sub_exc, pos=index)
        raise exc


def get_scanner_names(dbsession):
    return {name for name, in dbsession.query(Scanner.name)}


def get_scannable_subnets(dbsession):
    return {
        interface.network
        for interface, in dbsession.query(RouterInterface.address)
    }


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
        missing=colander.drop,
        widget=deferred_scanner_select_widget,
        validator=deferred_scanner_select_validator,
    )
    scanner_b = colander.SchemaNode(
        colander.String(),
        missing=colander.drop,
        widget=deferred_scanner_select_widget,
        validator=deferred_scanner_select_validator,
        description='Choose scanners to perform a differential scan.',
    )

    def validator(self, node, cstruct):
        scanner_a = cstruct.get('scanner_a')
        scanner_b = cstruct.get('scanner_b')
        if not scanner_a and scanner_b:
            exc = colander.Invalid(node)
            exc['scanner_a'] = 'Required'
            raise exc
        if scanner_a and not scanner_b:
            exc = colander.Invalid(node)
            exc['scanner_b'] = 'Required'
            raise exc
        if scanner_a and scanner_b and scanner_a == scanner_b:
            exc = colander.Invalid(node)
            exc['scanner_b'] = 'Must be different from Scanner A'
            raise exc


class ScanSchema(colander.Schema):
    nmap_options = colander.SchemaNode(colander.String())
    scanners = ScannerPair(
        widget=widget.MappingWidget(template='mapping_accordion', open=False))
    scan_targets = ScanTargets()

    @classmethod
    def form(cls, scanner_names, subnets):
        schema = cls().bind(scanner_names=scanner_names, subnets=subnets)
        return Form(schema, formid='scan', buttons=('submit',))


@view_config(route_name='show_scan', renderer='templates/scan.jinja2')
def show_scan(request):
    try:
        # Hyphen separators and case insensitivity allow noncanonical
        # representations.
        id_ = UUID(request.matchdict['id'])
    except ValueError:
        raise HTTPNotFound()
    scan = request.dbsession.query(Scan).get(id_)
    if not scan:
        raise HTTPNotFound()
    standalone = 'standalone' in request.params
    return {'scan': scan, 'standalone': standalone}


@view_config(route_name='show_scans', renderer='templates/scans.jinja2')
def show_scans(request):
    scans = tuple(
        request.dbsession.query(Scan).
        order_by(Scan.created_at.desc())
        [:SCAN_LISTING_PAGE_LENGTH])
    return {'scans': scans}


def schedule_scan(dbsession, scan_class, appstruct):
    # TODO: Fix circular import
    from .tasks import scan_workflow
    # TODO: Add user from session
    # TODO: Add guest access
    scan = scan_class.from_appstruct(dbsession, appstruct)
    scan_id = scan.id
    dbsession.add(scan)
    dbsession.flush()
    scan_workflow.delay(scan_id)
    return scan_id
