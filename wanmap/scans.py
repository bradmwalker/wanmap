import enum
from ipaddress import ip_network
from itertools import combinations
import logging
import uuid

import colander
from deform import widget
from pyramid.httpexceptions import HTTPNotFound
from pyramid.view import view_config

from sqlalchemy import (
    Column, DateTime, ForeignKey, ForeignKeyConstraint, String
)
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import relationship

from .network import RouterInterface
from .scanners import Scanner
from .schema import Persistable
from .util import to_ip_network


PING_SWEEP = '-sn -PE -n'
SCAN_LISTING_PAGE_LENGTH = 20
NO_MAPPED_SUBNETS_ALERT_MESSAGE = (
    'There are no subnets mapped. The Splitting Scan distributes scan jobs to '
    'scanners according to assigned subnets. Start scanners and/or assign '
    'subnets to the scanners.')
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


@view_config(route_name='show_scan', renderer='templates/scan.jinja2')
def show_scan(request):
    try:
        # Hyphen separators and case insensitivity allow noncanonical
        # representations.
        id_ = uuid.UUID(request.matchdict['id'])
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
