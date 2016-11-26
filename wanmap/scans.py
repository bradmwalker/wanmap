from ipaddress import ip_network
import logging
import socket

import arrow
import colander
from deform import widget
from pyramid.httpexceptions import HTTPNotFound
from pyramid.view import view_config

from .schema import (
    Scan, Scanner, ScannerSubnet,
)
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
    config.add_route('show_scan', '/scans/{time}/')
    config.add_route('new_splitting_scan', '/scans/new-splitting')
    config.add_route('new_delta_scan', '/scans/new-delta')


class ScanTargetNode(colander.SchemaNode):
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
    scan_target = ScanTargetNode()
    validator = colander.Length(
        min=1, min_err='Must submit at least one Scan Target')


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
