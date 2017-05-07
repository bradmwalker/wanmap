from ipaddress import ip_interface, ip_network
import logging

import colander
from deform import Form, ValidationFailure
from pyramid.httpexceptions import HTTPNotFound
from pyramid.view import view_config
from sqlalchemy import Column, ForeignKey, String
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import relationship

from .schema import Persistable
from .util import intersect_network_sets

logger = logging.getLogger(__name__)


def includeme(config):
    config.add_route('show_scanners', '/scanners/')
    config.add_route('show_scanner', '/scanners/{name}/')


class Scanner(Persistable):
    """The distributed scanner celery instances"""

    __tablename__ = 'scanners'
    name = Column(String(64), primary_key=True)
    interface = Column(postgresql.INET, nullable=False)

    subnets = relationship('ScannerSubnet', backref='scanner')
    subscans = relationship('Subscan', backref='scanner')

    @classmethod
    def create(cls, name, interface_address):
        """Creates a scanner configured to scan its own subnet."""

        scanner = cls(name=name, interface=interface_address)
        subnet = str(ip_interface(interface_address).network)
        scanner.subnets = [ScannerSubnet(scanner_name=name, subnet=subnet)]
        return scanner

    @property
    def subnet_blocks(self):
        return {ip_network(subnet.subnet) for subnet in self.subnets}

    def intersect_scan_targets(self, scan_targets):
        return intersect_network_sets(scan_targets, self.subnet_blocks)


class ScannerSubnet(Persistable):
    """The subnets managed by a scanner"""

    __tablename__ = 'scanner_subnets'
    scanner_name = Column(
        String(64), ForeignKey('scanners.name'), primary_key=True)
    # Should enforce partitioning of address space
    subnet = Column(postgresql.CIDR, primary_key=True)


@view_config(route_name='show_scanners', renderer='templates/scanners.jinja2')
def show_scanners(request):
    scanners = request.dbsession.query(Scanner).order_by(Scanner.name).all()
    return {'scanners': scanners}


def is_network(node, value):
    try:
        ip_network(value)
    except ValueError:
        raise colander.Invalid(
            node, 'Not a valid IP network address'.format(value))


class SubnetsSchema(colander.SequenceSchema):
    subnet = colander.SchemaNode(colander.String(), validator=is_network)


class ScannerSchema(colander.MappingSchema):
    subnets = SubnetsSchema()


@view_config(
    route_name='show_scanner', request_method='GET',
    renderer='templates/scanner.jinja2')
def show_scanner(request):
    name = request.matchdict['name']
    scanner = request.dbsession.query(Scanner).get(name)
    if not scanner:
        raise HTTPNotFound
    scanner_pstruct = {
        'name': scanner.name, 'interface': scanner.interface,
        'subnets': [subnet.subnet for subnet in scanner.subnets]
    }
    scanner_schema = ScannerSchema()
    form = Form(scanner_schema, formid='edit-scanner', buttons=('Edit',))
    form.set_pstruct(scanner_pstruct)

    scanner_form = form.render()
    return {'scanner': scanner, 'scanner_form': scanner_form}


@view_config(
    route_name='show_scanner', request_method='POST',
    renderer='templates/scanner.jinja2')
def edit_scanner(request):
    name = request.matchdict['name']
    scanner = request.dbsession.query(Scanner).get(name)
    if not scanner:
        raise HTTPNotFound
    scanner_schema = ScannerSchema()
    scanner_form = Form(
        scanner_schema, formid='edit-scanner', buttons=('Edit',))
    controls = request.POST.items()
    try:
        appstruct = scanner_form.validate(controls)
    except ValidationFailure as e:
        return {'scanner': scanner, 'scanner_form': e.render()}

    existing_subnets = set(scanner.subnets)
    proposed_subnets = {
        ScannerSubnet(scanner=scanner, subnet=subnet)
        for subnet in appstruct['subnets']
    }
    for subnet in existing_subnets - proposed_subnets:
        request.dbsession.delete(subnet)
    for subnet in proposed_subnets:
        request.dbsession.merge(subnet)
    request.dbsession.merge(scanner)
    return {'scanner': scanner, 'scanner_form': scanner_form.render()}
