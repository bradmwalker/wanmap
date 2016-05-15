import ipaddress
import logging

import colander
from deform import Form, ValidationFailure
from pyramid.httpexceptions import HTTPNotFound
from pyramid.view import view_config

from .schema import Scanner, ScannerSubnet


logger = logging.getLogger(__name__)


def includeme(config):
    config.add_route('show_scanners', '/scanners/')
    config.add_route('show_scanner', '/scanners/{name}/')


@view_config(route_name='show_scanners', renderer='templates/scanners.jinja2')
def show_scanners(request):
    scanners = request.dbsession.query(Scanner).order_by(Scanner.name).all()
    return {'scanners': scanners}


def is_network(node, value):
    try:
        ipaddress.ip_network(value)
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
