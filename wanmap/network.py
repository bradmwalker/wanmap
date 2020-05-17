from collections import deque
from ipaddress import ip_address, ip_interface
import logging
import re
from uuid import UUID

import arrow
import colander
from deform import Form, ValidationFailure
from deform.widget import PasswordWidget
from napalm import get_network_driver
from pyramid.httpexceptions import HTTPFound
from pyramid.view import view_config
from sqlalchemy import Column, DateTime, ForeignKey, String
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import joinedload, relationship
import transaction

from .schema import Persistable
from .util import intersect_network_sets

logger = logging.getLogger(__name__)


def includeme(config):
    config.add_route('show_network', '/network')


@view_config(
    route_name='show_network', request_method='GET',
    renderer='templates/network.jinja2')
def get_network(request):
    discovery_form = DiscoveryValidator.form()
    discovery_form = discovery_form.render()
    routers = (
        request.dbsession.query(Router).
        options(joinedload('_interfaces')).
        order_by(Router.id).
        all())
    return {
        'discovery_invalid': False,
        'discovery_form': discovery_form,
        'routers': routers,
    }


@view_config(
    route_name='show_network', request_method='POST',
    renderer='templates/network.jinja2')
def post_network_update(request):
    discovery_form = DiscoveryValidator.form()
    controls = request.POST.items()
    try:
        appstruct = discovery_form.validate(controls)
    except ValidationFailure as e:
        discovery_form = e.render()
        routers = (
            request.dbsession.query(Router).
            options(joinedload('_interfaces')).
            order_by(Router.id).
            all())
        return {
            'discovery_invalid': True,
            'discovery_form': discovery_form,
            'routers': routers,
        }

    # Resolve IP address
    seed_router_address = ip_address(appstruct['seed_router_host'])
    credentials = (appstruct['username'], appstruct['password'])
    with transaction.manager:
        routers = discover_network(seed_router_address, credentials)
        for router in routers:
            request.dbsession.merge(router)

    network_redirect = request.route_url('show_network')
    return HTTPFound(location=network_redirect)


class Router(Persistable):

    __tablename__ = 'routers'

    hostname = Column(String, primary_key=True)
    last_collected_at = Column(DateTime(timezone=True), nullable=False)

    _interfaces = relationship(
        'RouterInterface', cascade='all, delete-orphan', backref='router')

    @classmethod
    def create(cls, hostname, interfaces):
        interfaces = [
            RouterInterface(address=interface) for interface in interfaces
        ]
        return cls(
            hostname=hostname,
            last_collected_at=arrow.now().datetime,
            _interfaces=interfaces,
        )

    @property
    def interfaces(self):
        return frozenset(interface.address for interface in self._interfaces)

    @property
    def connected_subnets(self):
        return frozenset(interface.network for interface in self.interfaces)

    def is_scanner_link_local(self, scanner):
        return any(
            scanner.interface in interface.network
            for interface in self.interfaces)

    def intersect_scan_targets(self, scan_targets):
        return intersect_network_sets(scan_targets, self.connected_subnets)


class RouterInterface(Persistable):

    __tablename__ = 'router_interfaces'

    router_hostname = Column(
        String, ForeignKey('routers.hostname'), primary_key=True)
    address = Column(postgresql.INET, primary_key=True)


class DiscoveryValidator(colander.Schema):
    seed_router_host = colander.SchemaNode(
        colander.String(), title='Seed Router IP Address')
    username = colander.SchemaNode(
        colander.String(), validator=colander.Length(max=32))
    password = colander.SchemaNode(
        colander.String(), validator=colander.Length(max=32),
        widget=PasswordWidget())

    @classmethod
    def form(cls):
        schema = cls()
        return Form(schema, formid='discover-network', buttons=('submit',))


def discover_network(seed_router_hostname, credentials):
    """Traverses the network using BFS and collects router information."""

    to_visit = deque((seed_router_hostname,))
    routers = []
    discovered = {seed_router_hostname}
    while to_visit:
        visiting = to_visit.popleft()
        router, neighbors = get_router(visiting, credentials)
        if router:
            routers.append(router)
            for neighbor in neighbors:
                if neighbor not in discovered:
                    discovered.add(neighbor)
                    to_visit.append(neighbor)
    return routers


def get_router(hostname, credentials):
    """Collects router information and returns its LLDP neighbors."""

    # TODO: Fingerprint router before initializing proper driver
    driver = get_network_driver('vyos')
    with driver(hostname, *credentials) as device:
        logger.info('Collecting router information for %s', hostname)
        router = Router.create(
            hostname=hostname,
            interfaces=_get_router_interfaces(device))
        logger.info(
            'Collected router %s with %d interfaces',
            router.hostname, len(router.interfaces))
        neighbors = _get_neighbors(device)
        return router, neighbors


def _get_router_interfaces(device):
    ips = device.get_interfaces_ip()
    interfaces = []
    for interface, protocols in ips.items():
        for protocol, addresses in protocols.items():
            for address, prefix_len in addresses.items():
                address = ip_interface(
                    f"{address}/{prefix_len['prefix_length']}")
                interfaces.append(address)
    return frozenset(
        interface for interface in interfaces
        if not interface.is_link_local if not interface.is_loopback
        if not interface.is_multicast
    )


def _get_neighbors(device):
    lldp_neighbors = device.get_lldp_neighbors()
    neighbors = set()
    for interface, neighbor_entries in lldp_neighbors.items():
        for entry in neighbor_entries:
            neighbors.add(entry['hostname'])
    return neighbors
