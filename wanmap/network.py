from collections import deque
from ipaddress import ip_address, ip_interface
import logging
import re
from uuid import UUID

import arrow
import colander
from deform import Form, ValidationFailure
from deform.widget import PasswordWidget
import paramiko
from pyramid.httpexceptions import HTTPFound
from pyramid.view import view_config
from sqlalchemy import Column, DateTime, ForeignKey
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import joinedload, relationship
import transaction

from .schema import Persistable
from .util import intersect_network_sets, opposite_address

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

    # TODO: Determine a better key.
    id = Column(postgresql.UUID(as_uuid=True), primary_key=True)
    last_collected_at = Column(DateTime(timezone=True), nullable=False)

    _interfaces = relationship(
        'RouterInterface', cascade='all, delete-orphan', backref='router')

    @classmethod
    def create(cls, id_, interfaces):
        interfaces = [
            RouterInterface(address=interface) for interface in interfaces
        ]
        return cls(
            id=id_,
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

    router_id = Column(
        postgresql.UUID(as_uuid=True), ForeignKey('routers.id'),
        primary_key=True)
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


def discover_network(seed_router_address, credentials):
    """Traverses the network using BFS and collects router information."""

    to_visit = deque((seed_router_address,))
    routers = []
    known_addresses = set()
    while to_visit:
        visiting = to_visit.popleft()
        if visiting in known_addresses:
            continue
        router = get_router(visiting, credentials)
        if router:
            routers.append(router)
            known_addresses |= {
                interface.ip for interface in router.interfaces
            }
            to_visit.extend(neighbor_addresses(router.interfaces))
    return routers


def get_router(router_address, credentials):
    """Visits the router and retrieves its UUID and interfaces."""

    with paramiko.SSHClient() as ssh:
        logger.info('Collecting router information at %s', router_address)
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(
                str(router_address),
                username=credentials[0], password=credentials[1])
        except paramiko.ssh_exception.NoValidConnectionsError:
            return None
        else:
            router = Router.create(
                id_=_get_router_id(ssh),
                interfaces=_get_router_interfaces(ssh))
            logger.info(
                'Collected router %s with %d interfaces.',
                router.id, len(router.interfaces))
            return router


def _get_router_id(ssh):
    _, stdout, _ = ssh.exec_command('/usr/bin/cat /etc/ssh/uuid')
    output = stdout.read().decode()
    return UUID(output.strip())


def _get_router_interfaces(ssh):
    interfaces_output = _get_interfaces_output(ssh)
    return _parse_interfaces(interfaces_output)


def _get_interfaces_output(ssh):
    _, stdout, _ = ssh.exec_command('/usr/sbin/ip -o -f inet address')
    return stdout.read().decode()


def _parse_interfaces(interfaces_output):
    interface_regex = re.compile(r'inet ([.\d/]+) ')
    captured_interfaces = (
        match.group(1) for match in interface_regex.finditer(interfaces_output)
    )
    interfaces = map(ip_interface, captured_interfaces)
    return frozenset(
        interface for interface in interfaces
        if not interface.is_link_local if not interface.is_loopback
        if not interface.is_multicast
    )


def neighbor_addresses(interfaces):
    glue_net_interfaces = {
        interface for interface in interfaces
        if interface.network.prefixlen == 30    # TODO: Handle /31, /32
    }
    return frozenset(map(opposite_address, glue_net_interfaces))
