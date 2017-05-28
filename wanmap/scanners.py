from ipaddress import ip_interface
import logging

from pyramid.httpexceptions import HTTPNotFound
from pyramid.view import view_config
from sqlalchemy import Column, String
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import relationship

from .schema import Persistable

logger = logging.getLogger(__name__)


def includeme(config):
    config.add_route('show_scanners', '/scanners/')
    config.add_route('show_scanner', '/scanners/{name}/')


class Scanner(Persistable):
    """The distributed scanner celery instances"""

    __tablename__ = 'scanners'
    name = Column(String(64), primary_key=True)
    interface = Column(postgresql.INET, nullable=False)

    subscans = relationship('Subscan', backref='scanner')

    @classmethod
    def create(cls, name, interface_address):
        interface = ip_interface(interface_address)
        scanner = cls(name=name, interface=interface)
        return scanner


@view_config(route_name='show_scanners', renderer='templates/scanners.jinja2')
def show_scanners(request):
    scanners = request.dbsession.query(Scanner).order_by(Scanner.name).all()
    return {'scanners': scanners}


@view_config(
    route_name='show_scanner', request_method='GET',
    renderer='templates/scanner.jinja2')
def show_scanner(request):
    name = request.matchdict['name']
    scanner = request.dbsession.query(Scanner).get(name)
    if not scanner:
        raise HTTPNotFound
    return {'scanner': scanner}
