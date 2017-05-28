from ipaddress import ip_interface
import logging

from pyramid.view import view_config
from sqlalchemy import Column, String
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import relationship

from .schema import Persistable

logger = logging.getLogger(__name__)


def includeme(config):
    config.add_route('show_scanners', '/scanners/')


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
