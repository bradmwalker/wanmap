import logging

import arrow
from sqlalchemy import Column, DateTime, ForeignKey
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import relationship

from .schema import Persistable

logger = logging.getLogger(__name__)


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


class RouterInterface(Persistable):

    __tablename__ = 'router_interfaces'

    router_id = Column(
        postgresql.UUID(as_uuid=True), ForeignKey('routers.id'),
        primary_key=True)
    address = Column(postgresql.INET, primary_key=True)
