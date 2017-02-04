from ipaddress import ip_interface, ip_network
import logging

import arrow
from sqlalchemy import engine_from_config
from sqlalchemy import (
    Boolean, Column, DateTime, ForeignKey, ForeignKeyConstraint, String
)
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import (
    configure_mappers, joinedload, relationship, sessionmaker
)
from sqlalchemy.schema import MetaData
import zope.sqlalchemy

from .util import intersect_network_sets, to_ip_network

# Recommended naming convention used by Alembic, as various different database
# providers will autogenerate vastly different names making migrations more
# difficult. See: http://alembic.readthedocs.org/en/latest/naming.html
NAMING_CONVENTION = {
    "ix": 'ix_%(column_0_label)s',
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s"
}


_logger = logging.getLogger(__name__)

metadata = MetaData(naming_convention=NAMING_CONVENTION)
Persistable = declarative_base(metadata=metadata)


def includeme(config):
    config.include('pyramid_tm')
    settings = config.get_settings()
    session_factory = get_session_factory(get_engine(settings))
    config.registry['dbsession_factory'] = session_factory
    # make request.dbsession available for use in Pyramid
    config.add_request_method(
        # r.tm is the transaction manager used by pyramid_tm
        lambda r: get_tm_session(session_factory, r.tm),
        'dbsession',
        reify=True
    )


class User(Persistable):
    __tablename__ = 'users'
    name = Column(String(32), primary_key=True)
    type = Column(String(16), nullable=False)

    scans = relationship('Scan', backref='user')

    __mapper_args__ = {
        'polymorphic_identity': 'user',
        'polymorphic_on': 'type'
    }


class LocalUser(User):
    __tablename__ = 'local_users'
    name = Column(
        String(32),
        ForeignKey('users.name', onupdate='cascade'),
        primary_key=True)
    email = Column(String, unique=True, nullable=False)
    role = Column(String, nullable=False)
    activated = Column(Boolean, nullable=False, default=True)
    hash = Column(String(106), nullable=False)
    password_modified = Column(DateTime(timezone=True), nullable=False)

    __mapper_args__ = {'polymorphic_identity': 'local'}


class RemoteUser(User):
    __tablename__ = 'remote_users'
    name = Column(
        String(32),
        ForeignKey('users.name', onupdate='cascade'),
        primary_key=True)
    role = Column(String, nullable=False)

    __mapper_args__ = {'polymorphic_identity': 'remote'}


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


# Maps to a form submission that could potentially run multiple scans on
# multiple scanners
class Scan(Persistable):
    """Top-level construct for a user-submitted network scan task."""

    __tablename__ = 'scans'
    created_at = Column(DateTime(timezone=True), primary_key=True)
    user_name = Column(String, ForeignKey('users.name'), nullable=False)
    parameters = Column(String, nullable=False)
    type = Column(String, nullable=False)

    targets = relationship('ScanTarget', backref='scan')
    subscans = relationship('Subscan', backref='scan')

    __mapper_args__ = {
        'polymorphic_identity': 'scan',
        'polymorphic_on': 'type'
    }


class SplittingScan(Scan):
    __tablename__ = 'splitting_scans'
    created_at = Column(
        DateTime(timezone=True), ForeignKey('scans.created_at'),
        primary_key=True)

    __mapper_args__ = {'polymorphic_identity': 'splitting'}

    @classmethod
    def create(cls, session, user, parameters, targets):
        if not targets:
            raise ValueError('Must specify at least one scanning target.')
        created_at = arrow.now().datetime
        scan = cls(created_at=created_at, user=user, parameters=parameters)
        scan.targets.extend(ScanTarget.from_fields(targets))
        scanners = session.query(Scanner).options(joinedload('subnets'))
        scan_targets = {
            ip_network(target.net_block) for target in scan.targets
        }

        scanners_and_matching_targets = {
            scanner: scanner.intersect_scan_targets(scan_targets)
            for scanner in scanners
        }

        if not any(scanners_and_matching_targets.values()):
            raise Exception('No scanners have matching subnets assigned.')

        scan.subscans += [
            Subscan.create(scanner, matched_targets)
            for scanner, matched_targets
            in scanners_and_matching_targets.items()
            if matched_targets
        ]
        return scan


class DeltaScan(Scan):
    __tablename__ = 'delta_scans'
    created_at = Column(
        DateTime(timezone=True), ForeignKey('scans.created_at'),
        primary_key=True)

    __mapper_args__ = {'polymorphic_identity': 'delta'}

    @classmethod
    def create(cls, session, user, parameters, scanner_names, targets):
        if not targets:
            raise ValueError('Must specify at least one scanning target.')
        created_at = arrow.now().datetime
        scan = cls(created_at=created_at, user=user, parameters=parameters)
        scan.targets.extend(ScanTarget.from_fields(targets))
        scannable_subnets = {
            ip_network(subnet) for subnet,
            in session.query(ScannerSubnet.subnet)
        }
        scan_targets = {
            ip_network(target.net_block) for target in scan.targets
        }
        subscan_targets = intersect_network_sets(
            scan_targets, scannable_subnets)

        scanner_a = session.query(Scanner).get(scanner_names[0])
        scanner_b = session.query(Scanner).get(scanner_names[1])

        scan.subscans += [
            Subscan.create(scanner_a, subscan_targets),
            Subscan.create(scanner_b, subscan_targets),
        ]
        return scan


class ScanTarget(Persistable):
    """Scan task targets as initially specified."""

    __tablename__ = 'scan_targets'
    scan_created_at = Column(
        DateTime(timezone=True), ForeignKey('scans.created_at'),
        primary_key=True)
    net_block = Column(postgresql.INET, primary_key=True)
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
    scan_created_at = Column(
        DateTime(timezone=True), ForeignKey('scans.created_at'),
        primary_key=True)
    scanner_name = Column(
        String(64), ForeignKey('scanners.name'), primary_key=True)
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


class SubscanTarget(Persistable):
    """A target of a scan subtask, after pruning to scanner's subnets."""

    __tablename__ = 'subscan_targets'
    scan_created_at = Column(DateTime(timezone=True), primary_key=True)
    scanner_name = Column(String(64), primary_key=True)
    target = Column(postgresql.INET, primary_key=True)

    __table_args__ = (
        ForeignKeyConstraint(
            ('scan_created_at', 'scanner_name'),
            ('subscans.scan_created_at', 'subscans.scanner_name'),
        ),
    )


def get_engine(settings, prefix='sqlalchemy.'):
    _logger.info('Initializing Engine')
    engine = engine_from_config(settings, prefix)
    _logger.info('Established {!r}'.format(engine))
    return engine


def get_session_factory(connectable):
    factory = sessionmaker()
    factory.configure(bind=connectable)
    return factory


def get_tm_session(session_factory, transaction_manager):
    """
    Get a ``sqlalchemy.orm.Session`` instance backed by a transaction.

    This function will hook the session to the transaction manager which
    will take care of committing any changes.

    - When using pyramid_tm it will automatically be committed or aborted
      depending on whether an exception is raised.

    - When using scripts you should wrap the session in a manager yourself.
      For example::

          import transaction

          engine = get_engine(settings)
          session_factory = get_session_factory(engine)
          with transaction.manager:
              dbsession = get_tm_session(session_factory, transaction.manager)

    """
    dbsession = session_factory()
    zope.sqlalchemy.register(
        dbsession, transaction_manager=transaction_manager)
    return dbsession


# run configure_mappers after defining all of the models to ensure
# all relationships can be setup
configure_mappers()
