import ipaddress
import logging

import arrow
from sqlalchemy import engine_from_config
from sqlalchemy import (
    Boolean, Column, DateTime, ForeignKey, ForeignKeyConstraint, String
)
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, scoped_session, sessionmaker
import zope.sqlalchemy

_logger = logging.getLogger(__name__)

DBSession = scoped_session(sessionmaker())  # No ZopeTransactionExtension?
Persistable = declarative_base()
Engine = None


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
    name = Column(String(32), ForeignKey('users.name'), primary_key=True)
    email = Column(String, unique=True, nullable=False)
    role = Column(String, nullable=False)
    activated = Column(Boolean, nullable=False, default=True)
    hash = Column(String(106), nullable=False)
    password_modified = Column(DateTime(timezone=True), nullable=False)

    __mapper_args__ = {'polymorphic_identity': 'local'}


class RemoteUser(User):
    __tablename__ = 'remote_users'
    name = Column(String(32), ForeignKey('users.name'), primary_key=True)
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
        subnet = str(ipaddress.ip_interface(interface_address).network)
        scanner.subnets = [ScannerSubnet(scanner_name=name, subnet=subnet)]
        return scanner


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

    @classmethod
    def create_split(cls, session, user, parameters, targets):
        created_at = arrow.now().datetime
        if not targets:
            raise ValueError('Must specify at least one scanning target.')
        scan = cls(
            created_at=created_at, user=user, parameters=parameters,
            type='split')
        scan.targets = [
            ScanTarget(scan=scan, target=target) for target in targets
        ]
        session.add(scan)
        scan.subscans = scan._split_subscans(session)
        return scan

    def _split_subscans(self, session):
        matches = (
            session.query(
                Scanner, ScannerSubnet.subnet, ScanTarget.target).
            join(ScannerSubnet).
            join(
                ScanTarget,
                ScannerSubnet.subnet.op('<<=')(ScanTarget.target) |
                ScannerSubnet.subnet.op('>>=')(ScanTarget.target)).
            filter(ScanTarget.scan_created_at == self.created_at).
            order_by(ScannerSubnet.scanner_name).
            all())

        from collections import defaultdict
        scanners_targets = defaultdict(set)
        for scanner, subnet, target in matches:
            subnet = ipaddress.ip_network(subnet)
            target = ipaddress.ip_network(target)
            net_intersection = (
                subnet if subnet.prefixlen >= target.prefixlen else target)
            scanners_targets[scanner].add(str(net_intersection))

        subscans = [
            Subscan.create(self, scanner, targets)
            for scanner, targets in scanners_targets.items()
        ]
        return subscans

    @classmethod
    def create_delta(cls, session, user, parameters, scanner_names, targets):
        created_at = arrow.now().datetime
        if not targets:
            raise ValueError('Must specify at least one scanning target.')
        scan = cls(
            created_at=created_at, user=user, parameters=parameters,
            type='delta')
        scan.targets = [
            ScanTarget(scan=scan, target=target) for target in targets
        ]
        session.add(scan)
        scan.subscans = scan._create_delta_subscans(session, scanner_names)
        return scan

    def _create_delta_subscans(self, session, scanner_names):
        matches = (
            session.query(ScannerSubnet.subnet, ScanTarget.target).
            join(
                ScanTarget,
                ScannerSubnet.subnet.op('<<=')(ScanTarget.target) |
                ScannerSubnet.subnet.op('>>=')(ScanTarget.target)).
            filter(ScanTarget.scan_created_at == self.created_at).
            order_by(ScannerSubnet.scanner_name).
            all())

        scanner_a = session.query(Scanner).get(scanner_names[0])
        scanner_b = session.query(Scanner).get(scanner_names[1])

        targets = set()
        for subnet, target in matches:
            subnet = ipaddress.ip_network(subnet)
            target = ipaddress.ip_network(target)
            net_intersection = (
                subnet if subnet.prefixlen >= target.prefixlen else target)
            targets.add(str(net_intersection))

        subscans = [
            Subscan.create(self, scanner_a, targets),
            Subscan.create(self, scanner_b, targets),
        ]
        return subscans


class ScanTarget(Persistable):
    """Scan task targets as initially specified."""

    __tablename__ = 'scan_targets'
    scan_created_at = Column(
        DateTime(timezone=True), ForeignKey('scans.created_at'),
        primary_key=True)
    target = Column(postgresql.INET, primary_key=True)
    # Maps to multiple targets of one nmap instance


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
    def create(cls, scan, scanner, targets):
        subscan = cls(scan=scan, scanner=scanner)
        subscan.targets = [
            SubscanTarget(subscan=subscan, target=target) for target in targets
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


def init_engine(settings, keep_session=False):
    global Engine
    if not Engine:
        _logger.info('Initializing Engine')
        Engine = engine_from_config(settings, 'sqlalchemy.')
        _logger.info('Keep Session: {}'.format(keep_session))
        zope.sqlalchemy.register(DBSession, keep_session=keep_session)
        DBSession.configure(bind=Engine)
        Persistable.metadata.bind = Engine
        _logger.info('Established {!r}'.format(Engine))
        return Engine
