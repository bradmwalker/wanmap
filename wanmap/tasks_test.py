from unittest.mock import Mock, patch

import pytest
from sqlalchemy.orm import Session

from .scanners import Scanner
from .scans import PING_SWEEP
from .splittingscan import SplittingScan
from .tasks import Background, PersistenceTask
from . import tasks


def test_persistence_task_passes_initialized_dbsession(
    session_factory, celery_app):

    @celery_app.task(base=PersistenceTask, bind=True)
    def db_task(self, spy):
        spy(self.dbsession)

    celery_app.dbsession_factory = session_factory

    spy = Mock()
    db_task(spy)
    assert isinstance(spy.call_args[0][0], Session)


def test_persistence_task_commits_on_unit_of_work_success(
    dbsession, celery_app):

    @celery_app.task(base=PersistenceTask, bind=True)
    def db_task(self):
        scanner = Scanner.create('scanner1', '10.1.0.254/24')
        self.dbsession.add(scanner)

    celery_app.dbsession_factory = lambda: dbsession

    with patch.object(dbsession.transaction, 'commit') as commit:
        db_task()
    assert commit.called


def test_persistence_task_doesnt_commit_work_on_error(
    dbsession, celery_app):

    @celery_app.task(base=PersistenceTask, bind=True)
    def db_task(self):
        scanner = Scanner.create('scanner1', '10.1.0.254/24')
        self.dbsession.add(scanner)
        raise Exception

    celery_app.dbsession_factory = lambda: dbsession

    with patch.object(dbsession.transaction, 'commit') as commit,\
        pytest.raises(Exception):
        db_task()
    assert not commit.called


def test_persistence_task_on_error_doesnt_close_session_without_work(
    dbsession, celery_app):

    @celery_app.task(base=PersistenceTask, bind=True)
    def db_task(self):
        raise Exception

    celery_app.dbsession_factory = lambda: dbsession

    with patch.object(dbsession, 'close') as close,\
        pytest.raises(Exception):
        db_task()
    assert not close.called


def test_persistence_task_on_error_closes_session_with_work(
    dbsession, celery_app):

    @celery_app.task(base=PersistenceTask, bind=True)
    def db_task(self):
        scanner = Scanner.create('scanner1', '10.1.0.254/24')
        self.dbsession.add(scanner)
        raise Exception

    celery_app.dbsession_factory = lambda: dbsession

    with patch.object(dbsession, 'close') as close,\
        pytest.raises(Exception):
        db_task()
    assert close.called


def test_scan_workflow_dispatches_each_subscan(dbsession, fake_wan_scanners):

    Background.dbsession_factory = lambda: dbsession

    scan = SplittingScan.create(
        session=dbsession, parameters=PING_SWEEP,
        targets=('10.0.0.0/8',))
    dbsession.add(scan)
    dbsession.flush()
    subscan_count = len(scan.subscans)
    with patch('wanmap.tasks.exec_nmap_scan.apply_async') as exec_nmap_scan_spy:
        tasks.scan_workflow(scan.id)
    assert exec_nmap_scan_spy.called_count == subscan_count
