import pytest

from .scans import DeltaScan, PING_SWEEP


def test_create_delta_scan(dbsession, fake_wan_scanners, fake_wan_routers):
    scanner_a, scanner_b, *_ = (scanner.name for scanner in fake_wan_scanners)
    scan = DeltaScan.create(
        session=dbsession, parameters=PING_SWEEP,
        scanner_names=(scanner_a, scanner_b,), targets=('10.1.0.1',))
    subscan_targets = {
        target.target
        for subscan in scan.subscans
        for target in subscan.targets
    }
    assert subscan_targets == {'10.1.0.1/32'}


def test_delta_subscan_task_ids_initially_null(dbsession, fake_wan_scanners):
    scanner_a, scanner_b, *_ = (scanner.name for scanner in fake_wan_scanners)
    scan = DeltaScan.create(
        session=dbsession, parameters=PING_SWEEP,
        scanner_names=(scanner_a, scanner_b,), targets=('10.1.0.1',))
    assert not any(subscan.celery_task_id for subscan in scan.subscans)


def test_create_delta_scan_errors_on_no_targets(dbsession, fake_wan_scanners):
    scanner_names = tuple(scanner.name for scanner in fake_wan_scanners)
    with pytest.raises(ValueError):
        DeltaScan.create(
            session=dbsession, parameters=PING_SWEEP,
            scanner_names=scanner_names, targets=())
