"""Deterministic, synthetic retention tests; no live sources or patient data."""
from datetime import timedelta
from types import SimpleNamespace
import threading

from cryptography.fernet import Fernet
import pytest
from sqlalchemy import func, select


@pytest.fixture
def catalogue(tmp_path, monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("DATABASE_URL", "sqlite:///" + str(tmp_path / "catalogue.db"))
    monkeypatch.setenv("APP_SECRET_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("SESSION_SECRET", "synthetic-retention-session-" * 3)
    monkeypatch.setenv("DETECTOR_MODE", "rules")
    monkeypatch.setenv("SECURE_COOKIES", "false")
    monkeypatch.setenv("SOURCE_ALLOWED_ROOTS", '["' + str(tmp_path) + '"]')
    from app import models as m, worker
    from app.config import settings
    from app.db import engine, initialize, session
    from app.security import cipher, encrypt
    settings.cache_clear()
    engine.cache_clear()
    cipher.cache_clear()
    worker.STOP.clear()
    worker._ACTIVE_SCANS.clear()
    clock = SimpleNamespace(at=m.now())
    monkeypatch.setattr(m, "now", lambda: clock.at)
    initialize()
    with session() as db:
        db.add(m.Policy(id=1, retention_days=1, audit_retention_days=7, retention_approved=True))
        source = m.Source(name_encrypted=encrypt("Synthetic retention fixture"), kind="filesystem",
                          config_encrypted=encrypt({"root": str(tmp_path)}), safety_validated=True)
        db.add(source)
        db.commit()
        source_id = source.id

    def add_scan(status="queued", age=timedelta(), heartbeat=None, content=False):
        with session() as db:
            scan = m.Scan(source_id=source_id, status=status, created_at=clock.at - age,
                          heartbeat_at=heartbeat, options={"capture_evidence": True})
            db.add(scan)
            db.flush()
            if content:
                obj = m.ScanObject(scan_id=scan.id, object_key=scan.id, location_encrypted=encrypt("synthetic.txt"),
                                   status="full", examined=1, unit="bytes", metadata_encrypted=encrypt({}))
                db.add(obj)
                db.flush()
                finding = m.Finding(scan_id=scan.id, object_id=obj.id, entity_type="EMAIL_ADDRESS",
                                    classification="personal_data", confidence=.9, match_count=1,
                                    reason_encrypted=encrypt("synthetic detection"), segment_encrypted=encrypt("document"))
                db.add(finding)
                db.flush()
                db.add(m.FindingEvidence(finding_id=finding.id, payload_encrypted=encrypt({"examples": [{"value": "fixture@example.invalid"}]})))
            db.commit()
            return scan.id

    def counts():
        with session() as db:
            return tuple(db.scalar(select(func.count()).select_from(model))
                         for model in (m.ScanObject, m.Finding, m.FindingEvidence))

    yield SimpleNamespace(clock=clock, add_scan=add_scan, counts=counts, source_id=source_id,
                          m=m, worker=worker, session=session, encrypt=encrypt)
    assert not worker._ACTIVE_SCANS
    worker.STOP.clear()
    engine().dispose()
    engine.cache_clear()
    cipher.cache_clear()
    settings.cache_clear()


@pytest.mark.parametrize("status", ["completed", "cancelled", "failed", "interrupted", "queued", "paused"])
def test_expired_idle_scans_purge_at_exact_deadline_and_cascade_evidence(catalogue, status):
    c = catalogue
    expired = c.add_scan(status, timedelta(days=1), content=True)
    fresh = c.add_scan("completed", timedelta(hours=23), content=True)
    c.worker.purge_expired()
    with c.session() as db:
        assert db.get(c.m.Scan, expired) is None
        assert db.get(c.m.Scan, fresh) is not None
        assert db.get(c.m.Source, c.source_id) is not None
    assert c.counts() == (1, 1, 1)


@pytest.mark.parametrize("status", ["running", "paused"])
def test_expired_owned_scan_keeps_only_cancellation_marker(catalogue, status):
    c = catalogue
    scan_id = c.add_scan(status, timedelta(days=1), heartbeat=c.clock.at, content=True)
    c.worker.purge_expired()
    with c.session() as db:
        scan = db.get(c.m.Scan, scan_id)
        assert scan.status == "cancelled"
        assert scan.error == c.worker.RETENTION_EXPIRED
        assert scan.coverage == {}
    assert c.counts() == (0, 0, 0)
    # A stopped owner can release its marker on restart without source access.
    with c.session() as db:
        db.get(c.m.Scan, scan_id).heartbeat_at = None
        db.commit()
    c.worker.purge_expired()
    with c.session() as db:
        assert db.get(c.m.Scan, scan_id) is None


def synthetic_item(location="synthetic.txt"):
    from app.scanning import _object
    value = "fixture@example.invalid"
    return _object(location, "full", examined=len(value), findings=[{
        "entity_type": "EMAIL_ADDRESS", "classification": "personal_data", "confidence": .9,
        "match_count": 1, "reason": "synthetic detection", "segment": "document",
        "evidence": [{"value": value, "excerpt": value, "start": 0, "end": len(value), "segment": "document"}],
    }])


@pytest.mark.parametrize("paused", [False, True])
def test_housekeeping_expires_blocked_or_paused_scan_without_waiting_for_source(catalogue, monkeypatch, paused):
    c = catalogue
    scan_id = c.add_scan()
    holding, release, purged = threading.Event(), threading.Event(), threading.Event()
    errors = []

    def scanner(kind, config, options, detector, control):
        yield synthetic_item()
        if paused:
            with c.session() as db:
                db.get(c.m.Scan, scan_id).status = "paused"
                db.commit()
        holding.set()
        if paused:
            assert control() == "cancelled"
        else:
            assert release.wait(5)
        yield synthetic_item("late.txt")

    monkeypatch.setattr("app.scanning.scan_source", scanner)
    original_purge = c.worker.purge_expired
    started_at = c.clock.at

    def observed_purge():
        observed_at = c.clock.at
        result = original_purge()
        # Signal only a pass that began after expiry; the test clock can
        # advance while an earlier non-expired pass is still returning.
        if observed_at >= started_at + timedelta(days=1):
            purged.set()
        return result

    monkeypatch.setattr(c.worker, "purge_expired", observed_purge)

    def run():
        try:
            c.worker.run_scan(scan_id)
        except Exception as error:
            errors.append(error)

    with c.worker.retention_housekeeping(interval=.01):
        runner = threading.Thread(target=run)
        runner.start()
        try:
            assert holding.wait(5)
            assert c.counts() == (1, 1, 1)
            c.clock.at += timedelta(days=1)
            assert purged.wait(5)
            assert c.counts() == (0, 0, 0)
            if not paused:
                with c.session() as db:
                    assert db.get(c.m.Scan, scan_id).error == c.worker.RETENTION_EXPIRED
        finally:
            release.set()
            runner.join(5)
    assert not runner.is_alive()
    assert errors == []
    with c.session() as db:
        assert db.get(c.m.Scan, scan_id) is None
    assert c.counts() == (0, 0, 0)


def test_batch_crossing_deadline_is_rolled_back_before_phi_commit(catalogue, monkeypatch):
    c = catalogue
    scan_id = c.add_scan()

    def scanner(*args):
        yield synthetic_item()
        assert c.counts() == (1, 1, 1)
        yield synthetic_item("advance-clock-during-encryption")

    original_encrypt = c.worker.encrypt

    def advancing_encrypt(value):
        if value == "advance-clock-during-encryption":
            c.clock.at += timedelta(days=1)
        return original_encrypt(value)

    monkeypatch.setattr("app.scanning.scan_source", scanner)
    monkeypatch.setattr(c.worker, "encrypt", advancing_encrypt)
    c.worker.run_scan(scan_id)
    assert c.counts() == (0, 0, 0)
    with c.session() as db:
        assert db.get(c.m.Scan, scan_id) is None


def test_shortened_approved_policy_expires_existing_active_scan(catalogue):
    c = catalogue
    with c.session() as db:
        db.get(c.m.Policy, 1).retention_days = 3
        db.commit()
    scan_id = c.add_scan("running", timedelta(days=2), heartbeat=c.clock.at, content=True)
    c.worker.purge_expired()
    assert c.counts() == (1, 1, 1)
    with c.session() as db:
        db.get(c.m.Policy, 1).retention_days = 1
        db.commit()
    c.worker.purge_expired()
    assert c.counts() == (0, 0, 0)
    with c.session() as db:
        assert db.get(c.m.Scan, scan_id).error == c.worker.RETENTION_EXPIRED


def test_unapproved_policy_does_not_delete_data(catalogue):
    c = catalogue
    c.add_scan("completed", timedelta(days=2), content=True)
    with c.session() as db:
        db.get(c.m.Policy, 1).retention_approved = False
        db.commit()
    assert c.worker.purge_expired() is False
    assert c.counts() == (1, 1, 1)


def test_purge_is_bounded_and_reports_backlog(catalogue, monkeypatch):
    c = catalogue
    monkeypatch.setattr(c.worker, "RETENTION_BATCH_SIZE", 2)
    for _ in range(3):
        c.add_scan("completed", timedelta(days=2), content=True)
    assert c.worker.purge_expired() is True
    assert c.counts() == (1, 1, 1)
    assert c.worker.purge_expired() is False
    assert c.counts() == (0, 0, 0)


def test_housekeeping_exception_fails_closed_without_leaking_lock(catalogue, monkeypatch):
    c = catalogue
    calls = []

    def failing_purge():
        calls.append(1)
        if len(calls) == 1:
            return False
        with c.worker._CATALOG_WRITE_LOCK:
            raise RuntimeError("synthetic catalogue failure")

    monkeypatch.setattr(c.worker, "purge_expired", failing_purge)
    with c.worker.retention_housekeeping(interval=.01):
        assert c.worker.STOP.wait(2)
    assert c.worker._CATALOG_WRITE_LOCK.acquire(blocking=False)
    c.worker._CATALOG_WRITE_LOCK.release()
    assert not any(t.name == "retention-housekeeping" for t in threading.enumerate())


def test_database_lock_defers_worker_without_erasing_prior_content(catalogue, monkeypatch):
    c = catalogue
    from app.source_locks import source_database_lock
    config = {"host": "db.hospital.internal", "port": 3306, "database": "synthetic",
              "schema": "synthetic", "username": "scan_reader", "password": "synthetic-only"}
    with c.session() as db:
        source = db.get(c.m.Source, c.source_id)
        source.kind = "mysql"
        source.config_encrypted = c.encrypt(config)
        db.commit()
    scan_id = c.add_scan(content=True)
    operations = []

    def normalized(kind, candidate):
        operations.append("normalize")
        return dict(candidate)

    def detector(**kwargs):
        operations.append("detector")
        return SimpleNamespace(version="synthetic-lock-detector")

    def scanner(*args):
        operations.append("scan")
        yield synthetic_item("after-lock.txt")

    monkeypatch.setattr(c.worker, "normalize_config", normalized)
    monkeypatch.setattr("app.detection.Detector", detector)
    monkeypatch.setattr("app.scanning.scan_source", scanner)
    # Different user/schema still shares the same physical database resource.
    with source_database_lock("mysql", {**config, "host": "DB.HOSPITAL.INTERNAL", "username": "check_reader", "schema": "other"}):
        c.worker.run_scan(scan_id)
        with c.session() as db:
            assert db.get(c.m.Scan, scan_id).status == "queued"
        assert operations == []
        assert c.counts() == (1, 1, 1)
    c.worker.run_scan(scan_id)
    assert operations == ["normalize", "detector", "scan"]
    with c.session() as db:
        assert db.get(c.m.Scan, scan_id).status == "completed"
    assert c.counts() == (1, 1, 1)
    with source_database_lock("mysql", config):
        pass  # Worker released the resource lock after completion.


def test_database_lock_releases_when_worker_raises(catalogue, monkeypatch):
    c = catalogue
    from app.source_locks import source_database_lock
    config = {"host": "db.hospital.internal", "database": "synthetic"}
    with c.session() as db:
        source = db.get(c.m.Source, c.source_id)
        source.kind = "postgresql"
        source.config_encrypted = c.encrypt(config)
        db.commit()
    scan_id = c.add_scan()

    def failure(_):
        raise RuntimeError("synthetic worker failure")

    monkeypatch.setattr(c.worker, "_run_scan", failure)
    with pytest.raises(RuntimeError, match="synthetic worker failure"):
        c.worker.run_scan(scan_id)
    with source_database_lock("postgresql", config):
        pass
    assert not c.worker._ACTIVE_SCANS
