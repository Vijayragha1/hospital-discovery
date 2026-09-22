"""Synthetic restored catalogs only; no discovery source or network access."""
from datetime import timedelta
import hashlib
import json
import os
from types import SimpleNamespace

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
import pytest
from sqlalchemy import func, select


@pytest.fixture
def restored(tmp_path, monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("DATABASE_URL", "sqlite:///" + str(tmp_path / "restored.db"))
    monkeypatch.setenv("APP_SECRET_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("SESSION_SECRET", "synthetic-original-session-secret-" * 2)
    monkeypatch.setenv("DETECTOR_MODE", "rules")
    monkeypatch.setenv("SECURE_COOKIES", "false")
    monkeypatch.setenv("SOURCE_ALLOWED_ROOTS", json.dumps([str(tmp_path)]))
    from app import models as m, recovery, worker
    from app.config import settings
    from app.db import engine, initialize, session
    from app.security import cipher, encrypt, hash_password, stable_hash
    settings.cache_clear()
    engine.cache_clear()
    cipher.cache_clear()
    worker.STOP.clear()
    clock = SimpleNamespace(at=m.now())
    monkeypatch.setattr(m, "now", lambda: clock.at)
    initialize()
    token = "synthetic-restored-session-token"
    with session() as db:
        db.add(m.Policy(id=1, retention_days=3650, audit_retention_days=3650, retention_approved=False))
        user = m.User(username="synthetic-admin", password_hash=hash_password("synthetic-admin-password"), role="admin")
        source = m.Source(name_encrypted=encrypt("SYNTHETIC_SOURCE_NAME"), kind="filesystem",
            config_encrypted=encrypt({"root": str(tmp_path), "password": "SYNTHETIC_SECRET",
                                      "full_scan_allowed": True, "workload_validation_note": "OLD_APPROVAL"}),
            enabled=True, safety_validated=True)
        db.add_all([user, source])
        db.flush()
        db.add(m.LoginSession(token_hash=stable_hash(token), user_id=user.id, expires_at=clock.at + timedelta(hours=8)))
        db.add(m.Audit(actor="synthetic-reviewer", action="finding_reviewed", detail_encrypted=encrypt({"note": "SYNTHETIC_REVIEW"})))
        db.commit()
        source_id, user_id = source.id, user.id

    def add_scan(status="completed", age=timedelta(), content=True):
        with session() as db:
            scan = m.Scan(source_id=source_id, status=status, created_at=clock.at - age,
                options={"capture_evidence": True}, detector_version="synthetic/runtime-local-" + "a" * 64,
                heartbeat_at=clock.at, finished_at=clock.at if status == "completed" else None, coverage={"full": 1})
            db.add(scan)
            db.flush()
            if content:
                location = "SYNTHETIC_DOCUMENT.txt"
                key = stable_hash(source_id + ":" + hashlib.sha256(location.encode()).hexdigest())
                obj = m.ScanObject(scan_id=scan.id, object_key=key, location_encrypted=encrypt(location), status="full",
                    examined=20, unit="characters", fingerprint=stable_hash("SYNTHETIC_CONTENT"), metadata_encrypted=encrypt({}))
                db.add(obj)
                db.flush()
                finding = m.Finding(scan_id=scan.id, object_id=obj.id, entity_type="EMAIL_ADDRESS", classification="personal_data",
                    confidence=.9, match_count=1, reason_encrypted=encrypt("synthetic_recognizer"), segment_encrypted=encrypt("segment:1"),
                    review_status="confirmed")
                db.add(finding)
                db.flush()
                db.add(m.FindingEvidence(finding_id=finding.id, payload_encrypted=encrypt({"examples": [{
                    "value": "synthetic@example.invalid", "excerpt": "SYNTHETIC_EXCERPT"}], "truncated": False})))
            db.commit()
            return scan.id

    yield SimpleNamespace(m=m, recovery=recovery, worker=worker, session=session, add_scan=add_scan,
                          source_id=source_id, user_id=user_id, token=token, clock=clock, encrypt=encrypt)
    engine().dispose()
    engine.cache_clear()
    cipher.cache_clear()
    settings.cache_clear()
    worker.STOP.clear()


def prepare(c, **overrides):
    return c.recovery.prepare_restored_catalog(**{"retention_days": 1, "audit_retention_days": 7,
        "confirm_isolated_restore": True, **overrides})


def count(db, model):
    return db.scalar(select(func.count()).select_from(model))


def test_restore_quarantines_jobs_sessions_and_approvals_without_changing_surviving_identity(restored):
    c = restored
    from app.comparison import compare_scans
    from app.security import decrypt
    finished = [c.add_scan() for _ in range(2)]
    active = [c.add_scan(status) for status in c.recovery.RESUMABLE_STATUSES]
    secrets_before = (os.environ["APP_SECRET_KEY"], os.environ["SESSION_SECRET"])
    with c.session() as db:
        before = [(row.id, row.object_key, row.fingerprint, row.location_encrypted)
                  for row in db.scalars(select(c.m.ScanObject).order_by(c.m.ScanObject.id))]
        comparison_before = compare_scans(db, *(db.get(c.m.Scan, key) for key in finished))
        evidence_before = [(row.finding_id, row.payload_encrypted) for row in db.scalars(select(c.m.FindingEvidence))]
    result = prepare(c)
    assert result["status"] == "offline_preparation_completed" and result["sessions_revoked"] == 1
    assert result["users_disabled"] == 1 and result["fresh_administrator_required"]
    assert result["scans_quarantined"] == 4 and result["object_identities_verified"] == 6
    with c.session() as db:
        assert count(db, c.m.LoginSession) == 0
        assert not db.get(c.m.User, c.user_id).active
        source = db.get(c.m.Source, c.source_id)
        assert not source.enabled and not source.safety_validated
        config = decrypt(source.config_encrypted)
        assert config["password"] == "SYNTHETIC_SECRET"
        assert "full_scan_allowed" not in config and "workload_validation_note" not in config
        assert all(db.get(c.m.Scan, key).status == "completed" for key in finished)
        for key in active:
            scan = db.get(c.m.Scan, key)
            assert scan.status == "cancelled" and scan.error == c.recovery.RESTORE_QUARANTINE_REASON
            assert scan.heartbeat_at is None and scan.finished_at is not None
        assert before == [(row.id, row.object_key, row.fingerprint, row.location_encrypted)
                          for row in db.scalars(select(c.m.ScanObject).order_by(c.m.ScanObject.id))]
        assert evidence_before == [(row.finding_id, row.payload_encrypted) for row in db.scalars(select(c.m.FindingEvidence))]
        assert all(row.review_status == "confirmed" for row in db.scalars(select(c.m.Finding)))
        assert compare_scans(db, *(db.get(c.m.Scan, key) for key in finished)) == comparison_before
        assert db.scalar(select(c.m.Audit).where(c.m.Audit.action == "finding_reviewed")) is not None
    assert secrets_before == (os.environ["APP_SECRET_KEY"], os.environ["SESSION_SECRET"])
    public = json.dumps(result)
    assert not any(value in public for value in ("SYNTHETIC_SECRET", "SYNTHETIC_EXCERPT", "synthetic@example.invalid", c.token))


def test_restore_drains_expired_backlog_and_cascades_evidence_under_current_supplied_policy(restored, monkeypatch):
    c = restored
    monkeypatch.setattr(c.worker, "RETENTION_BATCH_SIZE", 2)
    expired = [c.add_scan(status, timedelta(days=1)) for status in ("queued", "running", "paused", "interrupted", "completed")]
    fresh = c.add_scan(age=timedelta(hours=23))
    with c.session() as db:
        for _ in range(5):
            db.add(c.m.Audit(at=c.clock.at - timedelta(days=7), actor="synthetic", action="old", detail_encrypted=c.encrypt({})))
        db.commit()
    result = prepare(c)
    assert result["retention_passes"] >= 3 and result["remaining_expired_records"] == 0
    with c.session() as db:
        assert all(db.get(c.m.Scan, key) is None for key in expired)
        assert db.get(c.m.Scan, fresh) is not None
        assert tuple(count(db, model) for model in (c.m.ScanObject, c.m.Finding, c.m.FindingEvidence)) == (1, 1, 1)
        assert not db.scalar(select(c.m.Audit).where(c.m.Audit.action == "old"))
        policy = db.get(c.m.Policy, 1)
        assert (policy.retention_days, policy.audit_retention_days, policy.retention_approved) == (1, 7, True)


def test_preparation_is_repeatable_and_resumption_requires_a_new_scan(restored, monkeypatch, capsys):
    c = restored
    key = c.add_scan("paused")
    prepare(c)
    second = prepare(c)
    assert second["sessions_revoked"] == second["scans_quarantined"] == 0
    # The existing bootstrap flow requires a fresh username; it cannot quietly
    # reactivate the restored old account or its password/role snapshot.
    from app.cli import main
    monkeypatch.setattr("getpass.getpass", lambda _: "fresh-synthetic-password")
    monkeypatch.setattr("sys.argv", ["app.cli", "init-admin", "--username", "fresh-recovery-admin"])
    main()
    capsys.readouterr()
    from app.main import app, attempts
    attempts.clear()
    # API starts only after both offline preparation calls have completed.
    with TestClient(app, headers={"X-Requested-With": "SentryDiscovery"}) as client:
        client.cookies.set("sentry_session", c.token)
        assert client.get("/api/auth/me").status_code == 401
        client.cookies.clear()
        assert client.post("/api/auth/login", json={"username": "synthetic-admin", "password": "synthetic-admin-password"}).status_code == 401
        assert client.post("/api/auth/login", json={"username": "fresh-recovery-admin", "password": "fresh-synthetic-password"}).status_code == 200
        assert client.post(f"/api/scans/{key}/resume").status_code == 409
        assert client.post("/api/scans", json={"source_id": c.source_id}).status_code == 409
        # Merely re-enabling the source does not restore safety approval.
        assert client.patch(f"/api/sources/{c.source_id}", json={"enabled": True}).status_code == 200
        assert client.post("/api/scans", json={"source_id": c.source_id}).status_code == 409


@pytest.mark.parametrize("override", [{"retention_days": 0}, {"audit_retention_days": 3651},
    {"retention_days": True}, {"audit_retention_days": "7"}, {"confirm_isolated_restore": False}])
def test_bad_approval_arguments_do_not_modify_restore(restored, override):
    c = restored
    key = c.add_scan("queued")
    with pytest.raises(c.recovery.RecoveryPreparationError):
        prepare(c, **override)
    with c.session() as db:
        assert db.get(c.m.Scan, key).status == "queued"
        assert count(db, c.m.LoginSession) == 1
        assert db.get(c.m.User, c.user_id).active
        assert db.get(c.m.Source, c.source_id).enabled
        assert not db.get(c.m.Policy, 1).retention_approved


@pytest.mark.parametrize("failure", ["encryption_key", "session_key", "corrupt_evidence", "corrupt_audit"])
def test_wrong_key_or_corrupt_encrypted_data_cannot_produce_success_or_partial_quarantine(restored, monkeypatch, failure):
    c = restored
    c.add_scan()
    from app.config import settings
    from app.security import cipher
    if failure in {"encryption_key", "session_key"}:
        monkeypatch.setenv("APP_SECRET_KEY" if failure == "encryption_key" else "SESSION_SECRET",
                           Fernet.generate_key().decode() if failure == "encryption_key" else "different-session-secret-" * 3)
        settings.cache_clear()
        cipher.cache_clear()
    else:
        with c.session() as db:
            if failure == "corrupt_evidence":
                db.scalar(select(c.m.FindingEvidence)).payload_encrypted = "SENSITIVE_CORRUPT_CIPHERTEXT"
            else:
                db.scalar(select(c.m.Audit)).detail_encrypted = "SENSITIVE_CORRUPT_CIPHERTEXT"
            db.commit()
    with pytest.raises(c.recovery.RecoveryPreparationError) as error:
        prepare(c)
    assert str(error.value) in {"catalog_preparation_failed", "catalog_identity_key_mismatch"}
    with c.session() as db:
        assert count(db, c.m.LoginSession) == 1
        assert db.get(c.m.User, c.user_id).active
        assert db.get(c.m.Source, c.source_id).enabled
        assert not db.get(c.m.Policy, 1).retention_approved


@pytest.mark.parametrize("failure", ["exception", "no_progress"])
def test_failed_retention_leaves_quarantine_committed_and_never_reports_ready(restored, monkeypatch, failure):
    c = restored
    key = c.add_scan("queued", timedelta(days=2))
    def broken_purge():
        if failure == "exception":
            raise RuntimeError("SENSITIVE_DRIVER_DETAIL")
        return False
    monkeypatch.setattr(c.recovery, "purge_expired", broken_purge)
    with pytest.raises(c.recovery.RecoveryPreparationError) as error:
        prepare(c)
    assert "SENSITIVE" not in str(error.value)
    with c.session() as db:
        assert count(db, c.m.LoginSession) == 0
        assert not db.get(c.m.User, c.user_id).active
        source = db.get(c.m.Source, c.source_id)
        assert not source.enabled and not source.safety_validated
        assert db.get(c.m.Scan, key).status == "cancelled"
        assert not db.scalar(select(c.m.Audit).where(c.m.Audit.action == "restored_catalog_prepared"))


def test_active_worker_lock_prevents_restore_mutation(restored):
    c = restored
    with c.worker.exclusive_worker():
        with pytest.raises(c.recovery.RecoveryPreparationError):
            prepare(c)
    with c.session() as db:
        assert count(db, c.m.LoginSession) == 1
        assert db.get(c.m.Source, c.source_id).enabled


def test_preparation_never_contacts_or_validates_a_discovery_source(restored, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Discovery source access is forbidden during restore preparation")
    monkeypatch.setattr("app.sources.normalize_config", forbidden)
    monkeypatch.setattr("app.sources.test_connection", forbidden)
    monkeypatch.setattr("app.scanning.scan_source", forbidden)
    assert prepare(restored)["status"] == "offline_preparation_completed"


def test_missing_schema_is_rejected_without_bootstrap_or_migration(restored):
    c = restored
    from app.db import engine
    from sqlalchemy import inspect
    c.m.FindingEvidence.__table__.drop(engine())
    with pytest.raises(c.recovery.RecoveryPreparationError, match="matching_catalog_schema_required"):
        prepare(c)
    assert "finding_evidence" not in inspect(engine()).get_table_names()
    with c.session() as db:
        assert count(db, c.m.LoginSession) == 1
        assert db.get(c.m.Source, c.source_id).enabled


def test_unknown_legacy_scan_state_is_not_silently_treated_as_terminal(restored):
    c = restored
    c.add_scan("unknown_legacy_state")
    with pytest.raises(c.recovery.RecoveryPreparationError, match="unsupported_scan_state"):
        prepare(c)
    with c.session() as db:
        assert count(db, c.m.LoginSession) == 1
        assert db.get(c.m.Source, c.source_id).enabled


def test_cli_requires_restore_acknowledgement_and_prints_only_summary(restored, monkeypatch, capsys):
    c = restored
    from app.cli import main
    command = ["app.cli", "prepare-restored-catalog", "--retention-days", "1", "--audit-retention-days", "7"]
    monkeypatch.setattr("sys.argv", command)
    with pytest.raises(SystemExit) as error:
        main()
    assert error.value.code == 2
    assert "--confirm-isolated-restore" in capsys.readouterr().err
    monkeypatch.setattr("sys.argv", command + ["--confirm-isolated-restore"])
    main()
    output = capsys.readouterr()
    summary = json.loads(output.out)
    assert summary["status"] == "offline_preparation_completed"
    assert summary["session_secret_verification"] == "not_verifiable_no_stored_objects"
    assert summary["object_identity_key_verified"] is False
    assert not output.err


def test_cli_failure_is_sanitized_and_nonzero(restored, monkeypatch, capsys):
    from app.cli import main
    monkeypatch.setattr("sys.argv", ["app.cli", "prepare-restored-catalog", "--retention-days", "0",
        "--audit-retention-days", "7", "--confirm-isolated-restore"])
    with pytest.raises(SystemExit) as error:
        main()
    assert error.value.code == 1
    output = capsys.readouterr()
    assert not output.out and "Keep API, worker and ingress stopped" in output.err
