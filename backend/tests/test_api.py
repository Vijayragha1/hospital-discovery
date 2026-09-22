import json
from datetime import timedelta

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import select


@pytest.fixture
def system(tmp_path, monkeypatch):
    root = tmp_path / "source"
    root.mkdir()
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("DATABASE_URL", "sqlite:///" + str(tmp_path / "catalog.db"))
    monkeypatch.setenv("APP_SECRET_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("SESSION_SECRET", "test-only-session-secret-" * 3)
    monkeypatch.setenv("DETECTOR_MODE", "rules")
    monkeypatch.setenv("SECURE_COOKIES", "false")
    monkeypatch.setenv("SOURCE_ALLOWED_ROOTS", json.dumps([str(root)]))
    monkeypatch.setenv("CLOUD_HOST_ALLOWLIST", "")
    from app.config import settings
    from app.db import engine, session
    from app.security import cipher, hash_password
    settings.cache_clear()
    engine.cache_clear()
    cipher.cache_clear()
    from app.main import app, attempts, capabilities
    capabilities.cache_clear()
    attempts.clear()
    from app.models import User
    with TestClient(app, headers={"X-Requested-With": "SentryDiscovery"}) as client:
        with session() as db:
            db.add(User(username="admin", password_hash=hash_password("test-admin-password"), role="admin"))
            db.add(User(username="reviewer", password_hash=hash_password("test-review-password"), role="reviewer"))
            db.commit()
        assert client.post("/api/auth/login", json={"username": "admin", "password": "test-admin-password"}).status_code == 200
        yield client, root, tmp_path
    engine().dispose()
    engine.cache_clear()
    cipher.cache_clear()
    settings.cache_clear()


def source_and_policy(client, root):
    result = client.post("/api/sources", json={"name": "Hospital documents", "kind": "filesystem", "config": {"root": str(root)}})
    assert result.status_code == 201, result.text
    source = result.json()
    assert client.post(f"/api/sources/{source['id']}/test").status_code == 200
    assert client.patch("/api/settings", json={"retention_days": 30, "audit_retention_days": 365, "retention_approved": True}).status_code == 200
    return source


def scan(client, source, **options):
    response = client.post("/api/scans", json={"source_id": source["id"], "options": options})
    assert response.status_code == 201, response.text
    scan_id = response.json()["id"]
    from app.worker import run_scan
    run_scan(scan_id)
    result = client.get(f"/api/scans/{scan_id}").json()
    assert result["status"] == "completed", result
    return result


def _database_lock_configuration(system, monkeypatch, kind):
    from app.config import settings
    _, _, temporary = system
    ca = temporary / "source-lock-test-ca.pem"
    ca.write_text("Synthetic CA placeholder; connector operations mocked")
    monkeypatch.setenv("SOURCE_DATABASE_CA_FILE", str(ca))
    monkeypatch.setenv("DATABASE_HOST_ALLOWLIST", "db.hospital.internal")
    settings.cache_clear()
    return {"host": "db.hospital.internal", "database": "hospital", "username": "reader",
            "password": "synthetic-lock-test-secret", "schema": "hospital" if kind == "mysql" else "public"}


@pytest.mark.parametrize("kind", ["postgresql", "mysql", "mssql"])
def test_database_connect_busy_returns_409_without_source_queries_or_registration(system, monkeypatch, kind):
    from app.source_locks import source_database_lock
    client, _, _ = system
    config = _database_lock_configuration(system, monkeypatch, kind)
    monkeypatch.setattr("app.main.test_connection", lambda *_: pytest.fail("Busy source issued a connection query"))
    with source_database_lock(kind, {**config, "username": "other_reader", "schema": "different_schema"}):
        response = client.post("/api/sources/connect", json={"name": "Hospital DB", "kind": kind, "config": config})
    assert response.status_code == 409
    assert "busy" in response.json()["detail"]
    assert config["host"] not in response.text and config["password"] not in response.text
    assert client.get("/api/sources").json() == []
    assert not any(event["action"] == "source_test_failed" for event in client.get("/api/audit").json())


@pytest.mark.parametrize("previous_gate", [False, True])
def test_database_retest_busy_preserves_previous_safety_gate(system, monkeypatch, previous_gate):
    from app.db import session
    from app.models import Source
    from app.source_locks import source_database_lock
    client, _, _ = system
    config = _database_lock_configuration(system, monkeypatch, "postgresql")
    created = client.post("/api/sources", json={"name": "Hospital DB", "kind": "postgresql", "config": config})
    assert created.status_code == 201
    source_id = created.json()["id"]
    with session() as db:
        db.get(Source, source_id).safety_validated = previous_gate
        db.commit()
    monkeypatch.setattr("app.main.test_connection", lambda *_: pytest.fail("Busy source issued a connection query"))
    with source_database_lock("postgresql", config):
        response = client.post(f"/api/sources/{source_id}/test")
    assert response.status_code == 409
    assert client.get("/api/sources").json()[0]["safety_validated"] is previous_gate
    assert not any(event["action"] == "source_test_failed" for event in client.get("/api/audit").json())


def test_database_api_check_lock_released_after_error_and_other_database_is_independent(system, monkeypatch):
    from app.source_locks import source_database_lock
    client, _, _ = system
    config = _database_lock_configuration(system, monkeypatch, "postgresql")
    calls = []

    def check(kind, checked):
        calls.append(checked["database"])
        if checked["database"] == "hospital":
            raise RuntimeError("synthetic-lock-test-secret")
        return {"ok": True, "read_only": True, "cancellation_verified": True, "safety_validated": True}

    monkeypatch.setattr("app.main.test_connection", check)
    response = client.post("/api/sources/connect", json={"name": "Hospital DB", "kind": "postgresql", "config": config})
    assert response.status_code == 422 and config["password"] not in response.text
    with source_database_lock("postgresql", config):
        other = client.post("/api/sources/connect", json={"name": "Other database", "kind": "postgresql",
                            "config": {**config, "database": "other"}})
    assert other.status_code == 201
    assert calls == ["hospital", "other"]


def test_end_to_end_discovery_encryption_export_review(system):
    client, root, tmp = system
    (root / "patient-named-file.txt").write_text("Patient ID: HOSP-12345\nDiagnosis: diabetes\nEmail: fictional@example.org")
    source = source_and_policy(client, root)
    result = scan(client, source)
    assert result["coverage"] == {"full": 1}
    findings = client.get("/api/findings", params={"scan_id": result["id"]}).json()
    assert {x["entity_type"] for x in findings} >= {"MRN", "EMAIL_ADDRESS", "HEALTH_INFORMATION"}
    assert any(x["classification"] == "patient_linked_health" for x in findings)
    exported = client.get(f"/api/scans/{result['id']}/export").json()
    assert len(exported["objects"]) == 1
    assert "fictional@example.org" not in json.dumps(exported)
    assert "HOSP-12345" not in json.dumps(exported)
    from app.db import engine
    with engine().connect() as connection:
        connection.exec_driver_sql("PRAGMA wal_checkpoint(TRUNCATE)")
    persisted = (tmp / "catalog.db").read_bytes()
    assert b"patient-named-file.txt" not in persisted
    assert b"fictional@example.org" not in persisted
    assert b"test-admin-password" not in persisted
    client.post("/api/auth/logout")
    client.post("/api/auth/login", json={"username": "reviewer", "password": "test-review-password"})
    assert client.post("/api/scans", json={"source_id": source["id"]}).status_code == 403
    assert client.get("/api/sources").json()[0]["config"] == {}
    assert client.patch(f"/api/findings/{findings[0]['id']}/review", json={"status": "confirmed", "note": "Locally verified"}).status_code == 200


def test_gates_allowlist_csrf_and_no_default_access(system):
    client, root, tmp = system
    assert client.post("/api/sources", json={"name": "Bad", "kind": "filesystem", "config": {"root": str(tmp)}}).status_code == 422
    response = client.post("/api/sources", json={"name": "Allowed", "kind": "filesystem", "config": {"root": str(root)}, "safety_validated": True})
    source = response.json()
    assert source["safety_validated"] is False  # Browser cannot assert that a check passed.
    assert client.post("/api/scans", json={"source_id": source["id"]}).status_code == 409
    client.post(f"/api/sources/{source['id']}/test")
    assert client.post("/api/scans", json={"source_id": source["id"]}).status_code == 409
    assert client.post("/api/auth/logout", headers={"Origin": "https://attacker.invalid"}).status_code == 403
    assert client.post("/api/auth/logout", headers={"X-Requested-With": ""}).status_code == 403
    client.post("/api/auth/logout")
    assert client.get("/api/findings").status_code == 401


def test_compare_lost_coverage_is_not_removal(system):
    client, root, _ = system
    document = root / "clinical.txt"
    document.write_text("MRN: TEST-1234\nDiagnosis: hypertension")
    source = source_and_policy(client, root)
    first = scan(client, source)
    document.unlink()
    second = scan(client, source)
    diff = client.get("/api/compare", params={"baseline": first["id"], "current": second["id"]}).json()
    assert diff["summary"] == {"coverage_lost": 1}


def test_compare_detector_change_not_attributed_to_data(system):
    client, root, _ = system
    (root / "test.txt").write_text("MRN: TEST-1234")
    source = source_and_policy(client, root)
    first, second = scan(client, source), scan(client, source)
    from app.db import session
    from app.models import Scan
    with session() as db:
        db.get(Scan, second["id"]).detector_version = "new-detector"
        db.commit()
    diff = client.get("/api/compare", params={"baseline": first["id"], "current": second["id"]}).json()
    assert diff["detector_changed"] is True
    assert diff["summary"] == {"not_comparable": 1}


def test_no_longer_observed_requires_complete_current_read(system):
    client, root, _ = system
    path = root / "sample.txt"
    path.write_text("Email: fictional@example.org")
    source = source_and_policy(client, root)
    first = scan(client, source)
    path.write_text("General hospital opening hours.")
    second = scan(client, source)
    diff = client.get("/api/compare", params={"baseline": first["id"], "current": second["id"]}).json()
    assert diff["summary"] == {"no_longer_observed": 1}


def test_retention_purges_only_terminal_scans(system):
    client, root, _ = system
    (root / "test.txt").write_text("Email: fictional@example.org")
    source = source_and_policy(client, root)
    result = scan(client, source)
    from app.db import session
    from app.models import Audit, Finding, Scan, now
    from app.worker import purge_expired
    with session() as db:
        db.get(Scan, result["id"]).created_at = now() - timedelta(days=31)
        db.commit()
    purge_expired()
    assert client.get(f"/api/scans/{result['id']}").status_code == 404
    with session() as db:
        assert not list(db.scalars(select(Finding)))
        assert db.scalar(select(Audit).where(Audit.action == "retention_purge")) is not None


def test_csv_formula_injection_neutralized(system):
    client, root, _ = system
    (root / "=formula.txt").write_text("Email: fictional@example.org")
    result = scan(client, source_and_policy(client, root))
    response = client.get(f"/api/scans/{result['id']}/export?format=csv")
    assert "'=formula.txt" in response.text


def test_persistent_exclusion_is_not_new_coverage_loss(system):
    client, root, _ = system
    (root / "archive.zip").write_bytes(b"synthetic excluded archive")
    source = source_and_policy(client, root)
    first, second = scan(client, source), scan(client, source)
    diff = client.get("/api/compare", params={"baseline": first["id"], "current": second["id"]}).json()
    assert diff["summary"] == {"not_comparable": 1}


def test_cancelled_queued_scan_cannot_be_started_by_worker(system):
    client, root, _ = system
    (root / "document.txt").write_text("Email: fictional@example.org")
    source = source_and_policy(client, root)
    scan_id = client.post("/api/scans", json={"source_id": source["id"]}).json()["id"]
    assert client.post(f"/api/scans/{scan_id}/cancel").json()["status"] == "cancelled"
    from app.worker import run_scan
    run_scan(scan_id)
    assert client.get(f"/api/scans/{scan_id}").json()["status"] == "cancelled"
    assert client.get(f"/api/scans/{scan_id}/objects").json() == []


def test_worker_rechecks_allowlist_after_queue(system, monkeypatch):
    client, root, tmp = system
    source = source_and_policy(client, root)
    scan_id = client.post("/api/scans", json={"source_id": source["id"]}).json()["id"]
    from app.config import settings
    from app.worker import run_scan
    monkeypatch.setenv("SOURCE_ALLOWED_ROOTS", json.dumps([str(tmp / "another-root")]))
    settings.cache_clear()
    run_scan(scan_id)
    result = client.get(f"/api/scans/{scan_id}").json()
    assert result["status"] == "failed"
    assert result["error"] == "source_no_longer_allowed"


def test_streamed_request_size_enforced_without_content_length(system):
    client, _, _ = system
    response = client.post("/api/auth/login", content=iter([b" " * 40000, b" " * 40000]),
                           headers={"Content-Type": "application/json"})
    assert response.status_code == 413


@pytest.mark.parametrize("resume_during_release", [False, True])
def test_database_pause_releases_scanner_and_resume_restarts(system, monkeypatch, resume_during_release):
    client, root, _ = system
    import sqlite3
    path = root / "fixture.db"
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE patients (id INTEGER)")
    source = client.post("/api/sources", json={"name": "Fixture", "kind": "sqlite", "config": {"path": str(path)}}).json()
    assert client.post(f"/api/sources/{source['id']}/test").status_code == 200
    client.patch("/api/settings", json={"retention_days": 30, "audit_retention_days": 365, "retention_approved": True})
    scan_id = client.post("/api/scans", json={"source_id": source["id"]}).json()["id"]
    released = []

    def paused_scanner(kind, config, options, detector, control):
        try:
            assert client.post(f"/api/scans/{scan_id}/pause").json()["status"] == "paused"
            assert control() == "cancelled"
            if resume_during_release:
                assert client.post(f"/api/scans/{scan_id}/resume").json()["status"] == "running"
            return
            yield  # A generator with no yielded partial object.
        finally:
            released.append(True)

    monkeypatch.setattr("app.scanning.scan_source", paused_scanner)
    from app.worker import run_scan
    run_scan(scan_id)
    assert released == [True]
    result = client.get(f"/api/scans/{scan_id}").json()
    assert result["status"] == ("queued" if resume_during_release else "paused")
    from app.db import session
    from app.models import Scan
    with session() as db:
        assert db.get(Scan, scan_id).heartbeat_at is None
    if not resume_during_release:
        assert client.post(f"/api/scans/{scan_id}/resume").json()["status"] == "queued"


def test_interrupted_scan_with_recent_heartbeat_is_requeued(system):
    client, root, _ = system
    source = source_and_policy(client, root)
    scan_id = client.post("/api/scans", json={"source_id": source["id"]}).json()["id"]
    from app.db import session
    from app.models import Scan, now
    with session() as db:
        job = db.get(Scan, scan_id)
        job.status = "interrupted"
        job.heartbeat_at = now()
        db.commit()
    assert client.post(f"/api/scans/{scan_id}/resume").json()["status"] == "queued"
    with session() as db:
        assert db.get(Scan, scan_id).heartbeat_at is None


def test_sensitive_data_access_audited_without_search_values(system):
    client, _, _ = system
    client.get("/api/findings", params={"entity_type": "not-a-patient-value"})
    events = client.get("/api/audit").json()
    assert any(x["action"] == "data_viewed" and x["detail"] == {"resource": "/api/findings"} for x in events)
    assert "not-a-patient-value" not in json.dumps(events)


def test_evidence_opt_in_encrypted_restricted_audited_and_not_exported(system):
    client, root, tmp = system
    value = "synthetic-evidence@example.org"
    (root / "record.txt").write_text(f"Patient ID: TEST-12345\nEmail: {value}\nDiagnosis: diabetes")
    source = source_and_policy(client, root)
    before = scan(client, source)
    before_findings = client.get("/api/findings", params={"scan_id": before["id"]}).json()
    old = next(f for f in before_findings if f["entity_type"] == "EMAIL_ADDRESS")
    no_capture = client.get(f"/api/findings/{old['id']}/evidence").json()
    assert no_capture["captured"] is False and no_capture["examples"] == []
    current = scan(client, source, capture_evidence=True)
    findings = client.get("/api/findings", params={"scan_id": current["id"]})
    assert value not in findings.text
    finding = next(f for f in findings.json() if f["entity_type"] == "EMAIL_ADDRESS")
    response = client.get(f"/api/findings/{finding['id']}/evidence")
    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    evidence = response.json()
    assert evidence["captured"] and evidence["available"]
    assert evidence["examples"][0]["value"] == value
    assert value in evidence["examples"][0]["excerpt"]
    assert evidence["examples"][0]["offset_scope"] == "segment"
    for format in ("csv", "json"):
        assert value not in client.get(f"/api/scans/{current['id']}/export", params={"format": format}).text
    audit_rows = client.get("/api/audit").json()
    assert value not in json.dumps(audit_rows)
    event = next(x for x in audit_rows if x["action"] == "finding_evidence_viewed" and x["detail"]["finding_id"] == finding["id"])
    assert event["detail"] == {"finding_id": finding["id"], "scan_id": current["id"], "example_count": 1}
    from app.db import engine, session
    from app.models import FindingEvidence
    from app.security import decrypt
    with session() as db:
        rows = list(db.scalars(select(FindingEvidence)))
        assert rows
        assert all(value not in row.payload_encrypted for row in rows)
        assert any(value in json.dumps(decrypt(row.payload_encrypted)) for row in rows)
        assert db.get(FindingEvidence, old["id"]) is None
    with engine().connect() as connection:
        connection.exec_driver_sql("PRAGMA wal_checkpoint(TRUNCATE)")
    assert value.encode() not in (tmp / "catalog.db").read_bytes()
    compared = client.get("/api/compare", params={"baseline": before["id"], "current": current["id"]}).json()
    assert compared["options_changed"] is False
    assert compared["summary"] == {"unchanged": 1}
    assert client.get("/api/findings/missing/evidence").status_code == 404
    assert client.post("/api/users", json={"username": "operator", "password": "test-operator-password", "role": "operator"}).status_code == 201
    client.post("/api/auth/logout")
    assert client.get(f"/api/findings/{finding['id']}/evidence").status_code == 401
    client.post("/api/auth/login", json={"username": "operator", "password": "test-operator-password"})
    assert client.get(f"/api/findings/{finding['id']}/evidence").status_code == 403
    assert client.get("/api/findings").status_code == 200
    client.post("/api/auth/logout")
    client.post("/api/auth/login", json={"username": "reviewer", "password": "test-review-password"})
    assert client.get(f"/api/findings/{finding['id']}/evidence").json()["examples"][0]["value"] == value


def test_evidence_deleted_with_finding_retention_and_old_catalog_upgrade(system):
    client, root, _ = system
    from app.db import initialize, session, engine
    from app.models import FindingEvidence, Scan, now
    from app.worker import purge_expired
    (root / "record.txt").write_text("Email: purge-evidence@example.org")
    source = source_and_policy(client, root)
    old_scan = scan(client, source)
    old_findings = client.get("/api/findings", params={"scan_id": old_scan["id"]}).json()
    # Simulate a deployed catalog made before the optional evidence table existed.
    FindingEvidence.__table__.drop(engine())
    initialize()
    assert client.get("/api/auth/me").status_code == 200
    assert client.get("/api/findings", params={"scan_id": old_scan["id"]}).json() == old_findings
    current = scan(client, source, capture_evidence=True)
    with session() as db:
        assert db.scalar(select(FindingEvidence)) is not None
        db.get(Scan, current["id"]).created_at = now() - timedelta(days=31)
        db.commit()
    purge_expired()
    with session() as db:
        assert db.scalar(select(FindingEvidence)) is None


def test_evidence_persistence_enforces_allowlist_and_limits():
    from app.worker import bounded_evidence
    item = {"value": "x" * 300, "excerpt": "x" * 500, "start": 0, "end": 300,
            "segment": "s" * 300, "unexpected_raw_document": "do not retain"}
    result = bounded_evidence({"match_count": 9, "evidence": [item] * 9})
    assert len(result["examples"]) == 3 and result["truncated"]
    assert all(len(x["value"]) == 256 and len(x["excerpt"]) == 400 and len(x["segment"]) == 256 for x in result["examples"])
    assert "unexpected_raw_document" not in json.dumps(result)
    item["value"] = "x" * 256
    item["excerpt"] = "x" * 400
    assert bounded_evidence({"match_count": 1, "evidence": [item]})["truncated"]
    assert bounded_evidence({"evidence": [{"value": "invalid", "start": -1, "end": 4}]})["examples"] == []


def test_source_setup_returns_only_admin_setup_fields_without_discovery(system, monkeypatch):
    client, root, _ = system
    from app.config import settings
    monkeypatch.setenv("DATABASE_HOST_ALLOWLIST", "db.hospital.internal")
    monkeypatch.setenv("SMB_HOST_ALLOWLIST", "files.hospital.internal")
    settings.cache_clear()

    def forbidden(*_, **__):
        raise AssertionError("Setup metadata must not enumerate files or connect to sources")

    monkeypatch.setattr("app.main.test_connection", forbidden)
    monkeypatch.setattr("pathlib.Path.iterdir", forbidden)
    response = client.get("/api/source-setup")
    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    assert response.json() == {"environment": "development", "allowed_roots": [str(root)],
                               "database_hosts": ["db.hospital.internal"], "smb_hosts": ["files.hospital.internal"],
                               "cloud_hosts": [],
                               "supported_kinds": ["filesystem", "smb", "postgresql", "mysql", "mssql", "s3", "azure_blob", "azure_table", "sqlite"]}
    for secret in (settings().database_url, settings().encryption_key, settings().session_secret):
        assert secret not in response.text
    viewed = [event for event in client.get("/api/audit").json()
              if event["action"] == "data_viewed" and event["detail"] == {"resource": "/api/source-setup"}]
    assert len(viewed) == 1
    # Production metadata never offers the fixture-only source kind.
    from dataclasses import replace
    monkeypatch.setattr("app.main.settings", lambda: replace(settings(), environment="production"))
    assert client.get("/api/source-setup").json()["supported_kinds"] == ["filesystem", "smb", "postgresql", "mysql", "mssql", "s3", "azure_blob", "azure_table"]


@pytest.mark.parametrize("kind", ["mysql", "mssql", "s3", "azure_blob", "azure_table"])
def test_new_connectors_dispatch_registration_and_never_return_credentials(system, monkeypatch, kind):
    client, _, _ = system
    from app.db import session
    from app.models import Source
    from app.security import decrypt
    module = "app.database_connectors" if kind in {"mysql", "mssql"} else "app.cloud_connectors"
    marker = "synthetic-credential-never-in-response"
    config = {key: marker + key for key in ("password", "access_key_id", "secret_access_key", "session_token", "sas_token")}
    config["tables"] = ["visits"]
    if kind in {"mysql", "mssql"}:
        config.update(host="db.hospital.internal", database="hospital")
    calls = []
    monkeypatch.setattr(module + ".normalize_config", lambda actual_kind, actual_config: dict(actual_config))

    def checked(actual_kind, actual_config):
        calls.append(actual_kind)
        assert actual_config == config
        result = {"ok": True, "safety_validated": True, "private_driver_detail": marker}
        result.update({"read_only": True, "cancellation_verified": True} if kind in {"mysql", "mssql"}
                      else {"read_only_operations": True})
        return result

    monkeypatch.setattr(module + ".test_connection", checked)
    response = client.post("/api/sources/connect", json={"name": "Synthetic source", "kind": kind, "config": config})
    assert response.status_code == 201, response.text
    assert calls == [kind]
    source_id = response.json()["source"]["id"]
    assert marker not in response.text + client.get("/api/sources").text + client.get("/api/audit").text
    with session() as db:
        source = db.get(Source, source_id)
        assert marker not in source.config_encrypted
        assert decrypt(source.config_encrypted) == config
    checked_again = client.post(f"/api/sources/{source_id}/test")
    assert checked_again.status_code == 200 and marker not in checked_again.text
    client.post("/api/auth/logout")
    client.post("/api/auth/login", json={"username": "reviewer", "password": "test-review-password"})
    assert client.get("/api/sources").json()[0]["config"] == {}


@pytest.mark.parametrize("kind", ["mysql", "mssql", "s3", "azure_blob", "azure_table"])
def test_new_connectors_fail_closed_on_incomplete_safety_and_retest_revokes_gate(system, monkeypatch, kind):
    client, _, _ = system
    from app.db import session
    from app.models import Source
    module = "app.database_connectors" if kind in {"mysql", "mssql"} else "app.cloud_connectors"
    monkeypatch.setattr(module + ".normalize_config", lambda *args: {})
    # SQL lacks cancellation; storage lacks the read-only-operations assertion.
    monkeypatch.setattr(module + ".test_connection", lambda *args: {"ok": True, "read_only": True, "safety_validated": True})
    payload = {"name": "Synthetic source", "kind": kind, "config": {}, "safety_validated": True}
    assert client.post("/api/sources/connect", json=payload).status_code == 422
    assert client.get("/api/sources").json() == []
    source_id = client.post("/api/sources", json=payload).json()["id"]
    with session() as db:
        db.get(Source, source_id).safety_validated = True
        db.commit()
    assert client.post(f"/api/sources/{source_id}/test").status_code == 422
    assert client.get("/api/sources").json()[0]["safety_validated"] is False


def test_azure_table_full_scan_cannot_be_enabled_or_queued(system, monkeypatch):
    client, _, _ = system
    monkeypatch.setattr("app.cloud_connectors.normalize_config", lambda *args: {"table": "Visits"})
    source_id = client.post("/api/sources", json={"name": "Synthetic table", "kind": "azure_table", "config": {}}).json()["id"]
    assert client.patch(f"/api/sources/{source_id}", json={"full_scan_allowed": True,
                         "workload_validation_note": "Synthetic workload review"}).status_code == 422
    assert client.post("/api/scans", json={"source_id": source_id, "options": {"full_scan": True}}).status_code == 422


@pytest.mark.parametrize("role", ["reviewer", "operator"])
def test_source_setup_and_connect_require_admin(system, role):
    client, root, _ = system
    if role == "operator":
        client.post("/api/users", json={"username": "operator", "password": "test-operator-password", "role": "operator"})
    client.post("/api/auth/logout")
    payload = {"name": "Hospital files", "kind": "filesystem", "config": {"root": str(root)}}
    assert client.get("/api/source-setup").status_code == 401
    assert client.post("/api/sources/connect", json=payload).status_code == 401
    password = "test-review-password" if role == "reviewer" else "test-operator-password"
    client.post("/api/auth/login", json={"username": role, "password": password})
    assert client.get("/api/source-setup").status_code == 403
    assert client.post("/api/sources/connect", json=payload).status_code == 403
    assert client.get("/api/sources").json() == []


def test_source_connect_checks_before_saving_and_keeps_scan_policy_gates(system):
    client, root, _ = system
    response = client.post("/api/sources/connect", json={"name": "Connected hospital files", "kind": "filesystem",
                                                       "config": {"root": str(root)}, "safety_validated": False})
    assert response.status_code == 201, response.text
    source, check = response.json()["source"], response.json()["check"]
    assert source["safety_validated"] is True
    assert check == {"ok": True, "read_only": True, "safety_validated": True}
    registered = client.get("/api/sources").json()
    assert len(registered) == 1
    assert {key: value for key, value in registered[0].items() if key != "created_at"} == {
        key: value for key, value in source.items() if key != "created_at"}
    assert client.post("/api/scans", json={"source_id": source["id"]}).status_code == 409
    client.patch("/api/settings", json={"retention_days": 30, "audit_retention_days": 365, "retention_approved": True})
    assert client.post("/api/scans", json={"source_id": source["id"], "options": {"full_scan": True}}).status_code == 409
    events = client.get("/api/audit").json()
    for action in ("source_created", "source_test_passed"):
        event = next(item for item in events if item["action"] == action)
        assert event["detail"] == {"source_id": source["id"], "kind": "filesystem"}
    assert "Connected hospital files" not in json.dumps(events)
    assert str(root) not in json.dumps(events)


def test_source_connect_rejects_unapproved_config_before_connection(system, monkeypatch):
    client, root, tmp = system
    calls = []
    monkeypatch.setattr("app.main.test_connection", lambda *args: calls.append(args))
    response = client.post("/api/sources/connect", json={"name": "Outside", "kind": "filesystem", "config": {"root": str(tmp)}, "safety_validated": True})
    assert response.status_code == 422
    assert "approved directory" in response.json()["detail"]
    assert calls == [] and client.get("/api/sources").json() == []
    assert str(tmp) not in response.text


@pytest.mark.parametrize("outcome", ["exception", "false", "truthy", "incomplete"])
def test_source_connect_failure_is_atomic_sanitized_and_cannot_trust_browser(system, monkeypatch, caplog, outcome):
    client, root, _ = system
    marker = "patient_secret_password_and_server_detail"

    def failed(*_):
        if outcome == "exception":
            raise RuntimeError(marker)
        if outcome == "false":
            return {"ok": True, "read_only": True, "safety_validated": False, "error": marker}
        if outcome == "truthy":
            return {"ok": True, "read_only": True, "safety_validated": "true", "error": marker}
        return {"ok": True, "safety_validated": True, "error": marker}

    monkeypatch.setattr("app.main.test_connection", failed)
    response = client.post("/api/sources/connect", json={"name": marker, "kind": "filesystem", "config": {"root": str(root)}, "safety_validated": True})
    assert response.status_code == 422
    assert isinstance(response.json()["detail"], str)
    assert "scanner account" in response.json()["detail"]
    assert client.get("/api/sources").json() == []
    events = client.get("/api/audit").json()
    failed_event = next(item for item in events if item["action"] == "source_test_failed")
    assert set(failed_event["detail"]) == {"attempt_id", "kind"}
    assert failed_event["detail"]["kind"] == "filesystem"
    assert marker not in response.text + json.dumps(events) + caplog.text
    assert not any(item["action"] == "source_created" for item in events)


def test_source_connect_postgresql_preserves_safety_checks_and_encrypts_credentials(system, monkeypatch):
    client, _, tmp = system
    from app.config import settings
    from app.db import session
    from app.models import Source
    from app.security import decrypt
    monkeypatch.setenv("DATABASE_HOST_ALLOWLIST", "db.hospital.internal")
    ca = tmp / "test-ca.pem"
    ca.write_text("Synthetic placeholder; driver is stubbed in this API contract test.")
    monkeypatch.setenv("SOURCE_DATABASE_CA_FILE", str(ca))
    settings.cache_clear()
    calls = []

    def check(kind, config):
        calls.append((kind, config))
        # Registration happens only after the connector completes its check.
        with session() as db:
            assert db.scalar(select(Source)) is None
        return {"ok": True, "read_only": True, "safety_validated": True,
                "cancellation_verified": True, "driver_detail": "must_not_escape"}

    monkeypatch.setattr("app.main.test_connection", check)
    config = {"host": "db.hospital.internal", "database": "hospital", "username": "discovery_reader",
              "password": "synthetic-database-secret", "port": 5432, "schema": "public", "tables": ["visits"],
              "full_scan_allowed": True}
    response = client.post("/api/sources/connect", json={"name": "Hospital database", "kind": "postgresql", "config": config})
    assert response.status_code == 201, response.text
    assert calls[0][0] == "postgresql"
    assert "sslmode=verify-full" in calls[0][1]["dsn"]
    assert "full_scan_allowed" not in calls[0][1]
    assert response.json()["check"]["cancellation_verified"] is True
    assert response.json()["source"]["config"]["password"] == "[redacted]"
    assert response.json()["source"]["config"]["dsn"] == "[redacted]"
    assert "synthetic-database-secret" not in response.text
    assert "must_not_escape" not in response.text
    with session() as db:
        source = db.get(Source, response.json()["source"]["id"])
        assert "synthetic-database-secret" not in source.config_encrypted
        assert decrypt(source.config_encrypted)["password"] == "synthetic-database-secret"


def test_source_connect_postgresql_requires_confirmed_cancellation(system, monkeypatch):
    client, _, _ = system
    config = _database_lock_configuration(system, monkeypatch, "postgresql")
    monkeypatch.setattr("app.main.test_connection", lambda *_: {"ok": True, "read_only": True, "safety_validated": True})
    response = client.post("/api/sources/connect", json={"name": "Hospital DB", "kind": "postgresql", "safety_validated": True,
                                                       "config": config})
    assert response.status_code == 422
    assert "query cancellation" in response.json()["detail"]
    assert client.get("/api/sources").json() == []


def test_source_connect_smb_requires_read_only_operations_and_redacts_credentials(system, monkeypatch):
    client, _, _ = system
    from app.config import settings
    monkeypatch.setenv("SMB_HOST_ALLOWLIST", "files.hospital.internal")
    settings.cache_clear()
    payload = {"name": "Hospital share", "kind": "smb", "safety_validated": True,
               "config": {"server": "files.hospital.internal", "share": "clinical", "subpath": "approved",
                          "username": "reader", "password": "synthetic-smb-secret"}}
    monkeypatch.setattr("app.main.test_connection", lambda *_: {"ok": True, "safety_validated": True, "read_only": True})
    failed = client.post("/api/sources/connect", json=payload)
    assert failed.status_code == 422
    assert client.get("/api/sources").json() == []
    monkeypatch.setattr("app.main.test_connection", lambda *_: {"ok": True, "safety_validated": True, "read_only_operations": True,
                                                               "note": "secret-driver-message"})
    response = client.post("/api/sources/connect", json=payload)
    assert response.status_code == 201
    assert response.json()["check"]["read_only_operations"] is True
    assert "hospital acceptance" in response.json()["check"]["note"]
    assert response.json()["source"]["config"]["password"] == "[redacted]"
    assert "synthetic-smb-secret" not in response.text
    assert "secret-driver-message" not in response.text


def test_source_connect_rolls_back_registration_if_audit_write_fails(system, monkeypatch, caplog):
    client, root, _ = system
    from app.security import audit

    def fail_creation(db, actor, action, detail=None):
        if action == "source_created":
            raise RuntimeError("catalog-driver-secret")
        return audit(db, actor, action, detail)

    monkeypatch.setattr("app.main.audit", fail_creation)
    response = client.post("/api/sources/connect", json={"name": "Hospital files", "kind": "filesystem", "config": {"root": str(root)}})
    assert response.status_code == 503
    assert "local catalogue" in response.json()["detail"]
    assert "catalog-driver-secret" not in response.text + caplog.text
    assert client.get("/api/sources").json() == []
    assert not any(event["action"] in {"source_created", "source_test_passed"} for event in client.get("/api/audit").json())
