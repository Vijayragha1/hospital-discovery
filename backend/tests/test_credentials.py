"""Credential replacement contracts, using synthetic sources and mocked I/O."""
from datetime import datetime, timedelta, timezone
import json
from urllib.parse import urlencode

import pytest
from sqlalchemy import select

from test_api import system  # noqa: F401 — shared isolated catalogue/login fixture


KINDS = ["postgresql", "mysql", "mssql", "smb", "s3", "azure_blob", "azure_table"]
SECRET_KEYS = {"password", "dsn", "access_key_id", "secret_access_key", "session_token", "sas_token"}


def sas(kind, marker):
    fields = {"sv": "2025-01-05", "sig": marker, "se": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
              "sp": "rl" if kind == "azure_blob" else "r", "spr": "https"}
    fields.update({"sr": "c"} if kind == "azure_blob" else {"tn": "Visits"})
    return urlencode(fields)


@pytest.fixture
def sources(system, monkeypatch):
    client, folder, temporary = system
    from app.config import settings
    from app.db import session
    from app.models import Source
    from app.security import decrypt
    ca = temporary / "credential-test-ca.pem"
    ca.write_text("Synthetic CA placeholder; source I/O is mocked")
    monkeypatch.setenv("SOURCE_DATABASE_CA_FILE", str(ca))
    monkeypatch.setenv("DATABASE_HOST_ALLOWLIST", "db.hospital.internal")
    monkeypatch.setenv("SMB_HOST_ALLOWLIST", "files.hospital.internal")
    monkeypatch.setenv("CLOUD_HOST_ALLOWLIST", "storage.hospital.internal")
    settings.cache_clear()
    monkeypatch.setattr("app.cloud_connectors._check_private", lambda host: None)

    def success(kind, config):
        return {"ok": True, "safety_validated": True,
                **({"read_only": True, "cancellation_verified": True} if kind in {"postgresql", "mysql", "mssql"}
                   else {"read_only": True} if kind == "filesystem" else {"read_only_operations": True})}

    monkeypatch.setattr("app.main.test_connection", success)

    def register(kind, *, auth_mode="access_key", approved=True):
        old_password = "synthetic-old-credential-secret"
        if kind in {"postgresql", "mysql", "mssql"}:
            config = {"host": "db.hospital.internal", "database": "hospital", "username": "reader1",
                      "password": old_password, "schema": "hospital" if kind == "mysql" else "public",
                      "tables": ["visits"], "patient_identifier_columns": {"visits": ["patient_key"]}}
        elif kind == "smb":
            config = {"server": "files.hospital.internal", "share": "clinical", "subpath": "approved/path",
                      "username": "reader1", "password": old_password, "domain": "HOSPITAL"}
        elif kind == "s3":
            config = {"endpoint_url": "https://storage.hospital.internal", "bucket": "hospital-fixture",
                      "prefix": "approved/patient-prefix/", "region": "ap-south-1", "auth_mode": auth_mode}
            if auth_mode == "access_key":
                config.update(access_key_id="synthetic-old-access-key", secret_access_key=old_password,
                              session_token="synthetic-old-session-token")
        elif kind in {"azure_blob", "azure_table"}:
            config = {"account_url": "https://storage.hospital.internal", "sas_token": sas(kind, old_password)}
            config.update({"container": "hospital-fixture", "prefix": "approved/"} if kind == "azure_blob"
                          else {"table": "Visits", "partition_key": "approved-partition"})
        else:
            config = {"root": str(folder)}
        response = client.post("/api/sources/connect", json={"name": "Synthetic credential test", "kind": kind, "config": config})
        assert response.status_code == 201, response.text
        source_id = response.json()["source"]["id"]
        if kind != "azure_table":
            update = client.patch(f"/api/sources/{source_id}", json={"full_scan_allowed": True,
                                  "workload_validation_note": "Synthetic approval retained"})
            assert update.status_code == 200
        with session() as db:
            source = db.get(Source, source_id)
            source.safety_validated = approved
            db.commit()
            original = decrypt(source.config_encrypted)
            encrypted = source.config_encrypted
        return source_id, original, encrypted

    return register, success


def replacement(kind):
    if kind in {"postgresql", "mysql", "mssql"}:
        return {"username": "reader2", "password": "synthetic-new-credential-secret"}
    if kind == "smb":
        return {"username": "reader2", "password": "synthetic-new-credential-secret", "domain": "NEWDOMAIN"}
    if kind == "s3":
        return {"access_key_id": "synthetic-new-access-key", "secret_access_key": "synthetic-new-credential-secret",
                "session_token": "synthetic-new-session-token"}
    return {"sas_token": sas(kind, "synthetic-new-credential-secret")}


@pytest.mark.parametrize("kind", KINDS)
def test_replacement_preserves_identity_scope_approval_history_and_encryption(system, sources, monkeypatch, kind):
    client, _, _ = system
    register, success = sources
    source_id, original, encrypted = register(kind, approved=False)
    from app.db import session
    from app.models import Audit, Scan, Source
    from app.security import decrypt
    from app.sources import normalize_config
    with session() as db:
        previous = Scan(source_id=source_id, status="completed", options={}, detector_version="fixture-detector")
        db.add(previous)
        db.commit()
        scan_id = previous.id
    changes = replacement(kind)
    observed = []

    def check(actual_kind, config):
        observed.append(config)
        # The replacement is not persisted before its connection check succeeds.
        with session() as db:
            assert db.get(Source, source_id).config_encrypted == encrypted
        return {**success(actual_kind, config), "private_driver_detail": "synthetic-new-credential-secret"}

    monkeypatch.setattr("app.main.test_connection", check)
    result = client.post(f"/api/sources/{source_id}/credentials", json={"credentials": changes})
    assert result.status_code == 200, result.text
    assert result.json()["source"]["id"] == source_id
    assert result.json()["source"]["safety_validated"] is True
    expected = normalize_config(kind, {**original, **changes})
    expected.update({key: original[key] for key in ("full_scan_allowed", "workload_validation_note") if key in original})
    with session() as db:
        source = db.get(Source, source_id)
        assert source.config_encrypted != encrypted
        assert decrypt(source.config_encrypted) == expected
        assert db.get(Scan, scan_id).source_id == source_id
        assert len(list(db.scalars(select(Source)))) == 1
        event = db.scalar(select(Audit).where(Audit.action == "source_credentials_updated"))
        assert decrypt(event.detail_encrypted) == {"source_id": source_id}
        assert "synthetic-new-credential-secret" not in source.config_encrypted + event.detail_encrypted
    assert len(observed) == 1
    assert client.get(f"/api/scans/{scan_id}").status_code == 200
    assert "synthetic-new-credential-secret" not in result.text + client.get("/api/audit").text
    for field in SECRET_KEYS & expected.keys():
        assert result.json()["source"]["config"][field] == "[redacted]"
    for key in set(original) - set(changes) - {"dsn"}:
        assert expected[key] == original[key]


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("previous_gate", [False, True])
def test_failed_replacement_preserves_old_config_and_gate(system, sources, monkeypatch, kind, previous_gate):
    client, _, _ = system
    register, _ = sources
    source_id, original, encrypted = register(kind, approved=previous_gate)
    from app.db import session
    from app.models import Source
    from app.security import decrypt

    def failed(*_):
        raise RuntimeError("synthetic-new-credential-secret private-server-error")

    monkeypatch.setattr("app.main.test_connection", failed)
    response = client.post(f"/api/sources/{source_id}/credentials", json={"credentials": replacement(kind)})
    assert response.status_code == 422
    assert "saved credentials were kept" in response.text
    with session() as db:
        source = db.get(Source, source_id)
        assert source.config_encrypted == encrypted and decrypt(source.config_encrypted) == original
        assert source.safety_validated is previous_gate
    events = client.get("/api/audit").json()
    event = next(event for event in events if event["action"] == "source_credentials_update_failed")
    assert event["detail"] == {"source_id": source_id}
    assert "synthetic-new-credential-secret" not in response.text + json.dumps(events)
    assert "private-server-error" not in response.text + json.dumps(events)


@pytest.mark.parametrize("kind,changes", [
    ("postgresql", {"host": "outside.invalid"}), ("mysql", {"database": "other"}),
    ("mssql", {"schema": "other"}), ("smb", {"share": "other"}),
    ("s3", {"prefix": "other/"}), ("s3", {"auth_mode": "iam_role"}),
    ("azure_blob", {"container": "other"}), ("azure_table", {"partition_key": "other"}),
    ("postgresql", {"full_scan_allowed": "false"}), ("postgresql", {"dsn": "ignored-url"}),
])
def test_replacement_rejects_scope_mode_and_approval_edits_before_io(system, sources, monkeypatch, kind, changes):
    client, _, _ = system
    source_id, _, encrypted = sources[0](kind)
    from app.db import session
    from app.models import Source
    monkeypatch.setattr("app.main.test_connection", lambda *_: pytest.fail("Invalid edit queried a source"))
    result = client.post(f"/api/sources/{source_id}/credentials", json={"credentials": changes})
    assert result.status_code == 422
    with session() as db:
        assert db.get(Source, source_id).config_encrypted == encrypted


@pytest.mark.parametrize("status", ["queued", "running", "paused"])
def test_replacement_rejects_active_scans_before_io(system, sources, monkeypatch, status):
    client, _, _ = system
    source_id, _, encrypted = sources[0]("postgresql")
    from app.db import session
    from app.models import Scan, Source
    with session() as db:
        db.add(Scan(source_id=source_id, status=status, options={}))
        db.commit()
    monkeypatch.setattr("app.main.test_connection", lambda *_: pytest.fail("Active source was queried"))
    result = client.post(f"/api/sources/{source_id}/credentials", json={"credentials": replacement("postgresql")})
    assert result.status_code == 409
    with session() as db:
        assert db.get(Source, source_id).config_encrypted == encrypted


@pytest.mark.parametrize("role", ["reviewer", "operator", "anonymous"])
def test_replacement_requires_administrator(system, sources, monkeypatch, role):
    client, _, _ = system
    source_id, _, _ = sources[0]("postgresql")
    if role == "operator":
        assert client.post("/api/users", json={"username": "operator", "password": "synthetic-operator-password", "role": role}).status_code == 201
    client.post("/api/auth/logout")
    if role != "anonymous":
        password = "test-review-password" if role == "reviewer" else "synthetic-operator-password"
        assert client.post("/api/auth/login", json={"username": role, "password": password}).status_code == 200
    monkeypatch.setattr("app.main.test_connection", lambda *_: pytest.fail("Unauthorized caller queried source"))
    result = client.post(f"/api/sources/{source_id}/credentials", json={"credentials": replacement("postgresql")})
    assert result.status_code == (401 if role == "anonymous" else 403)


def test_busy_database_replacement_leaves_source_and_gate_unchanged(system, sources, monkeypatch):
    client, _, _ = system
    source_id, config, encrypted = sources[0]("postgresql")
    from app.db import session
    from app.models import Source
    from app.source_locks import source_database_lock
    monkeypatch.setattr("app.main.test_connection", lambda *_: pytest.fail("Busy source was queried"))
    with source_database_lock("postgresql", {**config, "username": "other_reader", "schema": "other_schema"}):
        result = client.post(f"/api/sources/{source_id}/credentials", json={"credentials": replacement("postgresql")})
    assert result.status_code == 409 and "busy" in result.text
    with session() as db:
        source = db.get(Source, source_id)
        assert source.config_encrypted == encrypted and source.safety_validated is True
    assert not any(event["action"] == "source_credentials_update_failed" for event in client.get("/api/audit").json())


@pytest.mark.parametrize("kind,mode", [("filesystem", "access_key"), ("s3", "iam_role")])
def test_local_and_instance_role_sources_disallow_credential_replacement(system, sources, monkeypatch, kind, mode):
    client, _, _ = system
    source_id, _, _ = sources[0](kind, auth_mode=mode)
    monkeypatch.setattr("app.main.test_connection", lambda *_: pytest.fail("Disallowed source was queried"))
    result = client.post(f"/api/sources/{source_id}/credentials", json={"credentials": {"password": "synthetic-new-credential-secret"}})
    assert result.status_code == 422


def test_s3_session_token_can_be_explicitly_cleared_without_changing_keys(system, sources):
    client, _, _ = system
    source_id, original, _ = sources[0]("s3")
    result = client.post(f"/api/sources/{source_id}/credentials", json={"credentials": {"session_token": ""}})
    assert result.status_code == 200
    from app.db import session
    from app.models import Source
    from app.security import decrypt
    with session() as db:
        current = decrypt(db.get(Source, source_id).config_encrypted)
    assert current == {**original, "session_token": ""}


@pytest.mark.parametrize("credentials", [{}, {"password": None}, {"password": 123}, {"password": "x" * 16385}])
def test_invalid_credential_payload_never_queries_source(system, sources, monkeypatch, credentials):
    client, _, _ = system
    source_id, _, _ = sources[0]("postgresql")
    monkeypatch.setattr("app.main.test_connection", lambda *_: pytest.fail("Invalid payload queried source"))
    result = client.post(f"/api/sources/{source_id}/credentials", json={"credentials": credentials})
    assert result.status_code == 422
