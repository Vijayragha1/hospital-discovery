"""Deployment-owned PostgreSQL TLS and bounded safety-check regression tests.

Real certificate-chain/hostname tests live in scripts/integration_postgres.py;
these tests do not imply that a mocked driver validates certificates.
"""
from types import SimpleNamespace

import pytest
from sqlalchemy.engine import make_url

from app import sources


@pytest.fixture
def configured(monkeypatch, tmp_path):
    ca = tmp_path / "approved-ca.pem"
    ca.write_text("fixture public CA placeholder")
    monkeypatch.setenv("SOURCE_DATABASE_CA_FILE", str(ca))
    monkeypatch.setattr(sources, "settings", lambda: SimpleNamespace(database_hosts=("db.internal",)))
    monkeypatch.setattr("app.extraction.private_host", lambda host: host == "db.internal")
    return {"host": "db.internal", "database": "hospital", "username": "reader",
            "password": "secret:/@?#never-log", "schema": "public", "tables": ["visits"]}, ca


def test_postgresql_tls_uses_deployment_ca_and_overrides_submitted_dsn(configured):
    config, ca = configured
    result = sources.normalize_config("postgresql", {
        **config, "dsn": "postgresql://outside.invalid/?sslmode=disable", "sslmode": "disable",
        "sslrootcert": "/unapproved/browser-ca.pem", "ca_file": "/unapproved/browser-ca.pem",
        "gssencmode": "prefer", "connect_timeout": 3600,
    })
    url = make_url(result["dsn"])
    assert url.host == "db.internal" and url.password == config["password"]
    assert dict(url.query) == {"connect_timeout": "5", "sslmode": "verify-full",
                               "sslrootcert": str(ca), "ssl_min_protocol_version": "TLSv1.2",
                               "gssencmode": "disable"}
    assert not {"sslmode", "sslrootcert", "ca_file", "gssencmode"} & result.keys()
    assert "outside.invalid" not in result["dsn"]


@pytest.mark.parametrize("mode", ["unset", "relative", "missing", "directory"])
def test_postgresql_fails_closed_without_configured_ca(configured, monkeypatch, tmp_path, mode):
    config, _ = configured
    if mode == "unset":
        monkeypatch.delenv("SOURCE_DATABASE_CA_FILE")
    else:
        monkeypatch.setenv("SOURCE_DATABASE_CA_FILE", {
            "relative": "ca.pem", "missing": str(tmp_path / "private-name-missing.pem"),
            "directory": str(tmp_path),
        }[mode])
    with pytest.raises(ValueError, match="^Database trusted CA is not configured\\.$") as error:
        sources.normalize_config("postgresql", config)
    assert config["password"] not in str(error.value)
    assert str(tmp_path) not in str(error.value)


def test_postgresql_normalization_reloads_deployment_trust(configured, monkeypatch, tmp_path):
    config, old_ca = configured
    previous = sources.normalize_config("postgresql", config)
    new_ca = tmp_path / "replacement-ca.pem"
    new_ca.write_text("new fixture public CA placeholder")
    monkeypatch.setenv("SOURCE_DATABASE_CA_FILE", str(new_ca))
    current = sources.normalize_config("postgresql", previous)
    assert make_url(previous["dsn"]).query["sslrootcert"] == str(old_ca)
    assert make_url(current["dsn"]).query["sslrootcert"] == str(new_ca)


class ConnectionFixture:
    def __init__(self, cancellation_state="57014", recovery=1):
        self.statements = []
        self.cancellation_state = cancellation_state
        self.recovery = recovery
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.closed = True

    def rollback(self):
        self.statements.append("ROLLBACK")

    def execute(self, statement, *_):
        sql = str(statement)
        self.statements.append(sql)
        if "pg_sleep" in sql and self.cancellation_state is not None:
            failure = RuntimeError("driver detail must not reach diagnostics")
            failure.orig = SimpleNamespace(sqlstate=self.cancellation_state)
            raise failure
        value = self.recovery if sql == "SELECT 1" else False
        return SimpleNamespace(scalar=lambda: value)


def bind_fixture(monkeypatch, connection):
    engine = SimpleNamespace(disposed=False, dialect=SimpleNamespace(identifier_preparer=
        SimpleNamespace(quote_schema=lambda name: '"' + name + '"', quote=lambda name: '"' + name + '"')))
    observed = []
    engine.connect = lambda: connection
    engine.dispose = lambda: setattr(engine, "disposed", True)
    monkeypatch.setattr(sources, "create_engine", lambda dsn, **options: (observed.append((dsn, options)) or engine))
    return engine, observed


def test_postgresql_check_uses_verified_tls_and_bounded_cancellation_recovery(configured, monkeypatch):
    config, ca = configured
    connection = ConnectionFixture()
    engine, observed = bind_fixture(monkeypatch, connection)
    result = sources.test_connection("postgresql", config)
    assert result["cancellation_verified"] is True and result["read_only"] is True
    url = make_url(observed[0][0])
    assert url.query["sslmode"] == "verify-full" and url.query["sslrootcert"] == str(ca)
    assert url.query["connect_timeout"] == "5"
    assert observed[0][1]["hide_parameters"] is True
    assert "SET LOCAL statement_timeout='5s'" in connection.statements
    assert "SET LOCAL lock_timeout='1s'" in connection.statements
    cancellation = connection.statements.index("SELECT pg_sleep(0.05)")
    assert connection.statements[cancellation + 1:] == [
        "ROLLBACK", "SET TRANSACTION READ ONLY", "SET LOCAL statement_timeout='5s'",
        "SET LOCAL lock_timeout='1s'", "SELECT 1"]
    assert engine.disposed and connection.closed


@pytest.mark.parametrize("state,recovery", [(None, 1), ("08006", 1), ("57014", 0)])
def test_postgresql_rejects_failed_cancellation_or_recovery(configured, monkeypatch, state, recovery):
    config, _ = configured
    connection = ConnectionFixture(state, recovery)
    engine, _ = bind_fixture(monkeypatch, connection)
    with pytest.raises(ValueError) as error:
        sources.test_connection("postgresql", config)
    assert "driver detail" not in str(error.value)
    assert config["password"] not in str(error.value)
    assert engine.disposed and connection.closed
