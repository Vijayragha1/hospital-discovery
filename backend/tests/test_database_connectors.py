import json
import re
from types import SimpleNamespace

import pytest

from app import database_connectors as connectors
from app.detection import Detector


@pytest.fixture
def configured(monkeypatch, tmp_path):
    monkeypatch.setattr(connectors, "settings", lambda: SimpleNamespace(database_hosts=("db.internal",)))
    monkeypatch.setattr(connectors, "private_host", lambda host: host == "db.internal")
    ca = tmp_path / "ca.pem"
    ca.write_text("synthetic CA placeholder")
    monkeypatch.setenv("SOURCE_DATABASE_CA_FILE", str(ca))
    return {"host": "db.internal", "database": "hospital", "username": "reader", "password": "never-log-this"}


class FixtureServer:
    def __init__(self, kind, row_count=3):
        self.kind = kind
        self.data = [(str(i), f"H1234{i}", "diabetes", None) for i in range(row_count)]
        self.connections, self.executed, self.fetch_sizes, self.events = [], [], [], []
        self.writable = False
        self.fail_table = False
        self.cancel_works = True
        self.extra_tables = []

    def connect(self, *_args, **_kwargs):
        connection = SimpleNamespace(closed=False)
        def close():
            self.events.append("connection_closed")
            connection.closed = True
        connection.close = close
        connection.cursor = lambda *_: FixtureCursor(self, connection)
        self.connections.append(connection)
        return connection

    def response(self, query, params):
        self.executed.append((query, params))
        if query.startswith("SET ") or query.startswith("START "):
            return []
        if query == "SELECT VERSION()":
            return [("8.4.1",)]
        if "SERVERPROPERTY('ProductMajorVersion')" in query:
            return [(16,)]
        if query.startswith("SHOW SESSION STATUS"):
            return [("Ssl_cipher", "TLS_AES_256_GCM_SHA384")]
        if query == "SELECT CURRENT_ROLE()":
            return [("NONE",)]
        if query == "SHOW GRANTS":
            return [("GRANT " + ("SELECT, UPDATE" if self.writable else "SELECT") + " ON `hospital`.* TO `reader`@`%`",)]
        if "fn_my_permissions" in query:
            return [("UPDATE",)] if self.writable else [("CONNECT SQL" if params[1] == "SERVER" else "CONNECT" if params[1] == "DATABASE" else "SELECT",)]
        if "INFORMATION_SCHEMA.TABLES" in query:
            return [("visits", "BASE TABLE", "InnoDB"), ("report", "VIEW", None)] + self.extra_tables
        if "INFORMATION_SCHEMA.COLUMNS" in query or "FROM sys.columns c JOIN sys.types" in query:
            return [("id", "int"), ("mrn", "varchar"), ("diagnosis", "text"), ("attachment", "blob" if self.kind == "mysql" else "varbinary")]
        if "KEY_COLUMN_USAGE" in query:
            return [("id", None, None, "PRIMARY")]
        if "sys.indexes" in query:
            return [("id",)]
        if "sys.foreign_key_columns" in query:
            return []
        if "LIMIT 0" in query or "TOP (0)" in query:
            return []
        if query == "SELECT SLEEP(0.2)":
            return [(1 if self.cancel_works else 0,)]
        if query.startswith("WAITFOR"):
            if self.cancel_works:
                import pytds
                raise pytds.tds_base.TimeoutError()
            return []
        if query == "SELECT 1":
            return [(1,)]
        if self.fail_table:
            raise RuntimeError("never-log-this secret clinical content")
        limit = re.search(r"(?:LIMIT |TOP \()(\d+)", query)
        return self.data[:int(limit.group(1))] if limit else self.data


class FixtureCursor:
    def __init__(self, server, connection):
        self.server, self.connection, self.rows, self.position = server, connection, [], 0
    def execute(self, query, params=()):
        self.rows = self.server.response(query, params)
        self.position = 0
    def fetchmany(self, size):
        self.server.fetch_sizes.append(size)
        rows = self.rows[self.position:self.position + size]
        self.position += len(rows)
        return rows
    def fetchone(self):
        rows = self.fetchmany(1)
        return rows[0] if rows else None
    def cancel(self):
        self.server.events.append("cancel")
    def close(self):
        self.server.events.append("cursor_closed")


@pytest.mark.parametrize("kind,port,schema", [("mysql", 3306, "hospital"), ("mssql", 1433, "dbo")])
def test_normalization_approves_exact_hosts_and_drops_browser_safety_overrides(configured, kind, port, schema):
    normalized = connectors.normalize_config(kind, {**configured, "full_scan_allowed": True, "ssl_verify": False, "ca_file": "/secret"})
    assert normalized["port"] == port and normalized["schema"] == schema
    assert not {"full_scan_allowed", "ssl_verify", "ca_file"} & normalized.keys()
    with pytest.raises(connectors.ConnectorError):
        connectors.normalize_config(kind, {**configured, "host": "db.internal@outside.invalid"})
    with pytest.raises(connectors.ConnectorError):
        connectors.normalize_config(kind, {**configured, "tables": [""]})
    if kind == "mysql":
        with pytest.raises(connectors.ConnectorError, match="mysql_schema"):
            connectors.normalize_config(kind, {**configured, "schema": "another_database"})


@pytest.mark.parametrize("kind", ["mysql", "mssql"])
def test_driver_enforces_private_endpoint_and_verified_tls(configured, monkeypatch, kind):
    captured = {}
    def connect(**kwargs):
        captured.update(kwargs)
        return object()
    monkeypatch.setattr("pymysql.connect" if kind == "mysql" else "pytds.connect", connect)
    config = connectors.normalize_config(kind, configured)
    connectors._connect(kind, config)
    if kind == "mysql":
        assert captured["ssl_verify_cert"] and captured["ssl_verify_identity"]
        assert captured["local_infile"] is False
    else:
        assert captured["validate_host"] and captured["enc_login_only"] is False
        assert captured["pooling"] is False and captured["timeout"] == 5
    monkeypatch.setattr(connectors, "private_host", lambda _: False)
    with pytest.raises(connectors.ConnectorError, match="not_private"):
        connectors._connect(kind, config)


@pytest.mark.parametrize("kind", ["mysql", "mssql"])
def test_connection_requires_readonly_and_verified_cancellation(configured, monkeypatch, kind):
    server = FixtureServer(kind)
    monkeypatch.setattr(connectors, "_connect", server.connect)
    assert connectors.test_connection(kind, configured)["cancellation_verified"]
    assert all(connection.closed for connection in server.connections)
    server.writable = True
    with pytest.raises(connectors.ConnectorError, match="read_only"):
        connectors.test_connection(kind, configured)
    server.writable = False
    server.cancel_works = False
    with pytest.raises(connectors.ConnectorError, match="cancellation_unverified"):
        connectors.test_connection(kind, configured)


@pytest.mark.parametrize("kind", ["mysql", "mssql"])
def test_scans_sample_stream_and_report_binary_and_view_coverage(configured, monkeypatch, kind):
    server = FixtureServer(kind, 2500)
    monkeypatch.setattr(connectors, "_connect", server.connect)
    results = list(connectors.scan(kind, configured, {}, Detector("rules"), lambda: "running"))
    columns = [item for item in results if item["status"] == "sampled"]
    assert len(columns) == 3 and all(item["examined"] == 1000 for item in columns)
    assert any(item["reason"] == "binary_column_not_inspected" for item in results)
    assert any(item["reason"] == "database_views_not_scanned" for item in results)
    assert max(server.fetch_sizes) <= 100
    assert "H1234" not in json.dumps(results)
    config = {**configured, "tables": ["visits"], "full_scan_allowed": True}
    full = list(connectors.scan(kind, config, {"full_scan": True}, Detector("rules"), lambda: "running"))
    assert sum(item["status"] == "full" and item["examined"] == 2500 for item in full) == 3
    assert all(connection.closed for connection in server.connections)


@pytest.mark.parametrize("kind", ["mysql", "mssql"])
def test_cancel_coverage_and_failure_never_echo_values(configured, monkeypatch, caplog, kind):
    server = FixtureServer(kind, 2500)
    monkeypatch.setattr(connectors, "_connect", server.connect)
    checks = 0
    def control():
        nonlocal checks
        checks += 1
        return "running" if checks < 130 else "cancelled"
    results = list(connectors.scan(kind, configured, {}, Detector("rules"), control))
    assert any(item["reason"] == "scan_cancelled" and item["examined"] > 0 for item in results)
    assert all(connection.closed for connection in server.connections)
    server.fail_table = True
    results = list(connectors.scan(kind, configured, {}, Detector("rules"), lambda: "running"))
    assert any(item["reason"] == "table_query_or_detection_failed" for item in results)
    assert "never-log-this" not in json.dumps(results) + caplog.text


def test_scope_timeout_and_identifier_escaping(configured):
    for kind in ("mysql", "mssql"):
        results = list(connectors.scan(kind, configured, {"full_scan": True}, Detector("rules"), lambda: "running"))
        assert results[0]["status"] == "excluded"
        results = list(connectors.scan(kind, configured, {"statement_timeout_ms": 5001}, Detector("rules"), lambda: "running"))
        assert results[0]["reason"] == "database_timeout_limit_exceeded"
    assert connectors._quote("mysql", "a`b") == "`a``b`"
    assert connectors._quote("mssql", "a]b") == "[a]]b]"


def test_metadata_overflow_closes_transport_before_unbuffered_cursor(configured):
    server = FixtureServer("mysql")
    server.data = [(i,) for i in range(2000)]
    connection = server.connect()
    with pytest.raises(connectors.ConnectorError, match="metadata_limit"):
        connectors._query(connection, "mysql", "SELECT synthetic_rows", limit=10)
    assert server.events[-2:] == ["connection_closed", "cursor_closed"]


def test_mysql_abort_does_not_drain_closed_transport():
    from pymysql.connections import MySQLResult
    from pymysql.cursors import SSCursor
    connection = SimpleNamespace(_result=None, close=lambda: None)
    result = MySQLResult(connection)
    result.unbuffered_active = True
    result.has_next = False
    connection._result = result
    cursor = SSCursor(connection)
    cursor._result = result
    connectors._abort_cursor(connection, cursor, "mysql")
    assert result.unbuffered_active is False and result.connection is None
    assert cursor.connection is None
    result.__del__()  # Must not attempt _read_packet against the closed transport.


def test_mssql_permits_approved_ip_with_patched_san_validation(configured, monkeypatch):
    monkeypatch.setattr(connectors, "settings", lambda: SimpleNamespace(database_hosts=("10.1.2.3",)))
    assert connectors.normalize_config("mssql", {**configured, "host": "10.1.2.3"})["host"] == "10.1.2.3"


def _tls_patch_module():
    import runpy
    from pathlib import Path
    path = Path(__file__).resolve().parents[2] / "scripts" / "patch_python_tds.py"
    return SimpleNamespace(**runpy.run_path(str(path)))


def _certificate(dns_names=(), ip_names=(), common_name="legacy.internal", with_san=True):
    import datetime
    import ipaddress
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import NameOID
    from OpenSSL.crypto import X509
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now - datetime.timedelta(hours=1))
               .not_valid_after(now + datetime.timedelta(days=1)))
    if with_san:
        names = [x509.DNSName(value) for value in dns_names]
        names.extend(x509.IPAddress(ipaddress.ip_address(value)) for value in ip_names)
        builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=False)
    return X509.from_cryptography(builder.sign(key, hashes.SHA256()))


def test_tds_patch_hostname_verifier_checks_dns_ip_wildcard_and_san_precedence():
    namespace = {}
    exec(_tls_patch_module().HOSTNAME_MATCHER, namespace)
    verify = namespace["validate_host"]
    cert = _certificate(("db.internal", "*.clinic.internal"), ("10.1.2.3",))
    assert verify(cert, b"db.internal")
    assert verify(cert, b"DB.INTERNAL")
    assert verify(cert, b"10.1.2.3")
    assert verify(cert, b"sql.clinic.internal")
    assert not verify(cert, b"wrong.internal")
    assert not verify(cert, b"10.1.2.4")
    assert not verify(cert, b"sub.sql.clinic.internal")
    assert not verify(cert, b"legacy.internal")  # A matching CN cannot override SAN.
    assert not verify(_certificate(with_san=False), b"legacy.internal")
    assert not verify(_certificate(("10.1.2.3",)), b"10.1.2.3")  # IP requires IP SAN.


def test_tds_patch_is_locked_idempotent_and_preserves_chain_verification():
    import hashlib
    import importlib.util
    from pathlib import Path
    module = _tls_patch_module()
    source = Path(importlib.util.find_spec("pytds.tls").origin).read_bytes()
    patched = module.patch_bytes(source, "1.17.1")
    assert hashlib.sha256(patched).hexdigest() == connectors.TDS_TLS_SHA256
    assert module.patch_bytes(patched, "1.17.1") == patched
    # These unchanged driver operations perform chain validation before checking SAN.
    text = patched.decode()
    assert "ctx.set_verify(OpenSSL.SSL.VERIFY_PEER, verify_cb)" in text
    assert "ctx.load_verify_locations(cafile=cafile)" in text
    assert "conn.do_handshake()" in text and "if login.validate_host:" in text
    assert "return ret_code" in text
    with pytest.raises(RuntimeError, match="version_mismatch"):
        module.patch_bytes(source, "1.17.2")
    with pytest.raises(RuntimeError, match="source_mismatch"):
        module.patch_bytes(source + b"\n", "1.17.1")


def test_tds_patch_rejects_redirect_before_opening_another_host(monkeypatch):
    import hashlib
    import importlib.util
    from pathlib import Path
    import pytds
    module = _tls_patch_module()
    source = Path(importlib.util.find_spec("pytds").origin).read_bytes()
    patched = module.patch_init_bytes(source, "1.17.1")
    assert hashlib.sha256(patched).hexdigest() == connectors.TDS_INIT_SHA256
    assert module.patch_init_bytes(patched, "1.17.1") == patched
    with pytest.raises(RuntimeError, match="source_mismatch"):
        module.patch_init_bytes(source + b"\n", "1.17.1")
    events = []
    sock = SimpleNamespace(setsockopt=lambda *_: None, settimeout=lambda *_: None,
                           close=lambda: events.append("socket_closed"))
    monkeypatch.setattr(pytds.socket, "create_connection", lambda *_: pytest.fail("redirect must never open another connection"))
    monkeypatch.setattr(pytds.instance_browser_client, "resolve_instance_port", lambda **_: 1433)
    monkeypatch.setattr(pytds, "_TdsSocket", lambda **_: SimpleNamespace(login=lambda: {"server": "outside.invalid", "port": 1433}))
    with pytest.raises(pytds.tds_base.Error, match="routing is not supported"):
        pytds._connect(login=SimpleNamespace(access_token_callable=None), host="approved.internal",
                       port=1433, instance="", timeout=5, pooling=False, key=None,
                       autocommit=True, isolation_level=0, tzinfo_factory=None, sock=sock,
                       use_tz=None, row_strategy=None)
    assert events


def test_tds_explicit_debug_child_cannot_log_source_values(monkeypatch, caplog):
    import logging
    for name in ("pytds.login", "pytds.custom_runtime_child"):
        logger = logging.getLogger(name)
        monkeypatch.setattr(logger, "level", logging.DEBUG)
        monkeypatch.setattr(logger, "propagate", True)
    connectors._quiet_driver_logs()
    for name in ("pytds.login", "pytds.custom_runtime_child"):
        logger = logging.getLogger(name)
        logger.critical("never-log-this synthetic SQL password and source content")
        assert logger.level > logging.CRITICAL and logger.propagate is False
    assert "never-log-this" not in caplog.text


def test_mysql_rejects_granted_roles_and_nonmysql_servers(configured, monkeypatch):
    server = FixtureServer("mysql")
    original = server.response
    monkeypatch.setattr(connectors, "_connect", server.connect)
    server.response = lambda query, params: [("GRANT `writer_role`@`%` TO `reader`@`%`",)] if query == "SHOW GRANTS" else original(query, params)
    with pytest.raises(connectors.ConnectorError, match="direct_read_only"):
        connectors.test_connection("mysql", configured)
    server.response = lambda query, params: [("10.11-MariaDB",)] if query == "SELECT VERSION()" else original(query, params)
    with pytest.raises(connectors.ConnectorError, match="version_not_supported"):
        connectors.test_connection("mysql", configured)


def test_wide_table_limits_projection_and_fetch_before_rows_are_read():
    from app.scanning import DEFAULTS
    columns = [f"field_{i}" for i in range(1024)]
    options = connectors._projection_options(columns, set(), DEFAULTS)
    row_bytes = len(columns) * (options["max_text_chars"] + 1) * 4
    assert row_bytes <= connectors.MAX_ROW_TEXT_BYTES
    assert row_bytes * options["batch_size"] <= connectors.MAX_BATCH_TEXT_BYTES
    assert options["max_text_chars"] < 65536
    query = connectors._data_query("mysql", {"schema": "hospital"}, "visits", columns, set(), [], options)
    assert f", {options['max_text_chars'] + 1})" in query


def test_detection_processing_time_does_not_consume_database_call_budget(configured, monkeypatch):
    server = FixtureServer("mssql", 1000)
    monkeypatch.setattr(connectors, "_connect", server.connect)
    clock = [0.0]
    monkeypatch.setattr(connectors.time, "monotonic", lambda: clock[0])
    class SlowDetector:
        def analyze(self, *_, **__):
            clock[0] += 1
            return []
    results = list(connectors.scan("mssql", configured, {}, SlowDetector(), lambda: "running"))
    assert sum(item["status"] == "full" for item in results) == 3
    assert not any(item["status"] == "failed" for item in results)


def test_mssql_effective_column_write_and_control_privileges_fail_closed(configured, monkeypatch):
    server = FixtureServer("mssql")
    original = server.response
    monkeypatch.setattr(connectors, "_connect", server.connect)
    for permission, scope in (("CONTROL SERVER", "SERVER"), ("EXECUTE", "DATABASE"), ("UPDATE", "OBJECT")):
        server.response = lambda query, params, permission=permission, scope=scope: [(permission,)] if "fn_my_permissions" in query and params[1] == scope else original(query, params)
        with pytest.raises(connectors.ConnectorError, match="not_read_only"):
            connectors.test_connection("mssql", configured)
