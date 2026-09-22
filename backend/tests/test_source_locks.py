import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from app import source_locks as locks


CONFIG = {"host": "db.internal", "database": "hospital", "username": "reader",
          "password": "not-a-real-secret", "schema": "public"}


@pytest.fixture
def local_catalog(monkeypatch, tmp_path):
    catalog = SimpleNamespace(dialect=SimpleNamespace(name="sqlite"),
                              url=SimpleNamespace(database=str(tmp_path / "catalog.db")))
    monkeypatch.setattr(locks, "engine", lambda: catalog)
    return catalog


@pytest.mark.parametrize("kind", ["postgresql", "mysql", "mssql"])
def test_local_database_lock_contends_across_sources_but_not_databases(local_catalog, kind):
    with locks.source_database_lock(kind, CONFIG):
        with pytest.raises(locks.SourceBusy):
            with locks.source_database_lock(kind, {**CONFIG, "host": "DB.INTERNAL", "username": "different-user",
                                                   "password": "different-secret", "schema": "other",
                                                   "tables": ["other_table"], "dsn": "ignored-secret"}):
                pytest.fail("One database must not admit a second operation.")
        with locks.source_database_lock(kind, {**CONFIG, "database": "other_database"}):
            pass
    with locks.source_database_lock(kind, CONFIG):
        pass


def test_local_database_lock_releases_on_failure_and_contains_no_identifiers(local_catalog):
    with pytest.raises(RuntimeError, match="fixture failure"):
        with locks.source_database_lock("postgresql", CONFIG):
            raise RuntimeError("fixture failure")
    with locks.source_database_lock("postgresql", CONFIG):
        pass
    directory = Path(local_catalog.url.database + ".source-locks")
    assert directory.stat().st_mode & 0o777 == 0o700
    files = list(directory.iterdir())
    assert len(files) == 1 and files[0].read_bytes() == b""
    assert files[0].stat().st_mode & 0o777 == 0o600
    assert len(files[0].stem) == 64
    assert all(value not in files[0].name for value in CONFIG.values())


def test_sqlite_lock_contends_between_processes(local_catalog):
    # A thread-only mutex would falsely pass ordinary TestClient tests.
    code = """
import json, sys
from types import SimpleNamespace
from app import source_locks as locks
locks.engine = lambda: SimpleNamespace(dialect=SimpleNamespace(name='sqlite'), url=SimpleNamespace(database=sys.argv[1]))
config = json.loads(sys.stdin.read())
try:
    with locks.source_database_lock('postgresql', config):
        print('acquired')
except locks.SourceBusy:
    print('busy')
"""
    def child():
        return subprocess.run([sys.executable, "-c", code, local_catalog.url.database],
                              input=json.dumps(CONFIG), text=True, capture_output=True, check=True, timeout=10)
    with locks.source_database_lock("postgresql", CONFIG):
        blocked = child()
        assert blocked.stdout.strip() == "busy" and blocked.stderr == ""
    assert child().stdout.strip() == "acquired"


@pytest.mark.parametrize("kind", ["filesystem", "smb", "s3", "azure_blob", "azure_table", "sqlite"])
def test_nondatabase_sources_do_not_require_a_catalog_lock(monkeypatch, kind):
    monkeypatch.setattr(locks, "engine", lambda: pytest.fail("Non-database source accessed catalogue locks"))
    with locks.source_database_lock(kind, {}):
        pass


class PostgresConnection:
    def __init__(self, available=True, unlock_error=False):
        self.available, self.unlock_error = available, unlock_error
        self.operations = []
        self.closed = self.invalidated = False

    def execute(self, query, params):
        sql = str(query)
        self.operations.append((sql, params))
        if "pg_try_advisory_lock" in sql:
            return SimpleNamespace(scalar=lambda: self.available)
        if self.unlock_error:
            raise RuntimeError("fixture unlock failed")
        return SimpleNamespace(scalar=lambda: True)

    def commit(self):
        self.operations.append(("commit", {}))

    def invalidate(self):
        self.invalidated = True

    def close(self):
        self.closed = True


def postgres_catalog(monkeypatch, connection):
    monkeypatch.setattr(locks, "engine", lambda: SimpleNamespace(
        dialect=SimpleNamespace(name="postgresql"), connect=lambda: connection))


@pytest.mark.parametrize("operation_fails", [False, True])
def test_postgres_lock_releases_session_lock_and_closes_connection(monkeypatch, operation_fails):
    connection = PostgresConnection()
    postgres_catalog(monkeypatch, connection)
    try:
        with locks.source_database_lock("postgresql", CONFIG):
            assert len(connection.operations) == 2  # Commit before long source work.
            if operation_fails:
                raise ValueError("fixture operation failed")
    except ValueError:
        assert operation_fails
    statements = [sql for sql, _ in connection.operations]
    assert "pg_try_advisory_lock" in statements[0]
    assert "pg_advisory_unlock" in statements[2]
    assert statements[1] == statements[3] == "commit"
    assert connection.operations[0][1] == connection.operations[2][1]
    assert isinstance(connection.operations[0][1]["lock_id"], int)
    assert CONFIG["password"] not in repr(connection.operations)
    assert connection.closed and not connection.invalidated


def test_postgres_lock_busy_does_not_unlock_someone_elses_session(monkeypatch):
    connection = PostgresConnection(available=False)
    postgres_catalog(monkeypatch, connection)
    with pytest.raises(locks.SourceBusy) as failure:
        with locks.source_database_lock("postgresql", CONFIG):
            pytest.fail("Busy database entered source operation")
    assert connection.closed
    assert not any("pg_advisory_unlock" in sql for sql, _ in connection.operations)
    assert all(value not in str(failure.value) for value in CONFIG.values())


def test_postgres_unlock_failure_invalidates_physical_connection(monkeypatch):
    connection = PostgresConnection(unlock_error=True)
    postgres_catalog(monkeypatch, connection)
    with pytest.raises(RuntimeError, match="fixture unlock failed"):
        with locks.source_database_lock("postgresql", CONFIG):
            pass
    assert connection.closed and connection.invalidated


@pytest.mark.parametrize("change", [{"host": ""}, {"database": ""}, {"port": True}, {"port": "bad"}, {"port": 0}])
def test_invalid_lock_identity_fails_without_source_details(local_catalog, change):
    with pytest.raises(ValueError, match="^Invalid database lock identity\\.$"):
        with locks.source_database_lock("postgresql", {**CONFIG, **change}):
            pass
