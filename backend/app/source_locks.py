"""Coordinate source database operations across API and worker processes.

Only runtime entry points use these locks: standalone connector checks keep their
existing catalogue-independent API. Source credentials never form part of a key.
"""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import stat

from sqlalchemy import text

from .connectors import DATABASE_KINDS
from .db import engine


class SourceBusy(RuntimeError):
    def __init__(self):
        super().__init__("This database is busy with another connection check or scan. Try again after it finishes.")


def _identity(kind: str, config: dict) -> bytes:
    host = config.get("host")
    database = config.get("database")
    port = config.get("port", {"postgresql": 5432, "mysql": 3306, "mssql": 1433}[kind])
    if not isinstance(host, str) or not host.strip() or not isinstance(database, str) or not database:
        raise ValueError("Invalid database lock identity.")
    if isinstance(port, bool):
        raise ValueError("Invalid database lock identity.")
    try:
        port = int(port)
    except (TypeError, ValueError, OverflowError):
        raise ValueError("Invalid database lock identity.") from None
    if not 1 <= port <= 65535:
        raise ValueError("Invalid database lock identity.")
    # User, password, table and schema are deliberately excluded: two source
    # registrations pointed at the same database must share the same lock.
    value = json.dumps(["hospital-source-database/v1", kind, host.strip().lower(), port, database],
                       ensure_ascii=False, separators=(",", ":")).encode()
    return hashlib.sha256(value).digest()


@contextmanager
def _postgresql_lock(catalog, identity):
    connection = catalog.connect()
    acquired = False
    lock_id = int.from_bytes(identity[:8], "big", signed=True)
    try:
        acquired = connection.execute(text("SELECT pg_try_advisory_lock(CAST(:lock_id AS BIGINT))"),
                                      {"lock_id": lock_id}).scalar() is True
        # This is a session lock. Do not leave a catalogue transaction open for
        # the potentially long source scan; commit does not release the lock.
        connection.commit()
        if not acquired:
            raise SourceBusy()
        yield
    finally:
        try:
            if acquired:
                try:
                    released = connection.execute(text("SELECT pg_advisory_unlock(CAST(:lock_id AS BIGINT))"),
                                                  {"lock_id": lock_id}).scalar() is True
                    if not released:
                        raise RuntimeError("Database operation lock could not be released.")
                    connection.commit()
                except BaseException:
                    # A pooled connection must never retain a session lock.
                    # Invalidation closes the physical backend and its locks.
                    connection.invalidate()
                    raise
        finally:
            connection.close()


@contextmanager
def _sqlite_lock(catalog, identity):
    import fcntl

    database = catalog.url.database
    if not database or database == ":memory:":
        raise ValueError("Database operation locks require a persistent local catalogue.")
    path = Path(database).resolve()
    directory = path.parent / (path.name + ".source-locks")
    directory.mkdir(mode=0o700, exist_ok=True)
    # Never unlink lock files after release: another process may already hold
    # their inode. Names contain only hashes and files contain no source data.
    filename = directory / (identity.hex() + ".lock")
    fd = os.open(filename, os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    acquired = False
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("Invalid database operation lock file.")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            acquired = True
        except BlockingIOError:
            raise SourceBusy() from None
        yield
    finally:
        try:
            if acquired:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


@contextmanager
def source_database_lock(kind: str, config: dict):
    """Acquire one nonblocking cross-process lock for this source database."""
    if kind not in DATABASE_KINDS:
        yield
        return
    identity = _identity(kind, config)
    catalog = engine()
    if catalog.dialect.name == "postgresql":
        lock = _postgresql_lock(catalog, identity)
    elif catalog.dialect.name == "sqlite":
        lock = _sqlite_lock(catalog, identity)
    else:
        raise ValueError("Unsupported catalogue for database operation locking.")
    with lock:
        yield
