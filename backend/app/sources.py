import os
from pathlib import Path, PurePosixPath

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import URL

from .config import settings


def _postgresql_trusted_ca() -> str:
    """Trust belongs to the deployment, never to a submitted source configuration."""
    value = os.getenv("SOURCE_DATABASE_CA_FILE", "")
    path = Path(value)
    if not value or not path.is_absolute() or not path.is_file():
        raise ValueError("Database trusted CA is not configured.")
    return str(path)


def approved_path(raw: str) -> Path:
    if not isinstance(raw, str) or not raw:
        raise ValueError("A source path is required.")
    path = Path(raw).expanduser().resolve()
    roots = [Path(x).resolve() for x in settings().allowed_roots]
    if not any(path == r or path.is_relative_to(r) for r in roots):
        raise ValueError("Source path is outside SOURCE_ALLOWED_ROOTS.")
    return path


def normalize_config(kind: str, config: dict) -> dict:
    if kind in {"mysql", "mssql"}:
        from .database_connectors import normalize_config as normalize_database
        return normalize_database(kind, config)
    if kind in {"s3", "azure_blob", "azure_table"}:
        from .cloud_connectors import normalize_config as normalize_cloud
        return normalize_cloud(kind, config)
    result = dict(config)
    if kind == "filesystem":
        result = {"root": str(approved_path(config.get("root", "")))}
    elif kind == "sqlite":
        if settings().environment != "development":
            raise ValueError("SQLite sources are restricted to development fixtures.")
        result = {"path": str(approved_path(config.get("path", "")))}
    elif kind == "smb":
        server = str(config.get("server", "")).lower()
        if server not in settings().smb_hosts or any(c in server for c in "\\/@:"):
            raise ValueError("SMB server is not in SMB_HOST_ALLOWLIST.")
        share = str(config.get("share", ""))
        subpath = str(config.get("subpath", "")).replace("\\", "/")
        if not share or any(c in share for c in "\\/") or subpath.startswith("/") or ".." in PurePosixPath(subpath).parts:
            raise ValueError("Invalid share or subpath.")
        result = {"server": server, "share": share, "subpath": subpath,
                  "username": str(config.get("username", "")), "password": str(config.get("password", "")),
                  "domain": str(config.get("domain", ""))}
    elif kind == "postgresql":
        host = str(config.get("host", "")).lower()
        if host not in settings().database_hosts or any(c in host for c in "/\\@"):
            raise ValueError("Database host is not in DATABASE_HOST_ALLOWLIST.")
        port = int(config.get("port", 5432))
        if not 1 <= port <= 65535:
            raise ValueError("Invalid database port.")
        tables = config.get("tables", [])
        if not isinstance(tables, list) or len(tables) > 1000 or any(not isinstance(t, str) or len(t) > 128 for t in tables):
            raise ValueError("Tables must be a list of names.")
        result = {k: str(config.get(k, "")) for k in ("host", "database", "username", "password")}
        result.update(port=port, schema=str(config.get("schema", "public")), tables=tables)
        identifier_columns = config.get("patient_identifier_columns", {})
        if not isinstance(identifier_columns, dict) or any(
            not isinstance(k, str) or not isinstance(v, list) or
            any(not isinstance(c, str) or len(c) > 128 for c in v)
            for k, v in identifier_columns.items()
        ):
            raise ValueError("Invalid patient identifier column mapping.")
        result["patient_identifier_columns"] = identifier_columns
        if not result["database"] or not result["username"]:
            raise ValueError("Database and username are required.")
        result["dsn"] = URL.create("postgresql+psycopg", username=result["username"], password=result["password"],
                                   host=host, port=port, database=result["database"],
                                   query={"connect_timeout": "5", "sslmode": "verify-full",
                                          "sslrootcert": _postgresql_trusted_ca(),
                                          "ssl_min_protocol_version": "TLSv1.2",
                                          "gssencmode": "disable"}).render_as_string(hide_password=False)
    return result


def test_connection(kind: str, config: dict) -> dict:
    """Source diagnostics contain no exception strings, query text, or patient values."""
    if kind in {"mysql", "mssql"}:
        from .database_connectors import test_connection as check_database
        return check_database(kind, config)
    if kind in {"s3", "azure_blob", "azure_table"}:
        from .cloud_connectors import test_connection as check_cloud
        return check_cloud(kind, config)
    config = normalize_config(kind, config)
    if kind in ("filesystem", "sqlite"):
        path = approved_path(config["root" if kind == "filesystem" else "path"])
        if kind == "filesystem":
            if not path.is_dir():
                raise ValueError("Source directory is unavailable.")
            iterator = path.iterdir()
            next(iterator, None)
        else:
            if not path.is_file():
                raise ValueError("Fixture database is unavailable.")
            import sqlite3
            with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True) as connection:
                connection.execute("PRAGMA query_only=ON")
                connection.execute("SELECT name FROM sqlite_master WHERE type='table' LIMIT 1").fetchone()
        return {"ok": True, "read_only": True, "safety_validated": True}
    if kind == "smb":
        import smbclient
        from .extraction import private_host
        if not private_host(config["server"]):
            raise ValueError("Source endpoint must be private.")
        username = config["username"]
        if config.get("domain"):
            username = config["domain"] + "\\" + username
        cache = {}
        smbclient.ClientConfig(skip_dfs=True)
        try:
            smbclient.register_session(config["server"], username=username, password=config["password"],
                                       encrypt=True, connection_timeout=5, connection_cache=cache)
            root = "\\\\" + config["server"] + "\\" + config["share"]
            if config.get("subpath"):
                root += "\\" + config["subpath"].replace("/", "\\")
            with smbclient.scandir(root, connection_cache=cache) as entries:
                next(entries, None)
        finally:
            smbclient.reset_connection_cache(connection_cache=cache, fail_on_error=False)
        return {"ok": True, "read_only_operations": True, "safety_validated": True,
                "note": "Confirm the account has read-only source permissions during hospital acceptance."}
    from .extraction import private_host
    if not private_host(config["host"]):
        raise ValueError("Source endpoint must be private.")
    engine = create_engine(config["dsn"], pool_pre_ping=True, hide_parameters=True)
    try:
        with engine.connect() as connection:
            connection.execute(text("SET TRANSACTION READ ONLY"))
            connection.execute(text("SET LOCAL statement_timeout='5s'"))
            connection.execute(text("SET LOCAL lock_timeout='1s'"))
            privileged = connection.execute(text("SELECT rolsuper OR rolcreatedb OR rolcreaterole FROM pg_roles WHERE rolname=current_user")).scalar()
            if privileged:
                raise ValueError("Use a dedicated, unprivileged, read-only database role.")
            tables = config.get("tables") or inspect(connection).get_table_names(schema=config.get("schema", "public"))
            preparer = engine.dialect.identifier_preparer
            for table in tables:
                full = preparer.quote_schema(config.get("schema", "public")) + "." + preparer.quote(table)
                writable = connection.execute(text("SELECT has_table_privilege(current_user, :table, 'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')"), {"table": full}).scalar()
                if writable:
                    raise ValueError("Source role has write privileges on an approved table.")
            connection.rollback()
            connection.execute(text("SET TRANSACTION READ ONLY"))
            connection.execute(text("SET LOCAL statement_timeout='10ms'"))
            try:
                connection.execute(text("SELECT pg_sleep(0.05)"))
            except Exception as exc:
                state = getattr(getattr(exc, "orig", None), "sqlstate", None)
                connection.rollback()
                if state != "57014":
                    raise ValueError("Server-side query cancellation could not be verified.") from None
            else:
                raise ValueError("Server-side query cancellation could not be verified.")
            # Check recovery on the same connection, with bounded read-only commands.
            connection.execute(text("SET TRANSACTION READ ONLY"))
            connection.execute(text("SET LOCAL statement_timeout='5s'"))
            connection.execute(text("SET LOCAL lock_timeout='1s'"))
            if connection.execute(text("SELECT 1")).scalar() != 1:
                raise ValueError("Database recovery after cancellation could not be verified.")
        return {"ok": True, "read_only": True, "cancellation_verified": True, "safety_validated": True}
    finally:
        engine.dispose()
