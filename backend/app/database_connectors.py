"""Bounded MySQL 8 and SQL Server adapters; no source writes or raw diagnostics.

TLS trust is deployment configuration, never a browser-supplied arbitrary file.
SQL Server enforces read-only effective permissions, not a fictitious read-only
transaction: its ApplicationIntent routing flag alone is not an authorization gate.
"""
from __future__ import annotations

import logging
import hashlib
import math
import os
import re
import time
from pathlib import Path

from .config import settings
from .extraction import private_host


KINDS = {"mysql", "mssql"}
MAX_TABLES = 1000
MAX_COLUMNS = 1024
MAX_PERMISSIONS = 1024
MAX_ROW_TEXT_BYTES = 1024 * 1024
MAX_BATCH_TEXT_BYTES = 8 * 1024 * 1024
TDS_TLS_SHA256 = "e7a0a1ef8ef72f86966ba605514354b61917ab8acaadf968be8cfb4a1db3033f"
TDS_INIT_SHA256 = "4903a27c3811c27d9b41925fc16a6799c6edc86942ddd7c4b08685d0b1b78b73"


class ConnectorError(ValueError):
    """Only fixed, non-sensitive diagnostic codes may leave a connector."""


def _text(value, maximum=128, required=True):
    if not isinstance(value, str) or (required and not value.strip()) or len(value) > maximum or "\x00" in value:
        raise ConnectorError("invalid_database_configuration")
    return value


def normalize_config(kind: str, config: dict) -> dict:
    if kind not in KINDS or not isinstance(config, dict):
        raise ConnectorError("unsupported_database_kind")
    host = _text(config.get("host", ""), 253).strip().lower()
    if host not in settings().database_hosts or any(char in host for char in "/\\@:#?\n\r"):
        raise ConnectorError("database_host_not_approved")
    port = config.get("port", 3306 if kind == "mysql" else 1433)
    if isinstance(port, bool):
        raise ConnectorError("invalid_database_port")
    try:
        port = int(port)
    except (ValueError, TypeError, OverflowError):
        raise ConnectorError("invalid_database_port") from None
    if not 1 <= port <= 65535:
        raise ConnectorError("invalid_database_port")
    database = _text(config.get("database", ""))
    schema = _text(config.get("schema") or (database if kind == "mysql" else "dbo"))
    if kind == "mysql" and schema != database:
        raise ConnectorError("mysql_schema_must_equal_database")
    tables = config.get("tables", [])
    if not isinstance(tables, list) or len(tables) > MAX_TABLES:
        raise ConnectorError("invalid_table_scope")
    tables = list(dict.fromkeys(_text(value) for value in tables))
    identifiers = config.get("patient_identifier_columns", {})
    if not isinstance(identifiers, dict) or len(identifiers) > MAX_TABLES:
        raise ConnectorError("invalid_patient_identifier_mapping")
    mapping = {}
    for table, columns in identifiers.items():
        _text(table)
        if not isinstance(columns, list) or len(columns) > MAX_COLUMNS:
            raise ConnectorError("invalid_patient_identifier_mapping")
        mapping[table] = [_text(column) for column in columns]
    return {"host": host, "port": port, "database": database, "schema": schema, "tables": tables,
            "username": _text(config.get("username", ""), 256),
            "password": _text(config.get("password", ""), 4096, required=False),
            "patient_identifier_columns": mapping}


def _ca_file():
    value = os.getenv("SOURCE_DATABASE_CA_FILE", "")
    path = Path(value)
    if not value or not path.is_absolute() or not path.is_file():
        raise ConnectorError("database_trusted_ca_not_configured")
    return str(path)


def _quiet_driver_logs():
    # Child loggers with explicit DEBUG levels ignore the parent logger's level.
    names = {"pytds", "pytds.login", "pytds.sspi", "pytds.tds_socket",
             "pytds.tls", "pytds.smp"}
    names.update(name for name in list(logging.Logger.manager.loggerDict)
                 if name.startswith("pytds."))
    for name in names:
        logger = logging.getLogger(name)
        logger.setLevel(logging.CRITICAL + 1)
        logger.propagate = False


def _connect(kind, config, timeout=5):
    if not private_host(config["host"]):
        raise ConnectorError("database_endpoint_not_private")
    ca = _ca_file()
    if kind == "mysql":
        import pymysql
        return pymysql.connect(host=config["host"], port=config["port"], database=config["database"],
                               user=config["username"], password=config["password"], charset="utf8mb4",
                               ssl_ca=ca, ssl_verify_cert=True, ssl_verify_identity=True,
                               local_infile=False, autocommit=True, connect_timeout=5,
                               read_timeout=timeout, write_timeout=timeout)
    import pytds
    import pytds.tls
    if (hashlib.sha256(Path(pytds.tls.__file__).read_bytes()).hexdigest() != TDS_TLS_SHA256
            or hashlib.sha256(Path(pytds.__file__).read_bytes()).hexdigest() != TDS_INIT_SHA256):
        raise ConnectorError("mssql_tls_compatibility_patch_required")
    # pytds can log SQL and parameter representations at DEBUG. Suppress those logs.
    _quiet_driver_logs()
    return pytds.connect(server=config["host"], port=config["port"], database=config["database"],
                         user=config["username"], password=config["password"], cafile=ca,
                         validate_host=True, enc_login_only=False, readonly=True,
                         login_timeout=5, timeout=timeout, autocommit=True, use_mars=False,
                         pooling=False, disable_connect_retry=True, appname="HospitalDiscovery")


def _close(connection):
    if connection is not None:
        try:
            connection.close()
        except Exception:
            pass


def _cursor(connection, kind):
    if kind == "mysql":
        from pymysql.cursors import SSCursor
        return connection.cursor(SSCursor)
    return connection.cursor()


def _abort_cursor(connection, cursor, kind):
    """Discard a result without consuming the remaining source rows."""
    _close(connection)
    if cursor is None:
        return
    if kind == "mysql":
        # SSCursor.close() and MySQLResult.__del__ normally drain the network.
        # After transport closure their result must be marked inactive, otherwise
        # cleanup attempts to read the closed transport and emits raw exceptions.
        result = getattr(cursor, "_result", None)
        if result is not None:
            result.unbuffered_active = False
            result.connection = None
    try:
        cursor.close()
    except Exception:
        pass


def _query(connection, kind, query, parameters=(), limit=MAX_PERMISSIONS):
    cursor = _cursor(connection, kind)
    try:
        cursor.execute(query, parameters)
        rows = []
        while len(rows) <= limit:
            batch = cursor.fetchmany(min(100, limit + 1 - len(rows)))
            if not batch:
                return rows
            rows.extend(batch)
        # Never drain an unexpectedly large unbuffered result merely to close it.
        raise ConnectorError("database_metadata_limit_reached")
    except Exception:
        _abort_cursor(connection, cursor, kind)
        cursor = None
        raise
    finally:
        if cursor is not None:
            try:
                cursor.close()
            except Exception:
                pass


def _statement(connection, kind, query):
    cursor = _cursor(connection, kind)
    try:
        cursor.execute(query)
    finally:
        cursor.close()


def _quote(kind, identifier):
    return "`" + identifier.replace("`", "``") + "`" if kind == "mysql" else "[" + identifier.replace("]", "]]") + "]"


def _qualified(kind, schema, table):
    return _quote(kind, schema) + "." + _quote(kind, table)


def _configure(connection, kind, options):
    statement = options["statement_timeout_ms"]
    lock = options["lock_timeout_ms"]
    if kind == "mysql":
        _statement(connection, kind, f"SET SESSION max_execution_time={statement}")
        _statement(connection, kind, f"SET SESSION innodb_lock_wait_timeout={max(1, math.ceil(lock / 1000))}")
        _statement(connection, kind, "SET SESSION lock_wait_timeout=1")
        _statement(connection, kind, "SET SESSION TRANSACTION READ ONLY")
    else:
        _statement(connection, kind, f"SET LOCK_TIMEOUT {lock}")
        _statement(connection, kind, "SET TRANSACTION ISOLATION LEVEL READ COMMITTED")


def _validate_permissions(connection, kind, config, table=None):
    if kind == "mysql":
        version = _query(connection, kind, "SELECT VERSION()", limit=1)[0][0]
        if "mariadb" in str(version).lower() or not re.match(r"(?:8|9)\.", str(version)):
            raise ConnectorError("mysql_version_not_supported")
        cipher = _query(connection, kind, "SHOW SESSION STATUS LIKE 'Ssl_cipher'", limit=1)
        if not cipher or not cipher[0][1]:
            raise ConnectorError("database_tls_not_verified")
        # Role expansion varies by server configuration. Fail closed rather than
        # overlooking role/mandatory-role write privileges in this initial adapter.
        roles = _query(connection, kind, "SELECT CURRENT_ROLE()", limit=1)
        if not roles or roles[0][0] != "NONE":
            raise ConnectorError("mysql_requires_direct_read_only_grants")
        grants = _query(connection, kind, "SHOW GRANTS", limit=MAX_PERMISSIONS)
        if not grants:
            raise ConnectorError("database_permissions_unverified")
        for row in grants:
            # SELECT(column) is deliberately not accepted until effective column
            # permissions have a separately validated implementation.
            match = re.fullmatch(r"GRANT ([A-Z ,]+) ON .+ TO .+", str(row[0]))
            if not match or "WITH GRANT OPTION" in str(row[0]):
                raise ConnectorError("mysql_requires_direct_read_only_grants")
            if not set(match.group(1).split(", ")) <= {"USAGE", "SELECT", "SHOW VIEW"}:
                raise ConnectorError("database_account_not_read_only")
        return
    version = _query(connection, kind, "SELECT CAST(SERVERPROPERTY('ProductMajorVersion') AS int)", limit=1)
    if not version or not isinstance(version[0][0], int) or version[0][0] < 13:
        raise ConnectorError("mssql_version_not_supported")
    scopes = [(None, "SERVER", {"CONNECT SQL", "VIEW ANY DATABASE", "VIEW ANY DEFINITION", "VIEW SERVER STATE"}),
              (None, "DATABASE", {"CONNECT", "SELECT", "VIEW DEFINITION", "VIEW DATABASE STATE",
                                  "VIEW ANY COLUMN MASTER KEY DEFINITION", "VIEW ANY COLUMN ENCRYPTION KEY DEFINITION"})]
    if table is not None:
        scopes.append((_qualified(kind, config["schema"], table), "OBJECT", {"SELECT", "VIEW DEFINITION"}))
    for securable, scope, allowed in scopes:
        query = "SELECT permission_name FROM sys.fn_my_permissions(%s, %s)"
        permissions = _query(connection, kind, query, (securable, scope))
        if not permissions or any(str(row[0]).upper() not in allowed for row in permissions):
            raise ConnectorError("database_account_not_read_only")


def _inventory(connection, kind, config):
    params = [config["schema"]]
    scope = ""
    if config["tables"]:
        scope = " AND TABLE_NAME IN (" + ",".join("%s" for _ in config["tables"]) + ")"
        params.extend(config["tables"])
    if kind == "mysql":
        query = "SELECT TABLE_NAME,TABLE_TYPE,ENGINE FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA=%s" + scope + " ORDER BY TABLE_NAME LIMIT 1001"
    else:
        query = "SELECT TOP (1001) TABLE_NAME,TABLE_TYPE,NULL FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA=%s" + scope + " ORDER BY TABLE_NAME"
    return _query(connection, kind, query, tuple(params), limit=MAX_TABLES + 1)


def _columns(connection, kind, config, table):
    schema = config["schema"]
    if kind == "mysql":
        columns = _query(connection, kind, "SELECT COLUMN_NAME,DATA_TYPE FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=%s AND TABLE_NAME=%s ORDER BY ORDINAL_POSITION LIMIT 1025", (schema, table), limit=MAX_COLUMNS)
        keys = _query(connection, kind, "SELECT COLUMN_NAME,REFERENCED_TABLE_NAME,REFERENCED_COLUMN_NAME,CONSTRAINT_NAME FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA=%s AND TABLE_NAME=%s ORDER BY ORDINAL_POSITION LIMIT 1025", (schema, table), limit=MAX_COLUMNS)
        pk = [row[0] for row in keys if row[3] == "PRIMARY"]
        foreign_keys = [{"constrained_columns": [row[0]], "referred_table": row[1], "referred_columns": [row[2]]}
                        for row in keys if row[1]]
        binary_types = {"binary", "varbinary", "tinyblob", "blob", "mediumblob", "longblob", "geometry", "point", "linestring", "polygon", "multipoint", "multilinestring", "multipolygon", "geometrycollection"}
    else:
        name = _qualified(kind, schema, table)
        columns = _query(connection, kind, "SELECT TOP (1025) c.name,t.name FROM sys.columns c JOIN sys.types t ON c.user_type_id=t.user_type_id WHERE c.object_id=OBJECT_ID(%s) ORDER BY c.column_id", (name,), limit=MAX_COLUMNS)
        pk = [row[0] for row in _query(connection, kind, "SELECT TOP (1025) c.name FROM sys.indexes i JOIN sys.index_columns ic ON i.object_id=ic.object_id AND i.index_id=ic.index_id JOIN sys.columns c ON c.object_id=ic.object_id AND c.column_id=ic.column_id WHERE i.object_id=OBJECT_ID(%s) AND i.is_primary_key=1 ORDER BY ic.key_ordinal", (name,), limit=MAX_COLUMNS)]
        keys = _query(connection, kind, "SELECT TOP (1025) pc.name,rt.name,rc.name FROM sys.foreign_key_columns f JOIN sys.columns pc ON pc.object_id=f.parent_object_id AND pc.column_id=f.parent_column_id JOIN sys.tables rt ON rt.object_id=f.referenced_object_id JOIN sys.columns rc ON rc.object_id=f.referenced_object_id AND rc.column_id=f.referenced_column_id WHERE f.parent_object_id=OBJECT_ID(%s)", (name,), limit=MAX_COLUMNS)
        foreign_keys = [{"constrained_columns": [row[0]], "referred_table": row[1], "referred_columns": [row[2]]} for row in keys]
        supported_types = {"char", "varchar", "nchar", "nvarchar", "text", "ntext", "xml", "bigint", "int", "smallint", "tinyint", "bit", "decimal", "numeric", "money", "smallmoney", "float", "real", "date", "datetime", "datetime2", "smalldatetime", "datetimeoffset", "time", "uniqueidentifier"}
        binary_types = {str(row[1]).lower() for row in columns} - supported_types
    if not columns:
        raise ConnectorError("table_columns_not_visible")
    return [row[0] for row in columns], {row[0] for row in columns if str(row[1]).lower() in binary_types}, pk, foreign_keys


def _timeout_error(kind, exception):
    if kind == "mysql":
        return bool(exception.args and exception.args[0] in {3024, 1317})
    import pytds
    return isinstance(exception, pytds.tds_base.TimeoutError)


def test_connection(kind: str, config: dict) -> dict:
    connection = None
    try:
        config = normalize_config(kind, config)
        connection = _connect(kind, config, timeout=5)
        _configure(connection, kind, {"statement_timeout_ms": 5000, "lock_timeout_ms": 1000})
        _validate_permissions(connection, kind, config)
        tables = _inventory(connection, kind, config)
        if len(tables) > MAX_TABLES:
            raise ConnectorError("database_inventory_limit_requires_narrower_scope")
        if set(config["tables"]) - {row[0] for row in tables}:
            raise ConnectorError("selected_table_not_visible")
        for table, table_type, _ in tables:
            if table_type != "BASE TABLE":
                continue
            if kind == "mssql":
                _validate_permissions(connection, kind, config, table)
            # Reading zero rows verifies SELECT access without inspecting patient data.
            _query(connection, kind, "SELECT " + ("TOP (0) " if kind == "mssql" else "") + "* FROM " + _qualified(kind, config["schema"], table) + (" LIMIT 0" if kind == "mysql" else ""), limit=0)
        if kind == "mssql":
            # Keep routine permission/catalog checks at the normal query timeout.
            # The disposable short-timeout session only exercises cancellation.
            _close(connection)
            connection = _connect(kind, config, timeout=.1)
        cursor = _cursor(connection, kind)
        try:
            if kind == "mysql":
                _statement(connection, kind, "SET SESSION max_execution_time=10")
            try:
                cursor.execute("SELECT SLEEP(0.2)" if kind == "mysql" else "WAITFOR DELAY '00:00:00.300'")
                if kind == "mysql":
                    row = cursor.fetchone()
                    # MySQL SLEEP alone reports 1 when interrupted instead of raising.
                    if not row or row[0] != 1:
                        raise ConnectorError("database_cancellation_unverified")
                else:
                    raise ConnectorError("database_cancellation_unverified")
            except ConnectorError:
                raise
            except Exception as exc:
                if not _timeout_error(kind, exc):
                    raise ConnectorError("database_cancellation_unverified") from None
                if kind == "mssql":
                    cursor.cancel()
        finally:
            cursor.close()
        if _query(connection, kind, "SELECT 1", limit=1) != [(1,)]:
            raise ConnectorError("database_connection_recovery_unverified")
        return {"ok": True, "read_only": True, "safety_validated": True, "cancellation_verified": True,
                "tls_verified": True, "read_only_enforcement": "transaction_and_grants" if kind == "mysql" else "effective_permissions"}
    except ConnectorError:
        raise
    except Exception:
        raise ConnectorError("database_connection_or_safety_check_failed") from None
    finally:
        _close(connection)


def _data_query(kind, config, table, columns, binary, pk, options):
    limit = min(options["max_text_chars"], 65536) + 1
    projection = []
    for column in columns:
        quoted = _quote(kind, column)
        cast = f"LEFT(CAST({quoted} AS CHAR CHARACTER SET utf8mb4), {limit})" if kind == "mysql" else f"LEFT(CONVERT(nvarchar(max), {quoted}), {limit})"
        projection.append(("NULL" if column in binary else cast) + " AS " + quoted)
    top = f"TOP ({options['table_sample_rows'] + 1}) " if kind == "mssql" and not options["full_scan"] else ""
    query = "SELECT " + top + ", ".join(projection) + " FROM " + _qualified(kind, config["schema"], table)
    if pk:
        query += " ORDER BY " + ", ".join(_quote(kind, column) for column in pk)
    if kind == "mysql" and not options["full_scan"]:
        query += f" LIMIT {options['table_sample_rows'] + 1}"
    return query


def _projection_options(columns, binary, options):
    """Bound even wide-table rows before the database serializes their contents."""
    text_columns = max(1, len(columns) - len(binary))
    # Four bytes per Unicode character bounds both UTF-8 and Python's widest form.
    cell_limit = min(options["max_text_chars"], 65536, MAX_ROW_TEXT_BYTES // (4 * text_columns) - 1)
    row_bytes = 4 * text_columns * (cell_limit + 1)
    return {**options, "max_text_chars": cell_limit,
            "batch_size": min(options["batch_size"], max(1, MAX_BATCH_TEXT_BYTES // row_bytes))}


def scan(kind: str, config: dict, options: dict, detector, control):
    from .scanning import _column_results, _database_location, _object, _options, _patient_columns
    connection = None
    try:
        options = _options(options)
        if options["statement_timeout_ms"] > 5000 or options["lock_timeout_ms"] > 1000:
            raise ConnectorError("database_timeout_limit_exceeded")
        if options["full_scan"] and (config.get("full_scan_allowed") is not True or not config.get("tables")):
            yield _object("[database]", "excluded", "full_scan_requires_approved_explicit_tables", unit="rows")
            return
        config = normalize_config(kind, config)
        if control() != "running":
            yield _object("[database]", "partial", "scan_cancelled", unit="rows")
            return
        connection = _connect(kind, config, timeout=options["statement_timeout_ms"] / 1000)
        _configure(connection, kind, options)
        _validate_permissions(connection, kind, config)
        inventory = _inventory(connection, kind, config)
        if len(inventory) > MAX_TABLES:
            yield _object("[inventory]", "partial", "database_table_inventory_limit", unit="rows")
            inventory = inventory[:MAX_TABLES]
        for table in sorted(set(config["tables"]) - {row[0] for row in inventory}):
            yield _object(_database_location(config["schema"], table), "inaccessible", "requested_table_not_discovered", unit="rows")
        for table, table_type, engine in inventory:
            location = _database_location(config["schema"], table)
            if control() != "running":
                yield _object(location, "partial", "scan_cancelled", unit="rows")
                return
            if table_type != "BASE TABLE":
                yield _object(location, "excluded", "database_views_not_scanned", unit="rows")
                continue
            if kind == "mysql" and str(engine).lower() != "innodb":
                yield _object(location, "unsupported", "mysql_storage_engine_not_supported", unit="rows")
                continue
            cursor = None
            try:
                if connection is None:
                    connection = _connect(kind, config, timeout=options["statement_timeout_ms"] / 1000)
                    _configure(connection, kind, options)
                _validate_permissions(connection, kind, config, table)
                columns, binary, pk, foreign_keys = _columns(connection, kind, config, table)
                table_options = _projection_options(columns, binary, options)
                patient_columns, linkage = _patient_columns(table, foreign_keys, config)
                if kind == "mysql":
                    _statement(connection, kind, "START TRANSACTION READ ONLY")
                cursor = _cursor(connection, kind)
                remaining = options["statement_timeout_ms"] / 1000

                def db_call(operation, *arguments):
                    nonlocal remaining
                    if remaining <= 0:
                        raise ConnectorError("database_stream_deadline_reached")
                    started = time.monotonic()
                    try:
                        return operation(*arguments)
                    finally:
                        # Detector/NLP processing between calls is not database time.
                        remaining -= time.monotonic() - started

                db_call(cursor.execute, _data_query(kind, config, table, columns, binary, pk, table_options))

                def rows():
                    while True:
                        batch = db_call(cursor.fetchmany, table_options["batch_size"])
                        if not batch:
                            return
                        yield from batch

                # Pausing DB scans releases the transaction instead of retaining locks.
                db_control = lambda: "running" if control() == "running" else "cancelled"
                yield from _column_results(location, columns, rows(), options=table_options, detector=detector,
                                           control=db_control, metadata={"read_only": True, "tls_verified": True,
                                           "ordered_by_primary_key": bool(pk), "patient_linkage_evidence": linkage,
                                           "statement_timeout_ms": options["statement_timeout_ms"],
                                           "lock_timeout_ms": options["lock_timeout_ms"],
                                           "fetch_batch_size": table_options["batch_size"],
                                           "wide_table_cell_limit_applied": table_options["max_text_chars"] < min(options["max_text_chars"], 65536),
                                           "read_only_enforcement": "transaction_and_grants" if kind == "mysql" else "effective_permissions",
                                           "timeout_enforcement": "server_max_execution_time" if kind == "mysql" else "tds_attention_and_db_call_budget"},
                                           binary_columns=binary, patient_columns=patient_columns)
            except Exception:
                yield _object(location, "failed", "table_query_or_detection_failed", unit="rows")
            finally:
                # Closing transport first avoids SSCursor.close draining a cancelled
                # full-table result. The next table gets a fresh checked connection.
                _abort_cursor(connection, cursor, kind)
                connection = None
    except ConnectorError as exc:
        yield _object("[database]", "failed", str(exc), unit="rows")
    except Exception:
        yield _object("[database]", "failed", "database_connection_or_inventory_failed", unit="rows")
    finally:
        _close(connection)
