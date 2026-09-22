#!/usr/bin/env python3
"""Exercise only disposable loopback SQL fixtures, never hospital endpoints.

Provisioning uses fixed hospital_fixture objects and separate fixture administrator
credentials. Connector checks use dedicated reader/writer accounts. Output contains
only check names and success/failure, never credentials, SQL or driver diagnostics.
"""
import argparse
import json
import logging
import os
from pathlib import Path
import sys
import time
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
from app import database_connectors as adapters
from app.detection import Detector


def provision(kind, secrets, port):
    adapters._quiet_driver_logs()
    if kind == "mysql":
        import pymysql
        connection = pymysql.connect(host="127.0.0.1", port=port, user="root", password=secrets["mysql_admin"],
                                     ssl_ca=secrets["ca_file"], ssl_verify_cert=True, ssl_verify_identity=True, autocommit=True)
        cursor = connection.cursor()
        cursor.execute("CREATE DATABASE IF NOT EXISTS hospital_fixture")
        cursor.execute("CREATE USER IF NOT EXISTS 'hospital_reader'@'%%' IDENTIFIED BY %s", (secrets["reader"],))
        cursor.execute("CREATE USER IF NOT EXISTS 'hospital_writer'@'%%' IDENTIFIED BY %s", (secrets["writer"],))
        cursor.execute("GRANT SELECT ON hospital_fixture.* TO 'hospital_reader'@'%'")
        cursor.execute("GRANT SELECT,INSERT ON hospital_fixture.* TO 'hospital_writer'@'%'")
        cursor.execute("DROP VIEW IF EXISTS hospital_fixture.visits_view")
        cursor.execute("DROP TABLE IF EXISTS hospital_fixture.visits")
        cursor.execute("CREATE TABLE hospital_fixture.visits (id INTEGER PRIMARY KEY, mrn VARCHAR(32), diagnosis TEXT, notes TEXT, attachment BLOB) ENGINE=InnoDB")
        cursor.executemany("INSERT INTO hospital_fixture.visits VALUES (%s,%s,%s,%s,%s)",
                           [(i, f"SYNTHETIC-{i:05}", "diabetes", f"synthetic-{i}@example.test", None) for i in range(2500)])
        cursor.execute("CREATE VIEW hospital_fixture.visits_view AS SELECT id FROM hospital_fixture.visits")
    else:
        import pytds
        connection = pytds.connect(server="localhost", port=port, user="sa", password=secrets["mssql_admin"],
                                   cafile=secrets["ca_file"], validate_host=True, enc_login_only=False, autocommit=True, timeout=5)
        cursor = connection.cursor()
        cursor.execute("IF DB_ID(N'hospital_fixture') IS NULL CREATE DATABASE hospital_fixture")
        for name, password in (("hospital_reader", secrets["reader"]), ("hospital_writer", secrets["writer"])):
            # SQL Server CREATE LOGIN does not allow a bind variable as its password.
            quoted_password = "'" + password.replace("'", "''") + "'"
            cursor.execute(f"IF SUSER_ID(N'{name}') IS NULL CREATE LOGIN [{name}] WITH PASSWORD={quoted_password}, CHECK_POLICY=OFF")
        cursor.execute("USE hospital_fixture")
        for name in ("hospital_reader", "hospital_writer"):
            cursor.execute(f"IF USER_ID(N'{name}') IS NULL CREATE USER [{name}] FOR LOGIN [{name}]")
        cursor.execute("GRANT SELECT TO hospital_reader")
        cursor.execute("GRANT SELECT,INSERT TO hospital_writer")
        cursor.execute("DROP VIEW IF EXISTS dbo.visits_view")
        cursor.execute("DROP TABLE IF EXISTS dbo.visits")
        cursor.execute("CREATE TABLE dbo.visits (id INTEGER PRIMARY KEY, mrn VARCHAR(32), diagnosis NVARCHAR(MAX), notes NVARCHAR(MAX), attachment VARBINARY(MAX))")
        cursor.executemany("INSERT INTO dbo.visits VALUES (%s,%s,%s,%s,%s)",
                           [(i, f"SYNTHETIC-{i:05}", "diabetes", f"synthetic-{i}@example.test", None) for i in range(2500)])
        cursor.execute("CREATE VIEW dbo.visits_view AS SELECT id FROM dbo.visits")
    cursor.close()
    return connection


def run(kind, secrets, port, checks, real_detector=None):
    admin = provision(kind, secrets, port)
    config = {"host": "127.0.0.1" if kind == "mysql" else "localhost", "port": port, "database": "hospital_fixture",
              "username": "hospital_reader", "password": secrets["reader"]}
    detector = Detector("rules")

    def check(label, predicate):
        passed = bool(predicate())
        checks.append({"kind": kind, "check": label, "passed": passed})
        if not passed:
            raise AssertionError(label)

    def rejected(candidate):
        try:
            adapters.test_connection(kind, candidate)
        except adapters.ConnectorError:
            return True
        return False

    try:
        result = adapters.test_connection(kind, config)
        check("verified_tls_readonly_cancellation_and_recovery", lambda: all(result.get(key) is True for key in ("ok", "read_only", "tls_verified", "cancellation_verified")))
        if kind == "mssql":
            ip_result = adapters.test_connection(kind, {**config, "host": "127.0.0.1"})
            check("certificate_ip_san_verified", lambda: ip_result["tls_verified"] is True)
            def wrong_hostname_rejected():
                import socket
                import pytds
                # Fixed loopback socket tests a name mismatch without resolving or
                # connecting to the deliberately incorrect name.
                sock = socket.create_connection(("127.0.0.1", port), timeout=5)
                connection = None
                try:
                    connection = pytds.connect(server="wrong.invalid", port=port, sock=sock,
                                               user="hospital_reader", password=secrets["reader"],
                                               cafile=secrets["ca_file"], validate_host=True,
                                               enc_login_only=False, disable_connect_retry=True,
                                               login_timeout=5, timeout=5)
                except pytds.tds_base.Error as exc:
                    return "Certificate does not match host name" in str(exc)
                finally:
                    if connection is not None:
                        connection.close()
                    sock.close()
                return False
            check("trusted_certificate_wrong_hostname_rejected", wrong_hostname_rejected)
        check("write_capable_account_rejected", lambda: rejected({**config, "username": "hospital_writer", "password": secrets["writer"]}))
        import certifi
        os.environ["SOURCE_DATABASE_CA_FILE"] = certifi.where()
        try:
            check("untrusted_certificate_rejected", lambda: rejected(config))
        finally:
            os.environ["SOURCE_DATABASE_CA_FILE"] = secrets["ca_file"]
        sampled = list(adapters.scan(kind, config, {}, detector, lambda: "running"))
        check("sample_1000_rows_with_binary_and_view_gaps", lambda: sum(item["status"] == "sampled" and item["examined"] == 1000 for item in sampled) == 4
              and any(item["reason"] == "database_views_not_scanned" for item in sampled)
              and any(item["reason"] == "binary_column_not_inspected" for item in sampled))
        full_config = {**config, "tables": ["visits"], "full_scan_allowed": True}
        complete = list(adapters.scan(kind, full_config, {"full_scan": True}, detector, lambda: "running"))
        check("approved_full_scan_2500_rows", lambda: sum(item["status"] == "full" and item["examined"] == 2500 for item in complete) == 4)
        calls = 0
        def cancel():
            nonlocal calls
            calls += 1
            return "running" if calls < 130 else "cancelled"
        cancelled = list(adapters.scan(kind, full_config, {"full_scan": True}, detector, cancel))
        check("midstream_cancel_reports_partial", lambda: any(item["reason"] == "scan_cancelled" and item["examined"] > 0 for item in cancelled))
        locker = admin.cursor()
        if kind == "mysql":
            locker.execute("LOCK TABLES hospital_fixture.visits WRITE")
        else:
            locker.execute("BEGIN TRANSACTION")
            locker.execute("SELECT TOP (1) id FROM dbo.visits WITH (TABLOCKX, HOLDLOCK)")
            locker.fetchall()
        start = time.monotonic()
        try:
            locked = list(adapters.scan(kind, {**config, "tables": ["visits"]}, {}, detector, lambda: "running"))
            check("lock_timeout_fails_without_full_claim", lambda: time.monotonic() - start < 7 and any(item["status"] == "failed" for item in locked)
                  and all(item["status"] != "full" for item in locked))
        finally:
            locker.execute("UNLOCK TABLES" if kind == "mysql" else "ROLLBACK TRANSACTION")
            locker.close()
        recovered = list(adapters.scan(kind, {**config, "tables": ["visits"]}, {}, detector, lambda: "running"))
        check("new_scan_recovers_after_lock_timeout", lambda: any(item["status"] == "sampled" for item in recovered))
        if real_detector is not None:
            detected = list(adapters.scan(kind, {**config, "tables": ["visits"]},
                                         {"table_sample_rows": 1, "capture_evidence": True},
                                         real_detector, lambda: "running"))
            check("presidio_one_row_actual_match_evidence", lambda: any(
                finding["entity_type"] == "EMAIL_ADDRESS" and
                any(example["value"] == "synthetic-0@example.test" for example in finding.get("evidence", []))
                for item in detected for finding in item["findings"]
            ))
    finally:
        admin.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--credentials", type=Path, required=True)
    parser.add_argument("--kind", choices=["mysql", "mssql", "both"], default="both")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--presidio", action="store_true", help="Also run one row through the installed production NLP model")
    args = parser.parse_args()
    secrets = json.loads(args.credentials.read_text())
    os.environ["SOURCE_DATABASE_CA_FILE"] = secrets["ca_file"]
    # The runner is deliberately locked to localhost and fixed synthetic ports.
    adapters.settings = lambda: SimpleNamespace(database_hosts=("127.0.0.1", "localhost"))
    real_detector = Detector("presidio") if args.presidio else None
    checks = []
    for kind, port in (("mysql", 13306), ("mssql", 11433)):
        if args.kind not in (kind, "both"):
            continue
        try:
            run(kind, secrets, port, checks, real_detector)
        except Exception as exc:
            checks.append({"kind": kind, "check": "integration_completed", "passed": False,
                           "error_type": type(exc).__name__})
    result = {"synthetic_only": True, "checks": checks, "passed": bool(checks) and all(item["passed"] for item in checks)}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
