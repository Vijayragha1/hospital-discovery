#!/usr/bin/env python3
"""Exercise a disposable synthetic PostgreSQL source; never contacts hospital systems."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))


def command(*args):
    return subprocess.run(args, text=True, capture_output=True, check=True).stdout.strip()


def create_fixture_certificates(directory: Path):
    """Short-lived test-only certificate material; never reuse for a deployment."""
    from datetime import datetime, timedelta, timezone
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    now = datetime.now(timezone.utc)

    def ca(common_name):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                       .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=5))
                       .not_valid_after(now + timedelta(days=1))
                       .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                       .sign(key, hashes.SHA256()))
        return key, certificate

    ca_key, trusted = ca("Synthetic PostgreSQL fixture CA")
    _, untrusted = ca("Independent untrusted fixture CA")
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server = (x509.CertificateBuilder()
              .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fixture-postgres")]))
              .issuer_name(trusted.subject).public_key(server_key.public_key())
              .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=5))
              .not_valid_after(now + timedelta(days=1))
              .add_extension(x509.SubjectAlternativeName([x509.DNSName("fixture-postgres")]), critical=False)
              .sign(ca_key, hashes.SHA256()))
    directory.chmod(0o755)
    for filename, certificate in [("ca.pem", trusted), ("untrusted-ca.pem", untrusted), ("server.crt", server)]:
        (directory / filename).write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        (directory / filename).chmod(0o644)
    # The non-root disposable PostgreSQL process copies this to its private tmpfs
    # with mode 0600 before starting. No real credentials or client data are present.
    (directory / "server.key").write_bytes(server_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    (directory / "server.key").chmod(0o644)



def orchestrate(args):
    """Neither PostgreSQL nor the checker publishes a host port or has internet egress."""
    suffix = secrets.token_hex(5)
    network, container = "discovery-test-net-" + suffix, "discovery-test-pg-" + suffix
    client = "discovery-test-client-" + suffix
    password = secrets.token_hex(24)
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = tempfile.TemporaryDirectory(prefix="discovery-postgres-tls-")
    trust = Path(temporary.name)
    try:
        create_fixture_certificates(trust)
        command("docker", "network", "create", "--internal", network)
        command("docker", "run", "--detach", "--pull=never", "--platform", args.platform, "--name", container,
                "--network", network, "--network-alias", "fixture-postgres", "--network-alias", "fixture-wronghost",
                "--user", "70:70", "--read-only",
                "--cap-drop=ALL", "--security-opt", "no-new-privileges:true", "--memory", "512m", "--pids-limit", "128",
                "--tmpfs", "/var/lib/postgresql/data:rw,nosuid,noexec,size=256m,uid=70,gid=70",
                "--tmpfs", "/var/run/postgresql:rw,nosuid,noexec,size=16m,uid=70,gid=70",
                "--tmpfs", "/tmp:rw,nosuid,noexec,size=32m,uid=70,gid=70",
                "--mount", "type=bind,src=" + str(trust) + ",dst=/fixture-trust,readonly",
                "--env", "POSTGRES_USER=fixture_admin", "--env", "POSTGRES_DB=synthetic",
                "--env", "POSTGRES_PASSWORD=" + password, "--entrypoint", "sh", args.image, "-c",
                "umask 077; cp /fixture-trust/server.key /tmp/server.key; "
                "exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/fixture-trust/server.crt "
                "-c ssl_key_file=/tmp/server.key -c ssl_ca_file=/fixture-trust/ca.pem")
        # Source and utility mounts use the latest code even before the final image rebuild.
        # Recover a value-free JSON report from stdout; no host write mount is needed.
        result = subprocess.run([
            "docker", "run", "--pull=never", "--platform", args.platform, "--name", client,
            "--network", network, "--user", "10001:10001", "--read-only", "--cap-drop=ALL",
            "--security-opt", "no-new-privileges:true", "--memory", "3g", "--pids-limit", "128",
            "--tmpfs", "/tmp:rw,nosuid,noexec,size=128m,uid=10001,gid=10001",
            "--mount", "type=bind,src=" + str(ROOT / "backend") + ",dst=/app/backend,readonly",
            "--mount", "type=bind,src=" + str(ROOT / "scripts") + ",dst=/app/scripts,readonly",
            "--mount", "type=bind,src=" + str(trust / "ca.pem") + ",dst=/fixture-ca.pem,readonly",
            "--mount", "type=bind,src=" + str(trust / "untrusted-ca.pem") + ",dst=/fixture-untrusted-ca.pem,readonly",
            "--env", "FIXTURE_PASSWORD=" + password,
            "--entrypoint", "python", args.client_image,
            "/app/scripts/integration_postgres.py", "--inside-client", "--output", "/tmp/postgres-integration.json",
        ], text=True, capture_output=True)
        if result.stdout:
            print(result.stdout.strip())
        if result.stderr:
            print(result.stderr.replace(password, "[redacted]")[:2000], file=sys.stderr)
        # The stopped container retains the tmpfs only while alive, so the report is also
        # emitted as a marker by the checker and recovered below from captured stdout.
        marker = "INTEGRATION_REPORT="
        reports = [line[len(marker):] for line in result.stdout.splitlines() if line.startswith(marker)]
        if reports:
            output.write_text(json.dumps(json.loads(reports[-1]), indent=2) + "\n")
        return result.returncode
    except Exception as exc:
        diagnostic = getattr(exc, "stderr", "") or str(exc)
        print(diagnostic.replace(password, "[redacted]")[:1500], file=sys.stderr)
        return 2
    finally:
        subprocess.run(["docker", "rm", "--force", client], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["docker", "rm", "--force", container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["docker", "network", "rm", network], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        temporary.cleanup()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="postgres:17-alpine", help="Already-loaded local image; pulling disabled")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--platform", default="linux/amd64")
    parser.add_argument("--client-image", default="hospital-discovery-api:pilot", help="Already-loaded API image for isolated checker")
    parser.add_argument("--inside-client", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if not args.inside_client:
        return orchestrate(args)
    from sqlalchemy import create_engine, text
    from sqlalchemy.engine import URL
    from sqlalchemy.pool import NullPool
    from cryptography.fernet import Fernet
    from app.config import settings
    from app.detection import Detector
    from app.scanning import scan_source
    from app import source_locks
    from app.sources import normalize_config, test_connection

    password = os.environ["FIXTURE_PASSWORD"]
    started = time.monotonic()
    checks = {}
    engine = None
    reader_engine = None
    try:
        os.environ.update({"APP_SECRET_KEY": Fernet.generate_key().decode(), "SESSION_SECRET": secrets.token_hex(32),
                           "DATABASE_URL": "sqlite:////tmp/fixture-catalog.db", "ENVIRONMENT": "development",
                           "DETECTOR_MODE": "rules", "SOURCE_DATABASE_CA_FILE": "/fixture-ca.pem",
                           "DATABASE_HOST_ALLOWLIST": "fixture-postgres,fixture-wronghost"})
        settings.cache_clear()
        admin_url = URL.create("postgresql+psycopg", username="fixture_admin", password=password,
            host="fixture-postgres", port=5432, database="synthetic", query={"sslmode": "verify-full",
            "sslrootcert": "/fixture-ca.pem", "connect_timeout": "5", "gssencmode": "disable"})
        engine = create_engine(admin_url, poolclass=NullPool, hide_parameters=True)
        deadline = time.monotonic() + 45
        while True:
            try:
                with engine.connect() as connection:
                    connection.execute(text("SELECT 1"))
                break
            except Exception:
                if time.monotonic() >= deadline:
                    raise RuntimeError("Synthetic PostgreSQL startup failed") from None
                time.sleep(.25)
        checks["nonroot_readonly_container_startup"] = True
        with engine.begin() as connection:
            connection.execute(text("CREATE ROLE fixture_reader LOGIN PASSWORD '" + password + "'"))
            connection.execute(text("CREATE TABLE patients (patient_id INTEGER PRIMARY KEY, email TEXT)"))
            connection.execute(text("CREATE TABLE encounters (id INTEGER PRIMARY KEY, patient_id INTEGER REFERENCES patients(patient_id), diagnosis TEXT)"))
            connection.execute(text("INSERT INTO patients SELECT n, 'synthetic' || n || '@example.invalid' FROM generate_series(1, 2500) AS n"))
            connection.execute(text("INSERT INTO encounters SELECT n, n, 'Diagnosis: hypertension' FROM generate_series(1, 2500) AS n"))
            connection.execute(text("GRANT USAGE ON SCHEMA public TO fixture_reader"))
            connection.execute(text("GRANT SELECT ON patients, encounters TO fixture_reader"))
        submitted = {"host": "fixture-postgres", "port": 5432, "database": "synthetic", "username": "fixture_reader",
                     "password": password, "schema": "public", "tables": ["patients", "encounters"]}
        config = normalize_config("postgresql", submitted)
        dsn = config["dsn"]
        # Use this isolated fixture's PostgreSQL as the coordination catalogue.
        # Each acquisition opens a separate real session (the fixture uses NullPool).
        original_lock_engine = source_locks.engine
        source_locks.engine = lambda: engine
        try:
            with source_locks.source_database_lock("postgresql", config):
                began = time.monotonic()
                try:
                    with source_locks.source_database_lock("postgresql", {
                            **config, "username": "another_reader", "password": "ignored", "schema": "other"}):
                        checks["catalog_lock_blocks_same_database_across_accounts"] = False
                except source_locks.SourceBusy:
                    checks["catalog_lock_blocks_same_database_across_accounts"] = time.monotonic() - began < 2
                with source_locks.source_database_lock("postgresql", {**config, "database": "independent"}):
                    checks["catalog_lock_allows_other_databases"] = True
            try:
                with source_locks.source_database_lock("postgresql", config):
                    raise ValueError("synthetic source failure")
            except ValueError:
                pass
            with source_locks.source_database_lock("postgresql", config):
                checks["catalog_lock_released_after_failure"] = True
        finally:
            source_locks.engine = original_lock_engine
        safety = test_connection("postgresql", submitted)
        checks["verified_tls_readonly_cancellation_and_recovery"] = all(
            safety.get(key) is True for key in ("ok", "read_only", "cancellation_verified", "safety_validated"))
        for check, changed, trust_file, messages in [
            ("trusted_certificate_wrong_hostname_rejected", {**submitted, "host": "fixture-wronghost"}, "/fixture-ca.pem",
             ("does not match host name", "hostname mismatch")),
            ("untrusted_certificate_rejected", submitted, "/fixture-untrusted-ca.pem",
             ("certificate verify failed", "unable to get local issuer")),
        ]:
            os.environ["SOURCE_DATABASE_CA_FILE"] = trust_file
            began = time.monotonic()
            try:
                test_connection("postgresql", changed)
                checks[check] = False
            except Exception as failure:
                # Inspect locally without emitting URLs or driver messages. A DNS,
                # permission or unrelated error must not count as TLS validation.
                diagnostic = str(getattr(failure, "orig", failure)).lower()
                checks[check] = time.monotonic() - began < 7 and any(value in diagnostic for value in messages)
            finally:
                os.environ["SOURCE_DATABASE_CA_FILE"] = "/fixture-ca.pem"
        reader_engine = create_engine(dsn, poolclass=NullPool, hide_parameters=True)
        try:
            with reader_engine.begin() as connection:
                connection.execute(text("DELETE FROM patients WHERE patient_id = 1"))
            checks["write_denied_by_grants"] = False
        except Exception:
            checks["write_denied_by_grants"] = True
        with reader_engine.connect() as connection:
            with connection.begin():
                connection.execute(text("SET TRANSACTION READ ONLY"))
                checks["transaction_read_only"] = connection.execute(text("SHOW transaction_read_only")).scalar_one() == "on"
                checks["source_session_uses_tls"] = connection.execute(text(
                    "SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()")).scalar_one() is True
        timed_out = False
        began = time.monotonic()
        try:
            with reader_engine.begin() as connection:
                connection.execute(text("SET LOCAL statement_timeout = '100ms'"))
                connection.execute(text("SELECT pg_sleep(3)"))
        except Exception:
            timed_out = time.monotonic() - began < 2
        checks["server_statement_timeout_cancels_query"] = timed_out
        config["full_scan_allowed"] = True
        detector = Detector(mode="rules")
        sampled = list(scan_source("postgresql", config, {"table_sample_rows": 1000, "batch_size": 100}, detector, lambda: "running"))
        checks["sampled_coverage_and_cap"] = bool(sampled) and all(o["status"] == "sampled" and o["examined"] == 1000 for o in sampled)
        checks["email_detected"] = any(f["entity_type"] == "EMAIL_ADDRESS" for o in sampled for f in o["findings"])
        checks["patient_linked_health_detected"] = any(f["classification"] == "patient_linked_health" for o in sampled for f in o["findings"])
        full = list(scan_source("postgresql", config, {"full_scan": True, "batch_size": 100}, detector, lambda: "running"))
        checks["gated_full_scan_reads_all_rows"] = bool(full) and all(o["status"] == "full" and o["examined"] == 2500 for o in full)
        cancelled = list(scan_source("postgresql", config, {}, detector, lambda: "cancelled"))
        checks["cancelled_scan_is_partial"] = bool(cancelled) and all(o["status"] == "partial" for o in cancelled)
        with engine.connect() as connection:
            checks["source_records_unchanged"] = connection.execute(text("SELECT count(*) FROM patients")).scalar_one() == 2500
        report = {"synthetic": True, "hospital_validated": False, "checks": checks,
                  "all_passed": all(checks.values()), "elapsed_seconds": round(time.monotonic() - started, 2),
                  "sampled_object_count": len(sampled), "full_object_count": len(full),
                  "note": "Fixture-only operational checks; no hospital accuracy or workload claim"}
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n")
        print("INTEGRATION_REPORT=" + json.dumps(report))
        return 0 if report["all_passed"] else 1
    except Exception as exc:
        # Do not print connection URLs, SQL parameters or secrets.
        print("Synthetic PostgreSQL integration failed; inspect local fixture setup and dependency availability.", file=sys.stderr)
        print("Failure type: " + type(exc).__name__, file=sys.stderr)
        return 2
    finally:
        if reader_engine:
            reader_engine.dispose()
        if engine:
            engine.dispose()


if __name__ == "__main__":
    sys.exit(main())
