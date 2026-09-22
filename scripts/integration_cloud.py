#!/usr/bin/env python3
"""Exercise connectors against isolated local TLS MinIO/Azurite fixtures.

Provisioning uses separate administrator clients, never the connector. No real
cloud endpoint is accepted. Credentials are read from a local file, never output.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import socket
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--credentials", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--s3-port", type=int, default=19000)
    parser.add_argument("--blob-port", type=int, default=11000)
    parser.add_argument("--table-port", type=int, default=11002)
    parser.add_argument("--with-presidio", action="store_true", help="Also scan one synthetic record per connector with the local Presidio/spaCy model.")
    args = parser.parse_args()
    credentials = json.loads(args.credentials.read_text())
    ca = credentials["ca_file"]
    if not Path(ca).is_file():
        raise SystemExit("Fixture CA is unavailable.")
    os.environ["CLOUD_HOST_ALLOWLIST"] = "127.0.0.1,fixture.blob.localhost,fixture.table.localhost"
    os.environ["SOURCE_CLOUD_CA_FILE"] = ca
    # Local fixture DNS only; production connector resolution remains unchanged.
    real_dns = socket.getaddrinfo
    def fixture_dns(host, *values, **kwargs):
        if host in {"fixture.blob.localhost", "fixture.table.localhost"}:
            host = "127.0.0.1"
        return real_dns(host, *values, **kwargs)
    socket.getaddrinfo = fixture_dns

    import boto3
    from botocore.config import Config
    from azure.core.credentials import AzureNamedKeyCredential, AzureSasCredential
    from azure.data.tables import TableClient, TableSasPermissions, generate_table_sas
    from azure.storage.blob import BlobServiceClient, ContainerSasPermissions, generate_container_sas
    from app import cloud_connectors as cloud
    from app.detection import Detector
    cloud._quiet_sdk_logs()
    detector = Detector(mode="rules")
    checks = []
    s3_write_denial_verified = False
    diagnostics = []
    original_object_error = cloud._object_error
    def object_error(location, error):
        # Diagnostic types/status only. Never persist exception text, URLs or paths.
        diagnostics.append({"error_type": type(error).__name__, "status_code": getattr(error, "status_code", None)})
        return original_object_error(location, error)
    cloud._object_error = object_error
    def check(name, passed):
        checks.append({"check": name, "passed": bool(passed)})
        if not passed:
            raise AssertionError(name)
    scan = lambda kind, config, options={}: list(cloud.scan(kind, config, options, detector, lambda: "running"))
    token = secrets.token_hex(5)
    content = b"Patient name: Anita Sharma\nUHID: HOSP12345\nDiagnosis: diabetes\nfixture@example.test"
    prefix, bucket, container, table_name = "synthetic-" + token + "/", "discoveryfixture", "discoveryfixture", "Discovery" + token
    s3_url, blob_url, table_url = f"https://127.0.0.1:{args.s3_port}", f"https://fixture.blob.localhost:{args.blob_port}", f"https://fixture.table.localhost:{args.table_port}"
    s3 = boto3.client("s3", endpoint_url=s3_url, aws_access_key_id=credentials["minio_access"],
                      aws_secret_access_key=credentials["minio_secret"], region_name="us-east-1", verify=ca,
                      config=Config(proxies={}, retries={"total_max_attempts": 1}, connect_timeout=5, read_timeout=5,
                                    s3={"addressing_style": "path"}))
    azure_credential = AzureNamedKeyCredential("fixture", credentials["azure_key"])
    # Admin clients deliberately have write access only to local synthetic fixtures.
    from azure.core.pipeline.transport import RequestsTransport
    import requests
    def admin_transport():
        session = requests.Session()
        session.trust_env = False
        return RequestsTransport(session=session, session_owner=True, connection_verify=ca, connection_timeout=5, read_timeout=5)
    blobs = BlobServiceClient(blob_url, credential=azure_credential, transport=admin_transport(), retry_total=0, logging_enable=False)
    tables = TableClient(table_url, table_name=table_name, credential=azure_credential, transport=admin_transport(), retry_total=0, logging_enable=False)
    stage = "provision_s3"
    try:
        try:
            s3.create_bucket(Bucket=bucket)
        except s3.exceptions.BucketAlreadyOwnedByYou:
            pass
        for key, value in {"patient.txt": content, "archive.zip": b"excluded", "unknown.bin": b"unsupported"}.items():
            s3.put_object(Bucket=bucket, Key=prefix + key, Body=value)
        s3_config = {"endpoint_url": s3_url, "region": "us-east-1", "bucket": bucket, "prefix": prefix,
                     "auth_mode": "access_key", "access_key_id": credentials.get("minio_reader_access", credentials["minio_access"]),
                     "secret_access_key": credentials.get("minio_reader_secret", credentials["minio_secret"])}
        stage = "check_s3"
        check("s3_tls_connection_read_list", cloud.test_connection("s3", s3_config)["read_only_operations"])
        s3_result = scan("s3", s3_config)
        actual = next(row for row in s3_result if row["location"].endswith("patient.txt"))
        check("s3_download_detection", actual["status"] == "full" and any(f["entity_type"] == "EMAIL_ADDRESS" for f in actual["findings"]))
        check("s3_exclusions_accounted", {row["status"] for row in s3_result} >= {"full", "excluded", "unsupported"})
        check("s3_no_raw_values", "fixture@example.test" not in json.dumps(s3_result))
        check("s3_listing_limit_visible", scan("s3", s3_config, {"max_files": 1})[-1]["reason"] == "object_limit_reached")
        evidence = scan("s3", s3_config, {"capture_evidence": True})
        check("s3_opt_in_evidence", any(e["value"] == "fixture@example.test" for row in evidence for f in row["findings"] for e in f.get("evidence", [])))
        if credentials.get("minio_reader_access"):
            # Separate fixture probe; production connector has no write method.
            probe = boto3.client("s3", endpoint_url=s3_url, aws_access_key_id=s3_config["access_key_id"],
                                  aws_secret_access_key=s3_config["secret_access_key"], region_name="us-east-1", verify=ca,
                                  config=Config(proxies={}, retries={"total_max_attempts": 1}, s3={"addressing_style": "path"}))
            try:
                probe.put_object(Bucket=bucket, Key=prefix + "denied.txt", Body=b"synthetic")
            except Exception as error:
                s3_write_denial_verified = getattr(error, "response", {}).get("ResponseMetadata", {}).get("HTTPStatusCode") == 403
            finally:
                probe.close()
            check("s3_reader_rejects_write", s3_write_denial_verified)

        stage = "provision_azure_blob"
        try:
            blobs.create_container(container)
        except Exception as error:
            if getattr(error, "status_code", None) != 409:
                raise
        blobs.get_blob_client(container, prefix + "patient.txt").upload_blob(content, overwrite=False)
        expiry = datetime.now(timezone.utc) + timedelta(hours=1)
        blob_sas = generate_container_sas("fixture", container, account_key=credentials["azure_key"],
                                           permission=ContainerSasPermissions(read=True, list=True), expiry=expiry, protocol="https")
        blob_config = {"account_url": blob_url, "container": container, "prefix": prefix, "sas_token": blob_sas}
        stage = "check_azure_blob"
        check("azure_blob_tls_read_list_sas", cloud.test_connection("azure_blob", blob_config)["read_only_operations"])
        blob_result = scan("azure_blob", blob_config)
        diagnostics.extend({"kind": "azure_blob", "status": row["status"], "reason": row["reason"]} for row in blob_result)
        check("azure_blob_download_detection", blob_result[0]["status"] == "full" and any(f["entity_type"] == "EMAIL_ADDRESS" for f in blob_result[0]["findings"]))
        check("azure_blob_no_raw_values", "fixture@example.test" not in json.dumps(blob_result))
        # Deliberate write-denial check uses a separate SDK client, not connector code.
        reader = BlobServiceClient(blob_url, credential=blob_sas, transport=admin_transport(), retry_total=0, logging_enable=False)
        denied = False
        try:
            reader.get_blob_client(container, prefix + "denied.txt").upload_blob(b"synthetic")
        except Exception as error:
            denied = getattr(error, "status_code", None) == 403
        finally:
            reader.close()
        check("azure_blob_read_sas_rejects_write", denied)

        stage = "provision_azure_table"
        tables.create_table()
        stage = "provision_azure_table_entities"
        # Individual fixture writes avoid Azurite's product-style-host batch URL
        # issue. They are isolated admin provisioning, not connector operations.
        for i in range(1002):
            entity = {"PartitionKey": "Synthetic", "RowKey": f"{i:05d}", "notes": "diagnosis: diabetes" if i % 2 else "nonclinical"}
            if i % 2 == 0:
                entity["MRN"] = "HOSP12345"
            if i == 0:
                entity["email"] = "fixture@example.test"
                entity["patient_name"] = "Anita Sharma"
                entity["UHID"] = "HOSP12345"
            tables.create_entity(entity)
        table_sas = generate_table_sas(azure_credential, table_name, permission=TableSasPermissions(read=True), expiry=expiry, protocol="https")
        table_config = {"account_url": table_url, "table": table_name, "partition_key": "Synthetic", "sas_token": table_sas}
        stage = "check_azure_table"
        check("azure_table_tls_read_sas", cloud.test_connection("azure_table", table_config)["read_only_operations"])
        table_result = scan("azure_table", table_config)
        check("azure_table_1000_entity_sampling", len(table_result) == 1001 and table_result[-1]["status"] == "sampled" and table_result[-1]["examined"] == 1000)
        check("azure_table_entity_boundaries", all(f["classification"] != "patient_linked_health" for row in table_result for f in row["findings"]))
        check("azure_table_no_raw_keys_or_values", "fixture@example.test" not in json.dumps(table_result) and "Synthetic" not in json.dumps(table_result))
        check("azure_table_all_inspected_entities_stable", all(row["metadata"].get("source_stable") for row in table_result[:-1]))
        check("azure_table_full_scan_disabled", scan("azure_table", table_config, {"full_scan": True})[0]["status"] == "excluded")
        table_reader = TableClient(table_url, table_name=table_name, credential=AzureSasCredential(table_sas),
                                   transport=admin_transport(), retry_total=0, logging_enable=False)
        denied = False
        try:
            table_reader.create_entity({"PartitionKey": "Synthetic", "RowKey": "denied", "notes": "synthetic"})
        except Exception as error:
            denied = getattr(error, "status_code", None) == 403
        finally:
            table_reader.close()
        check("azure_table_read_sas_rejects_write", denied)
        if args.with_presidio:
            stage = "presidio_functional_smoke"
            detector = Detector(mode="presidio")
            for kind, source_config in (("s3", {**s3_config, "prefix": prefix + "patient.txt"}),
                                        ("azure_blob", {**blob_config, "prefix": prefix + "patient.txt"}),
                                        ("azure_table", table_config)):
                result = scan(kind, source_config, {"table_sample_rows": 1, "max_files": 1})
                entities = {finding["entity_type"] for row in result for finding in row["findings"]}
                check(kind + "_presidio_name_email_uhid", {"PERSON", "EMAIL_ADDRESS", "UHID"} <= entities)
    except Exception as error:
        # Third-party exceptions can contain signed URLs, so emit only fixed text.
        code = getattr(error, "error_code", None) or getattr(getattr(error, "error", None), "code", None)
        code = str(code) if code is not None else None
        if code is not None and not re.fullmatch(r"[A-Za-z0-9_.]{1,80}", code):
            code = "unrecognized"
        checks.append({"check": "fixture_run_completed", "passed": False, "stage": stage,
                       "error_type": type(error).__name__, "status_code": getattr(error, "status_code", None),
                       "error_code": code})
    finally:
        for client in (s3, blobs, tables):
            client.close()
        socket.getaddrinfo = real_dns
        cloud._object_error = original_object_error
        report = {"synthetic": True, "hospital_validated": False, "cloud_provider_validated": False,
                  "detector_mode": "rules", "fixtures": ["MinIO HTTPS", "Azurite Blob HTTPS", "Azurite Table HTTPS"],
                  "presidio_smoke_requested": args.with_presidio,
                  "s3_grant_restrictions_verified": s3_write_denial_verified,
                  "all_passed": bool(checks) and all(item["passed"] for item in checks), "checks": checks,
                  "diagnostics": diagnostics}
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"checks": len(checks), "all_passed": report["all_passed"]}))
    return 0 if report["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
