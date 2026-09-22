"""Synthetic SDK fixtures: never connect to hospital or cloud resources."""
import io
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from urllib.parse import urlencode

import pytest

from app import cloud_connectors as cloud
from app.detection import Detector


def sas(kind="azure_blob", **overrides):
    fields = {"sv": "2023-11-03", "sig": "synthetic", "spr": "https", "sp": "rl" if kind == "azure_blob" else "r",
              "se": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(), **({"sr": "c"} if kind == "azure_blob" else {"tn": "Patients"})}
    fields.update(overrides)
    return urlencode(fields)


@pytest.fixture(autouse=True)
def private_dns(monkeypatch):
    monkeypatch.setenv("CLOUD_HOST_ALLOWLIST", "cloud.test")
    monkeypatch.setattr(cloud.socket, "getaddrinfo", lambda *args, **kwargs: [(2, 1, 6, "", ("10.20.0.5", 443))])


def config(kind="s3", **overrides):
    value = ({"endpoint_url": "https://cloud.test", "bucket": "patients", "prefix": "", "access_key_id": "synthetic-access", "secret_access_key": "synthetic-secret"}
             if kind == "s3" else {"account_url": "https://cloud.test", "container" if kind == "azure_blob" else "table": "patients" if kind == "azure_blob" else "Patients", "sas_token": sas(kind)})
    value.update(overrides)
    return value


@pytest.mark.parametrize("url", ["http://cloud.test", "https://cloud.test/account", "https://cloud.test?sig=secret", "https://user:pass@cloud.test", "https://elsewhere.test", "https://cloud.test#part"])
def test_endpoint_rejects_unsafe_origin(url):
    with pytest.raises(ValueError):
        cloud.normalize_config("s3", config(endpoint_url=url))


@pytest.mark.parametrize("address", ["8.8.8.8", "169.254.169.254", "0.0.0.0", "224.0.0.1", "100.64.0.1"])
def test_public_or_metadata_dns_rejected(monkeypatch, address):
    monkeypatch.setattr(cloud.socket, "getaddrinfo", lambda *args, **kwargs: [(2, 1, 6, "", (address, 443))])
    with pytest.raises(ValueError):
        cloud.normalize_config("s3", config())


def test_credentials_and_unknown_fields_not_accepted_for_role():
    value = cloud.normalize_config("s3", config(auth_mode="iam_role", credential_process="bad", verify=False))
    assert "secret_access_key" not in value and "verify" not in value and "credential_process" not in value


@pytest.mark.parametrize("fields", [{"sp": "rwdl"}, {"si": "stored-policy"}, {"ss": "b"}, {"spr": "https,http"}, {"sr": "b"}, {"se": "2000-01-01T00:00:00Z"}])
def test_sas_requires_explicit_read_only_scope(fields):
    with pytest.raises(ValueError):
        cloud.normalize_config("azure_blob", config("azure_blob", sas_token=sas(**fields)))


def test_table_sas_scope_and_permissions():
    assert cloud.normalize_config("azure_table", config("azure_table"))["table"] == "Patients"
    with pytest.raises(ValueError):
        cloud.normalize_config("azure_table", config("azure_table", sas_token=sas("azure_table", tn="OtherTable")))


@pytest.mark.parametrize("url,method", [("https://elsewhere.test/data", "GET"), ("https://cloud.test/data", "PUT"), ("https://cloud.test:444/data", "GET")])
def test_redirects_and_mutations_fail_before_network(url, method):
    with pytest.raises(ValueError):
        cloud._guard_request("https://cloud.test", url, method)


class S3:
    def __init__(self, objects=None):
        self.objects = objects or {"patient.txt": b"UHID: HOSP12345\nDiagnosis: diabetes\ncontact@example.test"}
        self.closed = False
        self.bodies = []
        self.calls = []

    def list_objects_v2(self, **kwargs):
        self.calls.append(("list", kwargs))
        return {"Contents": [{"Key": key, "Size": len(value), "ETag": '"v1"'} for key, value in self.objects.items()], "IsTruncated": False}

    def get_object(self, **kwargs):
        self.calls.append(("get", kwargs))
        body = io.BytesIO(self.objects[kwargs["Key"]])
        self.bodies.append(body)
        return {"Body": body, "ContentLength": len(self.objects[kwargs["Key"]]), "ETag": '"v1"'}

    def head_object(self, **kwargs):
        self.calls.append(("head", kwargs))
        return {"ContentLength": len(self.objects[kwargs["Key"]]), "ETag": '"v1"'}

    def close(self):
        self.closed = True


def scan_s3(monkeypatch, client, options=None, control=lambda: "running"):
    monkeypatch.setattr(cloud, "_s3_client", lambda config: client)
    return list(cloud.scan("s3", config(), options or {}, Detector(mode="rules"), control))


def test_s3_conditional_reads_and_no_raw_values(monkeypatch):
    client = S3()
    objects = scan_s3(monkeypatch, client)
    assert objects[0]["status"] == "full" and objects[-1]["metadata"]["listing_complete"]
    assert any(f["entity_type"] == "EMAIL_ADDRESS" for f in objects[0]["findings"])
    assert "contact@example.test" not in json.dumps(objects)
    assert all(args["IfMatch"] == '"v1"' for name, args in client.calls if name in {"get", "head"})
    assert client.closed and all(body.closed for body in client.bodies)


def test_s3_opt_in_evidence(monkeypatch):
    objects = scan_s3(monkeypatch, S3(), {"capture_evidence": True})
    assert any(e["value"] == "contact@example.test" for f in objects[0]["findings"] for e in f.get("evidence", []))


def test_large_archive_and_unknown_do_not_download(monkeypatch):
    client = S3({"a.txt": b"x" * 11, "b.zip": b"data", "c.unknown": b"data"})
    result = scan_s3(monkeypatch, client, {"max_file_bytes": 10})
    assert [o["status"] for o in result[:-1]] == ["excluded", "excluded", "unsupported"]
    assert not any(method == "get" for method, _ in client.calls)


def test_max_objects_reports_coverage_gap(monkeypatch):
    result = scan_s3(monkeypatch, S3({"a.txt": b"one", "b.txt": b"two"}), {"max_files": 1})
    assert result[-1]["status"] == "partial" and result[-1]["reason"] == "object_limit_reached"


def test_changed_etag_never_complete(monkeypatch):
    client = S3()
    client.head_object = lambda **kwargs: {"ETag": '"v2"', "ContentLength": 1}
    result = scan_s3(monkeypatch, client)
    assert result[0]["status"] == "partial" and result[0]["reason"] == "object_changed_during_scan"


def test_listing_errors_are_redacted(monkeypatch):
    client = S3()
    def fail(**kwargs):
        raise RuntimeError("patient@example.test?sig=TOP_SECRET")
    client.list_objects_v2 = fail
    result = scan_s3(monkeypatch, client)
    assert result[-1]["status"] == "inaccessible" and "TOP_SECRET" not in json.dumps(result)
    assert client.closed


def test_cancelled_download_closes_body(monkeypatch):
    client = S3()
    states = iter(["running", "running", "running", "cancelled", "cancelled"])
    result = scan_s3(monkeypatch, client, control=lambda: next(states, "cancelled"))
    assert result[0]["reason"] == "scan_cancelled"
    assert client.closed and client.bodies[0].closed


class Paged:
    def __init__(self, values):
        self.values = values
    def __iter__(self):
        return iter(self.values)
    def by_page(self):
        for index in range(0, len(self.values), 100):
            yield iter(self.values[index:index + 100])


class Entity(dict):
    metadata = {"etag": '"v1"'}


class Azure:
    def __init__(self, entities):
        self.entities = entities
        self.closed = False
        self.queries = []
    def list_entities(self, **kwargs):
        self.queries.append(kwargs)
        return Paged(self.entities)
    def query_entities(self, *args, **kwargs):
        self.queries.append((args, kwargs))
        return Paged(self.entities)
    def get_entity(self, partition, row, **kwargs):
        return next(e for e in self.entities if e["PartitionKey"] == partition and e["RowKey"] == row)
    def close(self):
        self.closed = True


def test_table_limit_and_entity_boundaries(monkeypatch):
    entities = [Entity(PartitionKey="Synthetic", RowKey=str(i), **({"MRN": "HOSP12345"} if i % 2 == 0 else {"notes": "diagnosis: diabetes"})) for i in range(1001)]
    client = Azure(entities)
    monkeypatch.setattr(cloud, "_azure_client", lambda *args: client)
    result = list(cloud.scan("azure_table", config("azure_table"), {}, Detector(mode="rules"), lambda: "running"))
    assert len(result) == 1001 and result[-1]["status"] == "sampled" and result[-1]["examined"] == 1000
    assert all(f["classification"] != "patient_linked_health" for row in result for f in row["findings"])
    assert "Synthetic" not in json.dumps(result)
    assert client.closed


@pytest.mark.parametrize("location", ["s3/bucket/record.pdf", "azure/container/record.pdf"])
def test_cloud_document_unverified_layout_cannot_create_patient_links(monkeypatch, location):
    from app.extraction import ExtractionResult
    monkeypatch.setattr("app.extraction.extract_bytes", lambda *args: ExtractionResult(
        text="MRN: SYN100; diagnosis: diabetes", status="partial",
        metadata={"patient_linkage_context_verified": False}))
    result = cloud._extract(location, b"synthetic", 9, "fixture-etag", {"capture_evidence": False}, Detector("rules"))
    assert any(item["entity_type"] == "MRN" for item in result["findings"])
    health = next(item for item in result["findings"] if item["entity_type"] == "HEALTH_INFORMATION")
    assert health["classification"] == "clinical_content"
    assert health["reason"] == "clinical_content_with_unverified_patient_layout"
    assert all("evidence" not in item for item in result["findings"])


def test_table_partition_parameter_and_evidence(monkeypatch):
    entity = Entity(PartitionKey="a'b", RowKey="sensitive-id", email="test@example.test")
    client = Azure([entity])
    monkeypatch.setattr(cloud, "_azure_client", lambda *args: client)
    result = list(cloud.scan("azure_table", config("azure_table", partition_key="a'b"), {"capture_evidence": True}, Detector(mode="rules"), lambda: "running"))
    assert client.queries[0][1]["parameters"] == {"partition": "a'b"}
    assert "sensitive-id" not in result[0]["location"]
    assert any(e["value"] == "test@example.test" for f in result[0]["findings"] for e in f.get("evidence", []))


def test_table_rejects_full_scan_without_network(monkeypatch):
    monkeypatch.setattr(cloud, "_azure_client", lambda *args: pytest.fail("Client must not be created"))
    result = list(cloud.scan("azure_table", config("azure_table"), {"full_scan": True}, Detector(mode="rules"), lambda: "running"))
    assert result[0]["reason"] == "azure_table_full_scan_not_supported"


def test_blob_uses_conditional_reads(monkeypatch):
    content = b"contact@example.test"
    entry = SimpleNamespace(name="patient.txt", size=len(content), etag='"v1"')
    calls = []
    class Blob:
        def download_blob(self, **kwargs):
            calls.append(kwargs)
            return SimpleNamespace(chunks=lambda: iter([content]))
        def get_blob_properties(self, **kwargs):
            calls.append(kwargs)
            # Actual Azure/Azurite list XML and HTTP HEAD differ in quote syntax.
            return SimpleNamespace(size=len(content), etag="v1")
    class Container:
        closed = False
        def list_blobs(self, **kwargs):
            return Paged([entry])
        def get_blob_client(self, name):
            return Blob()
        def close(self):
            self.closed = True
    client = Container()
    monkeypatch.setattr(cloud, "_azure_client", lambda *args: client)
    result = list(cloud.scan("azure_blob", config("azure_blob"), {}, Detector(mode="rules"), lambda: "running"))
    assert result[0]["status"] == "full" and client.closed
    assert all(call["etag"] == '"v1"' for call in calls)
    assert "contact@example.test" not in json.dumps(result)


def test_strong_etag_quote_normalization_does_not_ignore_version_changes():
    assert cloud._same_etag('"v1"', "v1")
    assert not cloud._same_etag('"v1"', '"v2"')
    assert not cloud._same_etag('W/"v1"', '"v1"')
    assert not cloud._same_etag(None, None)


def test_connection_closes_client_and_returns_read_operations(monkeypatch):
    client = S3()
    monkeypatch.setattr(cloud, "_s3_client", lambda config: client)
    result = cloud.test_connection("s3", config())
    assert result["ok"] and result["read_only_operations"] and result["safety_validated"]
    assert "read_only" not in result and client.closed


def test_repeated_s3_continuation_does_not_loop(monkeypatch):
    client = S3()
    client.list_objects_v2 = lambda **kwargs: {"Contents": [], "IsTruncated": True, "NextContinuationToken": "same-token"}
    result = scan_s3(monkeypatch, client)
    assert result[-1]["reason"] == "listing_continuation_limit" and client.closed


def test_scan_revalidates_host_approval(monkeypatch):
    saved = cloud.normalize_config("s3", config())
    monkeypatch.setenv("CLOUD_HOST_ALLOWLIST", "")
    monkeypatch.setattr(cloud, "_s3_client", lambda *args: pytest.fail("Network client should not be built"))
    result = list(cloud.scan("s3", saved, {}, Detector(mode="rules"), lambda: "running"))
    assert result[0]["status"] == "failed"


def test_expired_cloud_access_not_successful_removal(monkeypatch):
    client = S3()
    class AccessDenied(Exception):
        response = {"ResponseMetadata": {"HTTPStatusCode": 403}}
    def denied(**kwargs):
        raise AccessDenied("private values must not escape")
    client.get_object = denied
    result = scan_s3(monkeypatch, client)
    assert result[0]["status"] == "inaccessible" and not result[0]["findings"]
    assert "private values" not in json.dumps(result)


def test_table_changed_version_is_partial(monkeypatch):
    entity = Entity(PartitionKey="p", RowKey="r", email="test@example.test")
    client = Azure([entity])
    changed = Entity(entity)
    changed.metadata = {"etag": '"v2"'}
    client.get_entity = lambda *args, **kwargs: changed
    monkeypatch.setattr(cloud, "_azure_client", lambda *args: client)
    result = list(cloud.scan("azure_table", config("azure_table"), {}, Detector(mode="rules"), lambda: "running"))
    assert result[0]["status"] == "partial" and not result[0]["metadata"]["source_stable"]


def test_azure_transport_pins_methods_and_disables_ambient_proxy(monkeypatch):
    from azure.core.pipeline.transport import RequestsTransport
    seen = []
    monkeypatch.setattr(RequestsTransport, "send", lambda self, request, **kwargs: seen.append(kwargs))
    transport = cloud._azure_transport("https://cloud.test")
    try:
        assert transport.session.trust_env is False
        transport.send(SimpleNamespace(method="GET", url="https://cloud.test/container?sig=secret"), proxies={"https": "bad-proxy"})
        assert seen == [{"proxies": {}}]
        with pytest.raises(ValueError):
            transport.send(SimpleNamespace(method="PUT", url="https://cloud.test/container"))
    finally:
        transport.close()


def test_cloud_ca_cannot_be_disabled_by_environment(monkeypatch):
    monkeypatch.setenv("SOURCE_CLOUD_CA_FILE", "false")
    with pytest.raises(ValueError):
        cloud._ca()


def test_download_deadline_visible_and_closes_body(monkeypatch):
    client = S3()
    times = iter([0, 0, 61])
    monkeypatch.setattr(cloud.time, "monotonic", lambda: next(times, 61))
    result = scan_s3(monkeypatch, client)
    assert result[0]["reason"] == "object_download_time_limit"
    assert client.closed and client.bodies[0].closed


def test_iam_role_uses_refreshable_fixed_imdsv2_provider_without_proxy(monkeypatch):
    import boto3
    import botocore.credentials
    import botocore.session
    import botocore.utils
    import botocore.httpsession
    calls = {}
    role = object()
    session = SimpleNamespace()
    class Fetcher:
        def __init__(self, **kwargs):
            calls["fetcher"] = kwargs
    class Provider:
        def __init__(self, iam_role_fetcher):
            calls["fetcher_instance"] = iam_role_fetcher
        def load(self):
            return role
    class Session:
        def __init__(self, **kwargs):
            if kwargs:
                calls["fixed_session"] = kwargs["botocore_session"]
        def client(self, *args, **kwargs):
            calls["client"] = kwargs
            return SimpleNamespace(meta=SimpleNamespace(events=SimpleNamespace(register=lambda *args: None)))
    monkeypatch.setattr(boto3, "Session", Session)
    monkeypatch.setattr(botocore.utils, "InstanceMetadataFetcher", Fetcher)
    monkeypatch.setattr(botocore.credentials, "InstanceMetadataProvider", Provider)
    monkeypatch.setattr(botocore.session, "get_session", lambda: session)
    monkeypatch.setattr(botocore.httpsession, "URLLib3Session", lambda **kwargs: calls.setdefault("imds_transport", kwargs))
    cloud._s3_client(cloud.normalize_config("s3", config(auth_mode="iam_role")))
    assert calls["fetcher"]["config"] == {"ec2_metadata_v1_disabled": True}
    assert calls["imds_transport"]["proxies"] == {}
    assert calls["fixed_session"]._credentials is role
    assert not any(key.startswith("aws_") for key in calls["client"])
