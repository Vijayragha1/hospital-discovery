"""Read-only, endpoint-scoped S3, Azure Blob/ADLS and Azure Table discovery.

No account enumeration or mutation is used. Source firewall rules are still required:
DNS validation is defense in depth, not a replacement for network enforcement.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import os
import re
import socket
import time
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from urllib.parse import parse_qsl, quote, urlsplit

KINDS = {"s3", "azure_blob", "azure_table"}
_RFC1918 = tuple(ipaddress.ip_network(cidr) for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"))


def _text(config, name, *, maximum=1024, required=False):
    value = config.get(name, "")
    if not isinstance(value, str) or len(value) > maximum or any(ord(c) < 32 for c in value):
        raise ValueError("Invalid cloud source field.")
    if required and not value:
        raise ValueError("A required cloud source field is missing.")
    return value


def _check_private(host):
    try:
        addresses = {ipaddress.ip_address(item[4][0]) for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)}
    except (OSError, ValueError):
        raise ValueError("Cloud endpoint DNS is unavailable.") from None
    if not addresses or any(not (a.is_loopback or any(a in network for network in _RFC1918 if a.version == network.version)) for a in addresses):
        raise ValueError("Cloud endpoint must resolve only to private addresses.")


def _endpoint(value):
    if not isinstance(value, str) or len(value) > 512 or any(ord(c) < 33 for c in value):
        raise ValueError("Cloud endpoint must be an approved HTTPS origin.")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        raise ValueError("Cloud endpoint must be an approved HTTPS origin.") from None
    host = (parsed.hostname or "").lower()
    allowed = {entry.strip().lower() for entry in os.getenv("CLOUD_HOST_ALLOWLIST", "").split(",") if entry.strip()}
    if (parsed.scheme != "https" or not host or parsed.username is not None or parsed.password is not None
            or parsed.path not in ("", "/") or parsed.query or parsed.fragment or host not in allowed
            or "\\" in value or (port is not None and not 1 <= port <= 65535)):
        raise ValueError("Cloud endpoint must be an approved HTTPS origin.")
    _check_private(host)
    authority = f"[{host}]" if ":" in host else host
    return "https://" + authority + (f":{port}" if port and port != 443 else "")


def _guard_request(endpoint, url, method):
    """Pin redirects/SDK-generated URLs to the exact configured origin."""
    parsed, approved = urlsplit(url), urlsplit(endpoint)
    if (method not in {"GET", "HEAD"} or parsed.scheme != approved.scheme or parsed.hostname != approved.hostname
            or (parsed.port or 443) != (approved.port or 443) or parsed.username is not None or parsed.password is not None):
        raise ValueError("Cloud request is outside the approved read-only endpoint.")
    # Recheck both operator allowlist and DNS for each network request.
    _endpoint(endpoint)


def _sas(token, kind, scope):
    try:
        pairs = parse_qsl(token.lstrip("?"), keep_blank_values=True, strict_parsing=True)
        fields = dict(pairs)
        if len(fields) != len(pairs) or not all(fields.get(k) for k in ("sv", "sig", "se", "sp")):
            raise ValueError
        if any(k in fields for k in ("si", "ss", "srt")) or fields.get("spr") != "https":
            raise ValueError
        if kind == "azure_blob":
            if fields.get("sr") != "c" or set(fields["sp"]) != {"r", "l"}:
                raise ValueError
        elif fields.get("tn", "").lower() != scope.lower() or fields["sp"] != "r":
            raise ValueError
        expiry = datetime.fromisoformat(fields["se"].replace("Z", "+00:00"))
        if expiry.tzinfo is None or expiry <= datetime.now(timezone.utc):
            raise ValueError
    except (ValueError, TypeError):
        raise ValueError("Use a non-expired HTTPS-only, explicitly read/list-only service SAS for this container or table.") from None
    return token.lstrip("?")


def normalize_config(kind, config):
    if kind not in KINDS or not isinstance(config, dict):
        raise ValueError("Unsupported cloud source kind.")
    result = {}
    if kind == "s3":
        result["endpoint_url"] = _endpoint(_text(config, "endpoint_url", required=True))
        result["bucket"] = _text(config, "bucket", maximum=63, required=True)
        if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", result["bucket"]) or ".." in result["bucket"]:
            raise ValueError("Use a bucket name, not a URL or access point ARN.")
        result["prefix"] = _text(config, "prefix")
        result["region"] = _text(config, "region", maximum=64) or "ap-south-1"
        if not re.fullmatch(r"[a-z0-9-]+", result["region"]):
            raise ValueError("Invalid S3 signing region.")
        result["auth_mode"] = config.get("auth_mode", "access_key")
        if result["auth_mode"] not in {"access_key", "iam_role"}:
            raise ValueError("Unsupported S3 authentication mode.")
        if result["auth_mode"] == "access_key":
            for key in ("access_key_id", "secret_access_key", "session_token"):
                result[key] = _text(config, key, maximum=8192, required=key != "session_token")
    else:
        result["account_url"] = _endpoint(_text(config, "account_url", required=True))
        scope = "container" if kind == "azure_blob" else "table"
        result[scope] = _text(config, scope, maximum=63, required=True)
        pattern = r"[a-z0-9](?:[a-z0-9-]{1,61})[a-z0-9]" if kind == "azure_blob" else r"[A-Za-z][A-Za-z0-9]{2,62}"
        if not re.fullmatch(pattern, result[scope]) or (kind == "azure_blob" and "--" in result[scope]):
            raise ValueError("Invalid Azure container or table name.")
        result["prefix" if kind == "azure_blob" else "partition_key"] = _text(config, "prefix" if kind == "azure_blob" else "partition_key")
        result["sas_token"] = _sas(_text(config, "sas_token", maximum=16384, required=True), kind, result[scope])
    return result


def _ca():
    # Only a host deployment setting; never accepted from source configuration.
    path = os.getenv("SOURCE_CLOUD_CA_FILE")
    if path and (not Path(path).is_absolute() or not Path(path).is_file()):
        raise ValueError("Cloud TLS CA file must be an existing absolute file path.")
    return path or True


def _quiet_sdk_logs():
    # HTTP/signing diagnostics can contain credentials and patient-bearing keys.
    # Disable the known SDK hierarchies even when the application root is DEBUG.
    for name in ("boto3", "botocore", "s3transfer", "azure", "urllib3", "requests"):
        logger = logging.getLogger(name)
        logger.setLevel(logging.CRITICAL + 1)
        logger.propagate = False
        for child_name, child in list(logging.Logger.manager.loggerDict.items()):
            if child_name.startswith(name + ".") and isinstance(child, logging.Logger):
                child.setLevel(logging.CRITICAL + 1)
                child.propagate = False


def _s3_client(config):
    import boto3
    from botocore.config import Config
    _quiet_sdk_logs()
    credentials = {}
    session = boto3.Session()
    if config["auth_mode"] == "iam_role":
        from botocore.credentials import InstanceMetadataProvider
        from botocore.utils import InstanceMetadataFetcher
        # Deliberately exclude profiles, credential_process, STS and arbitrary ECS URLs.
        fetcher = InstanceMetadataFetcher(timeout=2, num_attempts=1, env={},
                                          config={"ec2_metadata_v1_disabled": True})
        from botocore.httpsession import URLLib3Session
        # The pinned botocore fetcher otherwise consults HTTP_PROXY independently
        # of its env argument. IMDS credentials must never traverse a proxy.
        fetcher._session = URLLib3Session(timeout=2, proxies={})
        role = InstanceMetadataProvider(iam_role_fetcher=fetcher).load()
        if role is None:
            raise ValueError("EC2 instance-profile credentials are unavailable.")
        # Preserve the refreshable fixed provider without consulting the ambient
        # default credential chain. This is pinned/tested botocore integration.
        import botocore.session
        fixed_session = botocore.session.get_session()
        fixed_session._credentials = role
        session = boto3.Session(botocore_session=fixed_session)
    else:
        credentials = {"aws_access_key_id": config["access_key_id"], "aws_secret_access_key": config["secret_access_key"],
                       "aws_session_token": config.get("session_token") or None}
    client = session.client("s3", endpoint_url=config["endpoint_url"], region_name=config["region"], verify=_ca(),
                          config=Config(connect_timeout=5, read_timeout=5, retries={"total_max_attempts": 1},
                                        proxies={}, s3={"addressing_style": "path"}), **credentials)
    client.meta.events.register("before-send.s3", lambda request, **kwargs: _guard_request(config["endpoint_url"], request.url, request.method))
    return client


def _azure_transport(endpoint):
    import requests
    from azure.core.pipeline.transport import RequestsTransport

    class GuardedTransport(RequestsTransport):
        def send(self, request, **kwargs):
            _guard_request(endpoint, request.url, request.method)
            kwargs["proxies"] = {}
            return super().send(request, **kwargs)

    session = requests.Session()
    session.trust_env = False
    return GuardedTransport(session=session, session_owner=True, connection_timeout=5, read_timeout=5,
                            connection_verify=_ca())


def _azure_client(kind, config):
    from azure.core.credentials import AzureSasCredential
    from azure.core.pipeline.policies import RedirectPolicy
    _quiet_sdk_logs()
    common = {"credential": AzureSasCredential(config["sas_token"]), "transport": _azure_transport(config["account_url"]),
              "retry_total": 0, "logging_enable": False, "redirect_policy": RedirectPolicy(permit_redirects=False)}
    if kind == "azure_blob":
        from azure.storage.blob import ContainerClient
        return ContainerClient(config["account_url"], config["container"], max_single_get_size=65536,
                               max_chunk_get_size=65536, **common)
    from azure.data.tables import TableClient
    return TableClient(config["account_url"], table_name=config["table"], **common)


def _table_entities(client, config, page_size):
    if config.get("partition_key"):
        return client.query_entities("PartitionKey eq @partition", parameters={"partition": config["partition_key"]},
                                     results_per_page=page_size, timeout=5)
    return client.list_entities(results_per_page=page_size, timeout=5)


def _close(value):
    try:
        value.close()
    except Exception:
        pass


def test_connection(kind, config):
    config = normalize_config(kind, config)
    client = None
    try:
        client = _s3_client(config) if kind == "s3" else _azure_client(kind, config)
        if kind == "s3":
            client.list_objects_v2(Bucket=config["bucket"], Prefix=config["prefix"], MaxKeys=1)
        elif kind == "azure_blob":
            next(iter(client.list_blobs(name_starts_with=config["prefix"], results_per_page=1, timeout=5)), None)
        else:
            next(iter(_table_entities(client, config, 1)), None)
    except Exception:
        raise ValueError("Cloud source check failed. Check approved private DNS, trusted TLS, scope and read/list permissions.") from None
    finally:
        _close(client)
    return {"ok": True, "read_only_operations": True, "safety_validated": True,
            "note": "Only read/list operations were attempted; verify the dedicated identity has no write permissions during hospital acceptance."}


def _obj(*args, **kwargs):
    from .scanning import _object
    return _object(*args, **kwargs)


def _running(control):
    from .scanning import _running as running
    return running(control)


def _preflight(location, size, options):
    from .extraction import ARCHIVE_SUFFIXES, TEXT_SUFFIXES, TIKA_SUFFIXES
    suffix = PurePosixPath(location).suffix.lower()
    if suffix in ARCHIVE_SUFFIXES:
        return _obj(location, "excluded", "archive_scanning_disabled")
    if suffix not in TEXT_SUFFIXES | TIKA_SUFFIXES:
        return _obj(location, "unsupported", "unsupported_file_format")
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        return _obj(location, "partial", "object_size_unavailable")
    if size > options["max_file_bytes"]:
        return _obj(location, "excluded", "file_size_limit_reached", metadata={"source_size_bytes": size})
    return None


class _Cancelled(Exception):
    pass


class _Changed(Exception):
    pass


class _TimedOut(Exception):
    pass


def _download_running(control, started):
    if not _running(control):
        raise _Cancelled
    if time.monotonic() - started > 60:
        raise _TimedOut


def _extract(location, data, size, etag, options, detector):
    from .extraction import extract_bytes
    from .document_analysis import analyze_document
    result = extract_bytes(data, PurePosixPath(location).suffix, options)
    findings = analyze_document(location, data, PurePosixPath(location).suffix, result, options, detector)
    return _obj(location, result.status, result.reason, examined=result.examined, unit=result.unit,
                fingerprint=hashlib.sha256(data).hexdigest(), findings=findings,
                metadata={**result.metadata, "bytes_read": len(data), "source_size_bytes": size,
                          "source_stable": True, "etag_sha256": hashlib.sha256(etag.encode()).hexdigest(),
                          "fingerprint_scope": "downloaded_object_bytes"})


def _same_etag(first, second):
    # Azure XML listings can expose an unquoted ETag while HTTP HEAD returns the
    # same strong opaque tag in RFC header quotes. Compare the opaque value.
    def opaque(value):
        if not isinstance(value, str):
            return None
        return value[1:-1] if len(value) >= 2 and value.startswith('"') and value.endswith('"') else value
    return bool(first) and bool(second) and opaque(first) == opaque(second)


def _object_error(location, error):
    status = getattr(error, "status_code", None)
    response = getattr(error, "response", {})
    if isinstance(response, dict):
        status = response.get("ResponseMetadata", {}).get("HTTPStatusCode", status)
    if isinstance(error, _Cancelled):
        return _obj(location, "partial", "scan_cancelled")
    if isinstance(error, _TimedOut):
        return _obj(location, "partial", "object_download_time_limit")
    if isinstance(error, _Changed) or status in {404, 409, 412, 416}:
        return _obj(location, "partial", "object_changed_during_scan", metadata={"source_stable": False})
    return _obj(location, "inaccessible", "cloud_object_unavailable")


def _s3_object(client, config, entry, options, detector, control):
    key, size, etag = entry["Key"], entry.get("Size"), entry.get("ETag")
    location = "s3/" + quote(config["bucket"], safe="") + "/" + quote(key, safe="/")
    skipped = _preflight(location, size, options)
    if skipped:
        return skipped
    if not etag:
        return _obj(location, "partial", "object_version_unavailable")
    body = None
    try:
        started = time.monotonic()
        _download_running(control, started)
        response = client.get_object(Bucket=config["bucket"], Key=key, IfMatch=etag)
        body = response["Body"]
        if response.get("ETag") != etag or response.get("ContentLength") != size:
            raise _Changed
        data = bytearray()
        while True:
            _download_running(control, started)
            chunk = body.read(min(65536, options["max_file_bytes"] + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > options["max_file_bytes"]:
                raise _Changed
        if len(data) != size:
            raise _Changed
        result = _extract(location, bytes(data), size, etag, options, detector)
        latest = client.head_object(Bucket=config["bucket"], Key=key, IfMatch=etag)
        if latest.get("ETag") != etag or latest.get("ContentLength") != size:
            raise _Changed
        return result
    except Exception as error:
        return _object_error(location, error)
    finally:
        _close(body)


def _s3(config, options, detector, control):
    client = _s3_client(config)
    count, pages, token, seen_tokens = 0, 0, None, set()
    try:
        while True:
            if not _running(control):
                yield _obj("[cloud-coverage]", "partial", "scan_cancelled")
                return
            args = {"Bucket": config["bucket"], "Prefix": config["prefix"], "MaxKeys": min(100, options["batch_size"])}
            if token:
                args["ContinuationToken"] = token
            page = client.list_objects_v2(**args)
            pages += 1
            for entry in page.get("Contents", []):
                if count >= options["max_files"]:
                    yield _obj("[cloud-coverage]", "partial", "object_limit_reached", metadata={"objects_examined": count})
                    return
                if not _running(control):
                    yield _obj("[cloud-coverage]", "partial", "scan_cancelled")
                    return
                if not isinstance(entry.get("Key"), str) or not entry["Key"].startswith(config["prefix"]):
                    raise ValueError("Invalid listing scope")
                count += 1
                yield _s3_object(client, config, entry, options, detector, control)
            if not page.get("IsTruncated"):
                yield _obj("[cloud-coverage]", "full", metadata={"objects_examined": count, "listing_complete": True,
                                                                 "point_in_time_snapshot": False})
                return
            token = page.get("NextContinuationToken")
            if not token or token in seen_tokens or pages >= 10000:
                yield _obj("[cloud-coverage]", "partial", "listing_continuation_limit")
                return
            seen_tokens.add(token)
    except Exception:
        yield _obj("[cloud-coverage]", "inaccessible", "cloud_listing_unavailable", metadata={"objects_examined": count})
    finally:
        _close(client)


def _blob_object(client, config, entry, options, detector, control):
    from azure.core import MatchConditions
    name, size, etag = entry.name, entry.size, entry.etag
    location = "azure_blob/" + quote(config["container"], safe="") + "/" + quote(name, safe="/")
    skipped = _preflight(location, size, options)
    if skipped:
        return skipped
    if not etag:
        return _obj(location, "partial", "object_version_unavailable")
    blob = client.get_blob_client(name)
    chunks = None
    try:
        started = time.monotonic()
        _download_running(control, started)
        download = blob.download_blob(etag=etag, match_condition=MatchConditions.IfNotModified,
                                      max_concurrency=1, timeout=5)
        chunks = download.chunks()
        data = bytearray()
        for chunk in chunks:
            _download_running(control, started)
            if len(data) + len(chunk) > options["max_file_bytes"]:
                raise _Changed
            data.extend(chunk)
        if len(data) != size:
            raise _Changed
        result = _extract(location, bytes(data), size, etag, options, detector)
        latest = blob.get_blob_properties(etag=etag, match_condition=MatchConditions.IfNotModified, timeout=5)
        if not _same_etag(latest.etag, etag) or latest.size != size:
            raise _Changed
        return result
    except Exception as error:
        return _object_error(location, error)
    finally:
        _close(chunks)
        # Container owns the shared transport; closing the container after the scan
        # releases it. Chunk requests are bounded and consumed by the SDK.


def _blob(config, options, detector, control):
    client = _azure_client("azure_blob", config)
    count, pages = 0, 0
    try:
        listing = client.list_blobs(name_starts_with=config["prefix"], results_per_page=min(100, options["batch_size"]), timeout=5)
        for page in listing.by_page():
            pages += 1
            if pages > 10000:
                yield _obj("[cloud-coverage]", "partial", "listing_continuation_limit")
                return
            for entry in page:
                if count >= options["max_files"]:
                    yield _obj("[cloud-coverage]", "partial", "object_limit_reached", metadata={"objects_examined": count})
                    return
                if not _running(control):
                    yield _obj("[cloud-coverage]", "partial", "scan_cancelled")
                    return
                if not entry.name.startswith(config["prefix"]):
                    raise ValueError("Invalid listing scope")
                count += 1
                yield _blob_object(client, config, entry, options, detector, control)
        yield _obj("[cloud-coverage]", "full", metadata={"objects_examined": count, "listing_complete": True,
                                                        "point_in_time_snapshot": False})
    except Exception:
        yield _obj("[cloud-coverage]", "inaccessible", "cloud_listing_unavailable", metadata={"objects_examined": count})
    finally:
        _close(client)


def _table_entity(config, entity, options, detector, control):
    from .scanning import _column_results
    # Keys can contain patient information; use a digest rather than displaying them.
    identity = json.dumps([entity.get("PartitionKey"), entity.get("RowKey")], ensure_ascii=False).encode()
    location = "azure_table/" + quote(config["table"], safe="") + "/entity:" + hashlib.sha256(identity).hexdigest()
    columns = sorted(entity)
    # Service entity limit is 1 MiB. Also enforce it locally for SDK stubs/custom endpoints.
    serialized = json.dumps(dict(entity), ensure_ascii=False, default=str, sort_keys=True).encode()
    if len(serialized) > 1024 * 1024 or len(columns) > 255:
        return _obj(location, "partial", "entity_size_limit_reached", unit="rows")
    rows = _column_results(location, columns, [tuple(entity[column] for column in columns)],
                           options={**options, "full_scan": False}, detector=detector, control=control,
                           metadata={"ordered_by_primary_key": True})
    findings, incomplete = [], False
    for result in rows:
        incomplete |= result["status"] != "full"
        column = result["location"].rsplit("/", 1)[-1]
        for finding in result["findings"]:
            finding["segment"] = "property:" + column
            for evidence in finding.get("evidence", []):
                evidence["segment"] = "property:" + column + "/" + evidence["segment"]
            findings.append(finding)
    return _obj(location, "partial" if incomplete else "full", "entity_content_partial" if incomplete else None,
                examined=1, unit="rows", fingerprint=hashlib.sha256(serialized).hexdigest(), findings=findings,
                metadata={"properties_examined": len(columns), "source_stable": True, "patient_linkage": "entity_local_only",
                          "fingerprint_scope": "entity_properties", "sampling_method": "bounded_key_ordered_prefix"})


def _table(config, options, detector, control):
    client = _azure_client("azure_table", config)
    count, pages = 0, 0
    row_limit = min(options["table_sample_rows"], options["max_files"])
    try:
        entities = _table_entities(client, config, min(100, options["batch_size"]))
        for page in entities.by_page():
            pages += 1
            if pages > 1000:
                yield _obj("[cloud-coverage]", "partial", "listing_continuation_limit", unit="rows")
                return
            for entity in page:
                if count >= row_limit:
                    yield _obj("[cloud-coverage]", "sampled", "bounded_prefix_sample", examined=count, unit="rows",
                                metadata={"sample_rows": count, "row_limit": row_limit,
                                          "sampling_bias": "prefix_sample_not_representative", "total_rows_known": False})
                    return
                if not _running(control):
                    yield _obj("[cloud-coverage]", "partial", "scan_cancelled", unit="rows")
                    return
                count += 1
                if config.get("partition_key") and entity.get("PartitionKey") != config["partition_key"]:
                    raise ValueError("Invalid partition scope")
                result = _table_entity(config, entity, options, detector, control)
                etag = getattr(entity, "metadata", {}).get("etag")
                if not etag:
                    result.update(status="partial", reason="object_version_unavailable")
                    result["metadata"]["source_stable"] = False
                else:
                    try:
                        current = client.get_entity(entity["PartitionKey"], entity["RowKey"], timeout=5)
                        if getattr(current, "metadata", {}).get("etag") != etag:
                            result.update(status="partial", reason="object_changed_during_scan")
                            result["metadata"]["source_stable"] = False
                    except Exception:
                        result.update(status="partial", reason="object_changed_during_scan")
                        result["metadata"]["source_stable"] = False
                yield result
        yield _obj("[cloud-coverage]", "full", examined=count, unit="rows", metadata={"sample_rows": count,
                                                                                     "listing_complete": True, "point_in_time_snapshot": False})
    except Exception:
        yield _obj("[cloud-coverage]", "inaccessible", "cloud_listing_unavailable", unit="rows", metadata={"sample_rows": count})
    finally:
        _close(client)


def scan(kind, config, options, detector, control):
    from .scanning import _options
    try:
        config, options = normalize_config(kind, config), _options(options)
        if kind == "azure_table" and options["full_scan"]:
            yield _obj("[cloud-coverage]", "excluded", "azure_table_full_scan_not_supported", unit="rows")
            return
        yield from {"s3": _s3, "azure_blob": _blob, "azure_table": _table}[kind](config, options, detector, control)
    except Exception:
        yield _obj("[cloud-coverage]", "failed", "cloud_source_scan_failed")
