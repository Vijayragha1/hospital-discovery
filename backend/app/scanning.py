"""Read-only, bounded scanners. Actual-match values require explicit evidence capture."""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import sqlite3
import stat
import time
from collections import defaultdict
from contextlib import nullcontext
from pathlib import Path
from typing import Callable, Iterator
from urllib.parse import quote

from .detection import match_evidence, source_segments
from .extraction import (ARCHIVE_SUFFIXES, TEXT_SUFFIXES, TIKA_SUFFIXES, extract_bytes, private_host,
                         structured_kind, structured_text)
from .connectors import DATABASE_KINDS


DEFAULTS = {"max_file_bytes": 20 * 1024 * 1024, "max_files": 10000, "max_text_chars": 1_000_000,
            "table_sample_rows": 1000, "batch_size": 100, "statement_timeout_ms": 5000,
            "lock_timeout_ms": 1000, "full_scan": False, "capture_evidence": False}
_HARD_LIMITS = {"max_file_bytes": 100 * 1024 * 1024, "max_files": 100000,
                "max_text_chars": 10_000_000, "table_sample_rows": 1000, "batch_size": 100,
                "statement_timeout_ms": 30000, "lock_timeout_ms": 5000}
_PATIENT_COLUMN = re.compile(r"^(?:patient[ _-]?(?:id|number|no)|mrn|uhid|abha(?:[ _-]?(?:id|number))?)$", re.I)


def _options(options: dict) -> dict:
    result = dict(DEFAULTS)
    for name, ceiling in _HARD_LIMITS.items():
        value = options.get(name, result[name])
        if isinstance(value, bool):
            raise ValueError("invalid_scan_options")
        value = int(value)
        if value < 1 or value > ceiling:
            raise ValueError("invalid_scan_options")
        result[name] = value
    for name in ("full_scan", "capture_evidence"):
        if not isinstance(options.get(name, False), bool):
            raise ValueError("invalid_scan_options")
        result[name] = options.get(name, False)
    return result


def _object(location: str, status: str, reason: str | None = None, *, examined: int = 0,
            unit: str = "bytes", fingerprint: str | None = None, findings=None, metadata=None) -> dict:
    return {"object_key": hashlib.sha256(location.encode("utf-8", errors="surrogatepass")).hexdigest(),
            "location": location, "status": status, "reason": reason, "examined": examined, "unit": unit,
            "fingerprint": fingerprint, "findings": findings or [], "metadata": metadata or {}}


def _running(control: Callable[[], str]) -> bool:
    while True:
        state = control()
        if state == "running":
            return True
        if state != "paused":
            return False
        time.sleep(.2)


def _cancelled(location="[scan]") -> dict:
    return _object(location, "partial", "scan_cancelled")


def scan_source(kind: str, config: dict, options: dict, detector, control: Callable[[], str]) -> Iterator[dict]:
    """Never echo secrets/errors. Only explicit opt-in adds bounded match evidence."""
    try:
        settings = _options(options)
    except (ValueError, TypeError, OverflowError):
        yield _object("[scan]", "failed", "invalid_scan_options")
        return
    from .database_connectors import scan as scan_database
    from .cloud_connectors import scan as scan_cloud
    scanners = {"filesystem": _filesystem, "smb": _smb, "sqlite": _sqlite, "postgresql": _postgresql,
                **{name: (lambda *args, name=name: scan_database(name, *args)) for name in ("mysql", "mssql")},
                **{name: (lambda *args, name=name: scan_cloud(name, *args)) for name in ("s3", "azure_blob", "azure_table")}}
    if kind not in scanners:
        yield _object("[source]", "unsupported", "source_kind_not_supported")
        return
    if kind in DATABASE_KINDS | {"sqlite", "azure_table"} and settings["full_scan"]:
        if config.get("full_scan_allowed") is not True:
            yield _object("[database]", "excluded", "full_scan_not_approved", unit="rows")
            return
        if not (config.get("table") if kind == "azure_table" else config.get("tables")):
            yield _object("[database]", "excluded", "full_scan_requires_explicit_tables", unit="rows")
            return
    try:
        yield from scanners[kind](config, settings, detector, control)
    except Exception:
        # A connector/driver may embed query values, passwords or DSNs in its exception.
        yield _object("[source]", "failed", "source_scan_failed")


def _local_entries(directory_fd: int, prefix: str = "", depth: int = 0):
    try:
        with os.scandir(directory_fd) as entries:
            for entry in entries:
                relative = f"{prefix}/{entry.name}".lstrip("/")
                try:
                    if entry.is_symlink():
                        yield relative, directory_fd, entry.name, "symlink"
                    elif entry.is_dir(follow_symlinks=False):
                        yield relative, directory_fd, entry.name, "directory"
                        if depth >= 64:
                            yield relative, directory_fd, entry.name, "depth_limit"
                            continue
                        child_fd = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory_fd)
                        try:
                            yield from _local_entries(child_fd, relative, depth + 1)
                        finally:
                            os.close(child_fd)
                    elif entry.is_file(follow_symlinks=False):
                        yield relative, directory_fd, entry.name, "file"
                    else:
                        yield relative, directory_fd, entry.name, "special"
                except OSError:
                    yield relative, directory_fd, entry.name, "inaccessible"
    except OSError:
        yield prefix or "[root]", directory_fd, "", "inaccessible"


def _file_result(relative, data, initial_stat, final_stat, options, detector):
    extracted = extract_bytes(data, Path(relative).suffix, options)
    from .document_analysis import analyze_document
    findings = analyze_document(relative, data, Path(relative).suffix, extracted, options, detector)
    changed = (initial_stat.st_size, initial_stat.st_mtime_ns, initial_stat.st_ino) != (
        final_stat.st_size, final_stat.st_mtime_ns, final_stat.st_ino)
    status, reason = extracted.status, extracted.reason
    metadata = {**extracted.metadata, "bytes_read": len(data), "source_size_bytes": initial_stat.st_size,
                "source_modified_ns": initial_stat.st_mtime_ns, "source_stable": not changed}
    if changed:
        status, reason = "partial", "file_changed_during_scan"
    return _object(relative, status, reason, examined=extracted.examined, unit=extracted.unit,
                   fingerprint=hashlib.sha256(data).hexdigest(), findings=findings, metadata=metadata)


def _filesystem(config, options, detector, control):
    root_text = config.get("root", "")
    if not isinstance(root_text, str) or not root_text or not Path(root_text).is_absolute():
        yield _object("[root]", "failed", "absolute_root_required")
        return
    # Opening every ancestor with O_NOFOLLOW prevents intermediate symlink escapes too.
    root_fd = None
    try:
        root_fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        for component in Path(root_text).parts[1:]:
            if component in {".", ".."}:
                raise ValueError("unsafe_root")
            next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
            os.close(root_fd)
            root_fd = next_fd
        count = 0
        entries = _local_entries(root_fd)
        try:
            for relative, parent_fd, name, kind in entries:
                if not _running(control):
                    yield _cancelled()
                    return
                if count >= options["max_files"]:
                    yield _object("[coverage]", "partial", "file_limit_reached", metadata={"objects_examined": count})
                    return
                count += 1
                if kind == "directory":
                    continue
                if kind != "file":
                    reasons = {"symlink": "symlink_excluded", "depth_limit": "directory_depth_limit",
                               "special": "special_file_excluded", "inaccessible": "path_not_readable"}
                    yield _object(relative, "inaccessible" if kind == "inaccessible" else "excluded", reasons[kind])
                    continue
                suffix = Path(relative).suffix.lower()
                if suffix in ARCHIVE_SUFFIXES:
                    yield _object(relative, "excluded", "archive_scanning_disabled", metadata={"bytes_read": 0})
                    continue
                if suffix not in TEXT_SUFFIXES | TIKA_SUFFIXES:
                    yield _object(relative, "unsupported", "unsupported_file_format", metadata={"bytes_read": 0})
                    continue
                try:
                    file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
                    with os.fdopen(file_fd, "rb") as handle:
                        before = os.fstat(handle.fileno())
                        if not stat.S_ISREG(before.st_mode):
                            yield _object(relative, "excluded", "special_file_excluded")
                            continue
                        if before.st_size > options["max_file_bytes"]:
                            yield _object(relative, "excluded", "file_size_limit", metadata={"source_size_bytes": before.st_size})
                            continue
                        data = handle.read(options["max_file_bytes"] + 1)
                        if len(data) > options["max_file_bytes"]:
                            yield _object(relative, "partial", "file_grew_beyond_limit", examined=options["max_file_bytes"])
                            continue
                        # Extraction can take time: compare the path again after it finishes.
                        result = _file_result(relative, data, before, os.fstat(handle.fileno()), options, detector)
                        after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                        if (before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns):
                            result.update(status="partial", reason="file_changed_during_scan")
                            result["metadata"]["source_stable"] = False
                        yield result
                except OSError:
                    yield _object(relative, "inaccessible", "file_not_readable_or_changed")
                except Exception:
                    yield _object(relative, "failed", "extraction_or_detection_failed")
        finally:
            entries.close()
    except (OSError, ValueError):
        yield _object("[root]", "inaccessible", "root_unavailable_or_symlink")
    finally:
        if root_fd is not None:
            os.close(root_fd)


def _smb(config, options, detector, control):
    server, share = config.get("server", ""), config.get("share", "")
    subpath = config.get("subpath", "") or ""
    if not all(isinstance(value, str) for value in (server, share, subpath)):
        yield _object("[share]", "failed", "invalid_smb_path")
        return
    parts = subpath.replace("\\", "/").split("/") if subpath else []
    if (not server or not share or any(char in server for char in "\\/@: ") or
            any(char in share for char in "\\/:\x00") or share in {".", ".."} or
            any(part in {"", ".", ".."} or "\x00" in part or ":" in part for part in parts)):
        yield _object("[share]", "failed", "invalid_smb_path")
        return
    if not private_host(server):
        yield _object("[share]", "failed", "smb_endpoint_not_private")
        return
    try:
        import smbclient
    except ImportError:
        yield _object("[share]", "failed", "smbprotocol_dependency_missing")
        return
    logging.getLogger("smbprotocol").setLevel(logging.CRITICAL)
    logging.getLogger("smbclient").setLevel(logging.CRITICAL)
    root = "\\\\" + server + "\\" + share + ("\\" + "\\".join(parts) if parts else "")
    cache = {}
    kwargs = {"connection_cache": cache}
    try:
        # DFS referrals can escape the approved share; pilot excludes them.
        smbclient.ClientConfig(skip_dfs=True)
        username = config.get("username")
        if config.get("domain") and username:
            username = config["domain"] + "\\" + username
        smbclient.register_session(server, username=username, password=config.get("password"),
                                   encrypt=True, connection_timeout=5, **kwargs)
        from smbprotocol.open import CreateOptions
        # Refuse a configured root/subpath which is itself a reparse point.
        current = "\\\\" + server + "\\" + share
        for component in [None, *parts]:
            if component is not None:
                current += "\\" + component
            root_info = smbclient.stat(current, follow_symlinks=False, **kwargs)
            if getattr(root_info, "st_file_attributes", 0) & 0x400:
                yield _object("[share]", "excluded", "reparse_point_excluded")
                return
        pending = [(root, "", 0)]
        count = 0
        while pending:
            directory, prefix, depth = pending.pop()
            if not _running(control):
                yield _cancelled()
                return
            try:
                for entry in smbclient.scandir(directory, create_options=CreateOptions.FILE_OPEN_REPARSE_POINT, **kwargs):
                    if not _running(control):
                        yield _cancelled()
                        return
                    if count >= options["max_files"]:
                        yield _object("[coverage]", "partial", "file_limit_reached", metadata={"objects_examined": count})
                        return
                    relative = f"{prefix}/{entry.name}".lstrip("/")
                    remote_path = directory + "\\" + entry.name
                    count += 1
                    try:
                        info = entry.stat(follow_symlinks=False)
                        if getattr(info, "st_file_attributes", 0) & 0x400 or entry.is_symlink():
                            yield _object(relative, "excluded", "reparse_point_excluded")
                        elif entry.is_dir(follow_symlinks=False):
                            if depth >= 64:
                                yield _object(relative, "excluded", "directory_depth_limit")
                            else:
                                pending.append((remote_path, relative, depth + 1))
                        elif not entry.is_file(follow_symlinks=False):
                            yield _object(relative, "excluded", "special_file_excluded")
                        elif Path(relative).suffix.lower() in ARCHIVE_SUFFIXES:
                            yield _object(relative, "excluded", "archive_scanning_disabled", metadata={"bytes_read": 0})
                        elif Path(relative).suffix.lower() not in TEXT_SUFFIXES | TIKA_SUFFIXES:
                            yield _object(relative, "unsupported", "unsupported_file_format", metadata={"bytes_read": 0})
                        elif info.st_size > options["max_file_bytes"]:
                            yield _object(relative, "excluded", "file_size_limit", metadata={"source_size_bytes": info.st_size})
                        else:
                            with smbclient.open_file(remote_path, mode="rb", create_options=CreateOptions.FILE_OPEN_REPARSE_POINT, **kwargs) as handle:
                                data = handle.read(options["max_file_bytes"] + 1)
                            if len(data) > options["max_file_bytes"]:
                                yield _object(relative, "partial", "file_grew_beyond_limit", examined=options["max_file_bytes"])
                                continue
                            after = smbclient.stat(remote_path, follow_symlinks=False, **kwargs)
                            result = _file_result(relative, data, info, after, options, detector)
                            # Re-check after OCR/detection as with local files.
                            last = smbclient.stat(remote_path, follow_symlinks=False, **kwargs)
                            if (last.st_size, last.st_mtime_ns, last.st_ino) != (info.st_size, info.st_mtime_ns, info.st_ino):
                                result.update(status="partial", reason="file_changed_during_scan")
                                result["metadata"]["source_stable"] = False
                            yield result
                    except Exception:
                        yield _object(relative, "inaccessible", "smb_object_unavailable")
            except Exception:
                yield _object(prefix or "[share]", "inaccessible", "smb_directory_unavailable")
    except Exception:
        yield _object("[share]", "inaccessible", "smb_connection_unavailable")
    finally:
        try:
            smbclient.delete_session(server, **kwargs)
        except Exception:
            pass


def _quote_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def _database_location(*parts: str) -> str:
    # Database identifiers may legally contain slashes or percent signs. Encoding each
    # component prevents different table/column tuples sharing a location/object key.
    return "/".join(quote(part, safe="") for part in parts)


def _selected_tables(tables, config):
    selected = config.get("tables") or []
    if not isinstance(selected, list) or not all(isinstance(value, str) for value in selected):
        raise ValueError("invalid_table_filter")
    # User input is only matched against discovered identifiers, never interpolated.
    return [table for table in tables if not selected or table in selected]


def _cell_evidence(findings, value, prefix, row_number):
    """Remove synthetic labels and rebuild excerpts from the actual cell only."""
    segments = dict(source_segments(value))
    for finding in findings:
        evidence = []
        for example in finding.get("evidence", []):
            segment = example["segment"]
            source = segments.get(segment)
            if source is None:
                continue
            adjustment = len(prefix) if segment == "segment:1/block:1/row:1" else 0
            start, end = example["start"] - adjustment, example["end"] - adjustment
            item = match_evidence(source, start, end, f"scan_row:{row_number}/{segment}")
            # Fail closed when a detector span cannot be mapped to the actual cell.
            if item and item["value"] == example["value"]:
                evidence.append(item)
                if len(evidence) == 3:
                    break
        finding["evidence"] = evidence


def _column_results(table_location, columns, rows, *, options, detector, control, metadata, binary_columns=None,
                    patient_columns=None, evaluation_primary_keys=None):
    cap = None if options["full_scan"] else options["table_sample_rows"]
    cell_limit = min(options["max_text_chars"], 65536)
    groups = {column: {} for column in columns}
    examined = 0
    nonempty = defaultdict(int)
    truncated = set()
    unverified_structure = set()
    binary = set(binary_columns or [])
    has_more = False
    cancelled = False
    sample_digests = {column: hashlib.sha256() for column in columns}
    for row in rows:
        if not _running(control):
            cancelled = True
            break
        if cap is not None and examined >= cap:
            has_more = True
            break
        examined += 1
        raw_row = row
        row = dict(zip(columns, raw_row))
        original_key = {}
        if evaluation_primary_keys and len(raw_row) == len(columns) + 2 * len(evaluation_primary_keys):
            for index, name in enumerate(evaluation_primary_keys):
                sql_type, number = raw_row[len(columns) + 2 * index:len(columns) + 2 * index + 2]
                original_key[name] = number if sql_type in {"integer", "real"} else row.get(name) if sql_type == "text" else None
        references = []
        references_ambiguous = False
        for name, item in row.items():
            if name in binary or item is None or not str(item).strip():
                continue
            if _PATIENT_COLUMN.fullmatch(name) or name in (patient_columns or set()):
                label = name.lower()
                kind = label.upper() if label in {"mrn", "uhid"} else "ABHA" if label.startswith("abha") else "PATIENT_REFERENCE"
                if isinstance(item, (dict, list, bytes)) or structured_kind(str(item)):
                    references_ambiguous = True
                else:
                    references.append((kind, str(item)))
        references = list(set(references))
        patient_reference = bool(references)
        references_ambiguous |= len(references) > 1
        for column, value in row.items():
            # Hash inspected values with unambiguous row framing. Evidence is separate.
            if value is None:
                sample_digests[column].update(b"null\x00")
            if value is None or column in binary:
                if value is None and column not in binary and getattr(detector, "_association_sink", None) is not None:
                    with detector._association_context(f"{table_location}/{quote(column, safe='')}",
                            cell={"original": None, "text": "", "prefix": "", "primary_key": original_key}):
                        pass
                continue
            nonempty[column] += 1
            if isinstance(value, bytes):
                binary.add(column)
                continue
            if isinstance(value, (dict, list)):
                value = json.dumps(value, ensure_ascii=False)
            else:
                value = str(value)
            original_value = value
            encoded = value.encode("utf-8", errors="replace")
            sample_digests[column].update(len(encoded).to_bytes(8, "big"))
            sample_digests[column].update(encoded)
            if len(value) > cell_limit:
                value = value[:cell_limit]
                truncated.add(column)
            context = f"column {column}" + ("; patient_reference_ambiguous" if references_ambiguous else
                                           "; patient_reference_present" if patient_reference else "")
            # A label helps contextual recognition, but is not source-record content.
            # Normalize whitespace so it cannot create artificial record boundaries.
            prefix = re.sub(r"\s+", " ", column) + ": "
            kind = structured_kind(value)
            if kind:
                value, structure_reason, _ = structured_text(value, kind, cell_limit)
                if structure_reason:
                    unverified_structure.add(column)
                # A JSON/XML cell can contain several independent patients. Do not
                # label its child records with the containing row's patient ID.
                context = context.replace("patient_reference_present", "").replace("patient_reference_ambiguous", "")
                prefix = ""
            detection_options = {"capture_evidence": True} if options["capture_evidence"] else {}
            observation_scope = getattr(detector, "_observation_context", None)
            scope = (observation_scope(f"{table_location}/{quote(column, safe='')}", finding_segment="column",
                                       prefix_length=len(prefix)) if observation_scope else nullcontext())
            association_scope = getattr(detector, "_association_context", None)
            association = (association_scope(f"{table_location}/{quote(column, safe='')}",
                cell={"original": original_value, "text": prefix + value, "prefix": prefix,
                      "primary_key": original_key},
                references=references if not kind else ()) if association_scope else nullcontext())
            with association:
                with scope:
                    cell_findings = detector.analyze(prefix + value, context=context, **detection_options) if value.strip() else []
            if options["capture_evidence"]:
                _cell_evidence(cell_findings, value, prefix, examined)
            identifier_column = bool(_PATIENT_COLUMN.fullmatch(column)) or column in (patient_columns or set())
            if identifier_column and value.strip() and not any(item["entity_type"] in {"MRN", "UHID", "ABHA", "ABHA_ADDRESS"} for item in cell_findings):
                cell_findings.append({"entity_type": "PATIENT_REFERENCE", "classification": "personal_data",
                                      "confidence": .85, "match_count": 1,
                                      "reason": "patient_identifier_column_or_declared_relationship", "segment": "column",
                                      **({"evidence": []} if options["capture_evidence"] else {})})
            for finding in cell_findings:
                key = (finding["entity_type"], finding["classification"], finding["reason"])
                if key not in groups[column]:
                    groups[column][key] = {**finding, "segment": "column", "match_count": 0}
                    if options["capture_evidence"]:
                        groups[column][key]["evidence"] = []
                group = groups[column][key]
                group["match_count"] += finding["match_count"]
                group["confidence"] = max(group["confidence"], finding["confidence"])
                if options["capture_evidence"]:
                    group["evidence"].extend(finding["evidence"][:3 - len(group["evidence"])])
    for column in columns:
        status, reason = ("sampled", "bounded_prefix_sample") if has_more else ("full", None)
        if column in truncated:
            status, reason = "partial", "cell_text_limit_reached"
        elif column in unverified_structure:
            status, reason = "partial", "structured_cell_boundaries_unverified"
        if column in binary:
            status, reason = "unsupported", "binary_column_not_inspected"
        if cancelled:
            status, reason = "partial", "scan_cancelled"
        yield _object(f"{table_location}/{quote(column, safe='')}", status, reason, examined=0 if column in binary else examined,
                       unit="rows", fingerprint=None if column in binary else sample_digests[column].hexdigest(), findings=list(groups[column].values()),
                       metadata={**metadata, "sample_rows": examined, "nonempty_cells_examined": nonempty[column],
                                 "row_limit": cap, "total_rows_known": not has_more and not cancelled,
                                 "sampling_method": "full_stream" if cap is None else ("bounded_ordered_prefix" if metadata.get("ordered_by_primary_key") else "bounded_prefix"),
                                 "sampling_bias": "none_full_table" if cap is None else "prefix_sample_not_representative",
                                 "cell_limit_characters": cell_limit,
                                 "fingerprint_scope": "inspected_values_only",
                                 "patient_linkage": "row_local_identifier_or_declared_foreign_key_context_only"})


def _patient_columns(table, foreign_keys, config):
    columns, evidence = set(), set()
    for foreign_key in foreign_keys:
        target = foreign_key.get("referred_table", "") or ""
        targets = foreign_key.get("referred_columns") or []
        if (re.search(r"(?:^|_)patients?(?:_|$)", target, re.I)
                or any(_PATIENT_COLUMN.fullmatch(name or "") for name in targets)):
            columns.update(foreign_key.get("constrained_columns") or [])
            evidence.add("declared_foreign_key_to_patient_table_or_identifier")
    configured = config.get("patient_identifier_columns") or {}
    if isinstance(configured, dict) and isinstance(configured.get(table), list):
        columns.update(value for value in configured[table] if isinstance(value, str))
        if configured[table]:
            evidence.add("hospital_configured_identifier_column")
    return columns, sorted(evidence)


def _sqlite(config, options, detector, control):
    """Fixture-only connector, enforced read-only at SQLite connection and query levels."""
    path_text = config.get("path", "")
    if not isinstance(path_text, str) or not path_text or not Path(path_text).is_absolute():
        yield _object("[database]", "failed", "absolute_fixture_path_required")
        return
    path = Path(path_text)
    if not path.is_file() or path.is_symlink() or path.resolve() != path:
        yield _object("[database]", "inaccessible", "fixture_unavailable_or_symlink")
        return
    connection = None
    try:
        connection = sqlite3.connect("file:" + quote(str(path), safe="/") + "?mode=ro", uri=True,
                                     timeout=options["lock_timeout_ms"] / 1000)
        connection.execute("PRAGMA query_only = ON")
        tables = [row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
        selected = _selected_tables(tables, config)
        missing = set(config.get("tables") or []) - set(tables)
        for table in sorted(missing):
            yield _object(_database_location("main", table), "inaccessible", "requested_table_not_discovered", unit="rows")
        for table in selected:
            if not _running(control):
                yield _cancelled()
                return
            try:
                details = connection.execute("PRAGMA table_info(" + _quote_identifier(table) + ")").fetchall()
                columns = [item[1] for item in details]
                binary = {item[1] for item in details if "BLOB" in item[2].upper()}
                pk = [item[1] for item in sorted(details, key=lambda item: item[5]) if item[5]]
                foreign_keys = [{"referred_table": item[2], "constrained_columns": [item[3]], "referred_columns": [item[4]]}
                                for item in connection.execute("PRAGMA foreign_key_list(" + _quote_identifier(table) + ")")]
                patient_columns, linkage_evidence = _patient_columns(table, foreign_keys, config)
                limit = min(options["max_text_chars"], 65536) + 1
                projection = ", ".join(("NULL" if column in binary else f"substr(CAST({_quote_identifier(column)} AS TEXT), 1, {limit})")
                                       + " AS " + _quote_identifier(column) for column in columns)
                if getattr(detector, "_association_sink", None) is not None:
                    for column in pk:
                        identifier = _quote_identifier(column)
                        projection += f", typeof({identifier}), CASE WHEN typeof({identifier}) IN ('integer','real') THEN {identifier} ELSE NULL END"
                query = "SELECT " + projection + " FROM " + _quote_identifier(table)
                if pk:
                    query += " ORDER BY " + ", ".join(_quote_identifier(column) for column in pk)
                if not options["full_scan"]:
                    query += " LIMIT ?"
                deadline = time.monotonic() + options["statement_timeout_ms"] / 1000
                connection.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
                cursor = connection.execute(query, () if options["full_scan"] else (options["table_sample_rows"] + 1,))

                def rows():
                    while True:
                        batch = cursor.fetchmany(options["batch_size"])
                        if not batch:
                            return
                        yield from batch

                yield from _column_results(_database_location("main", table), columns, rows(), options=options, detector=detector,
                                           control=control, binary_columns=binary,
                                           patient_columns=patient_columns, evaluation_primary_keys=pk,
                                           metadata={"fixture_only": True, "read_only": True, "ordered_by_primary_key": bool(pk),
                                                     "patient_linkage_evidence": linkage_evidence})
                cursor.close()
            except Exception:
                yield _object(_database_location("main", table), "failed", "table_query_or_detection_failed", unit="rows", metadata={"fixture_only": True})
            finally:
                connection.set_progress_handler(None, 0)
        view_count = connection.execute("SELECT count(*) FROM sqlite_master WHERE type='view'").fetchone()[0]
        if view_count:
            yield _object("[views]", "excluded", "database_views_not_scanned", unit="rows", metadata={"view_count": view_count})
    except Exception:
        yield _object("[database]", "inaccessible", "fixture_connection_unavailable", unit="rows")
    finally:
        if connection is not None:
            connection.close()


def _postgresql(config, options, detector, control):
    try:
        from sqlalchemy import create_engine, inspect, text
        from sqlalchemy.engine import make_url
        from sqlalchemy.pool import NullPool
        from sqlalchemy.sql.sqltypes import LargeBinary
    except ImportError:
        yield _object("[database]", "failed", "sqlalchemy_dependency_missing", unit="rows")
        return
    dsn = config.get("dsn", "")
    schema = config.get("schema") or "public"
    engine = None
    try:
        url = make_url(dsn)
        if url.get_backend_name() != "postgresql" or not isinstance(schema, str):
            yield _object("[database]", "failed", "invalid_postgresql_configuration", unit="rows")
            return
        if url.drivername == "postgresql":
            url = url.set(drivername="postgresql+psycopg")
        if not url.host or not private_host(url.host):
            yield _object("[database]", "failed", "postgresql_endpoint_not_private", unit="rows")
            return
        # One unpooled connection; no shared mutable connection/session state.
        engine = create_engine(url, poolclass=NullPool, echo=False,
                               connect_args={"connect_timeout": 5}, hide_parameters=True)
        with engine.connect() as connection:
            with connection.begin():
                connection.execute(text("SET TRANSACTION READ ONLY"))
                connection.execute(text("SELECT set_config('statement_timeout', :value, true)"), {"value": str(options["statement_timeout_ms"])})
                connection.execute(text("SELECT set_config('lock_timeout', :value, true)"), {"value": str(options["lock_timeout_ms"])})
                inventory = inspect(connection)
                tables = inventory.get_table_names(schema=schema)
                selected = _selected_tables(tables, config)
                for table in sorted(set(config.get("tables") or []) - set(tables)):
                    yield _object(_database_location(schema, table), "inaccessible", "requested_table_not_discovered", unit="rows")
                for table in selected:
                    if not _running(control):
                        yield _cancelled()
                        return
                    # A savepoint allows a timed-out table to fail without losing inventory/session settings.
                    savepoint = connection.begin_nested()
                    try:
                        details = inventory.get_columns(table, schema=schema)
                        columns = [item["name"] for item in details]
                        binary = {item["name"] for item in details if isinstance(item["type"], LargeBinary)}
                        pk = inventory.get_pk_constraint(table, schema=schema).get("constrained_columns") or []
                        patient_columns, linkage_evidence = _patient_columns(table, inventory.get_foreign_keys(table, schema=schema), config)
                        cell_limit = min(options["max_text_chars"], 65536) + 1
                        projection = ", ".join(("NULL" if column in binary else f"left(CAST({_quote_identifier(column)} AS TEXT), :cell_limit)")
                                               + " AS " + _quote_identifier(column) for column in columns)
                        query = "SELECT " + projection + " FROM " + _quote_identifier(schema) + "." + _quote_identifier(table)
                        if pk:
                            query += " ORDER BY " + ", ".join(_quote_identifier(column) for column in pk)
                        if not options["full_scan"]:
                            query += " LIMIT :row_limit"
                        cursor = connection.execute(
                            text(query).execution_options(stream_results=True, yield_per=options["batch_size"]),
                            {"row_limit": options["table_sample_rows"] + 1, "cell_limit": cell_limit})
                        try:
                            yield from _column_results(_database_location(schema, table), columns, cursor, options=options,
                                                       detector=detector, control=control, binary_columns=binary,
                                                       patient_columns=patient_columns,
                                                       metadata={"read_only": True, "ordered_by_primary_key": bool(pk),
                                                                 "patient_linkage_evidence": linkage_evidence,
                                                                 "statement_timeout_ms": options["statement_timeout_ms"],
                                                                 "lock_timeout_ms": options["lock_timeout_ms"],
                                                                 "snapshot_consistency": "per_table_statement"})
                        finally:
                            cursor.close()
                        savepoint.commit()
                    except Exception:
                        savepoint.rollback()
                        yield _object(_database_location(schema, table), "failed", "table_query_or_detection_failed", unit="rows")
                views = inventory.get_view_names(schema=schema)
                if views:
                    yield _object("[views]", "excluded", "database_views_not_scanned", unit="rows", metadata={"view_count": len(views)})
    except Exception:
        yield _object("[database]", "inaccessible", "postgresql_connection_or_inventory_failed", unit="rows")
    finally:
        if engine is not None:
            engine.dispose()
