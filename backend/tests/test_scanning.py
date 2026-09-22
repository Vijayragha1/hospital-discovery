import json
import sqlite3

from app.detection import Detector
from app.scanning import scan_source


def scan(kind, config, options=None, control=lambda: "running", detector=None):
    return list(scan_source(kind, config, options or {}, detector or Detector("rules"), control))


def test_filesystem_symlink_escape_and_stable_value_free_findings(tmp_path):
    root = (tmp_path / "approved").resolve()
    root.mkdir()
    (root / "notes.txt").write_text("MRN: H123456. Diagnosis: diabetes.")
    secret = tmp_path / "outside.txt"
    secret.write_text("outside@example.test")
    (root / "escape.txt").symlink_to(secret)
    results = scan("filesystem", {"root": str(root)})
    by_path = {item["location"]: item for item in results}
    assert by_path["escape.txt"]["reason"] == "symlink_excluded"
    assert not by_path["escape.txt"]["findings"]
    assert by_path["notes.txt"]["status"] == "full"
    assert by_path["notes.txt"]["findings"]
    output = json.dumps(results)
    assert "H123456" not in output
    assert "outside@example.test" not in output
    again = scan("filesystem", {"root": str(root)})
    assert {item["object_key"] for item in results} == {item["object_key"] for item in again}


def test_file_limits_and_cancellation(tmp_path):
    root = tmp_path.resolve()
    (root / "large.txt").write_text("a" * 50)
    limited = scan("filesystem", {"root": str(root)}, {"max_file_bytes": 10})
    assert limited[0]["reason"] == "file_size_limit"
    (root / "second.txt").write_text("ok")
    limited = scan("filesystem", {"root": str(root)}, {"max_files": 1})
    assert limited[-1]["reason"] == "file_limit_reached"
    cancelled = scan("filesystem", {"root": str(root)}, control=lambda: "cancelled")
    assert cancelled[0]["reason"] == "scan_cancelled"


def test_root_symlink_and_parent_traversal_rejected(tmp_path):
    root = tmp_path.resolve()
    link = root / "alias"
    link.symlink_to(root, target_is_directory=True)
    assert scan("filesystem", {"root": str(link)})[0]["reason"] == "root_unavailable_or_symlink"
    assert scan("filesystem", {"root": str(root) + "/../" + root.name})[0]["reason"] == "root_unavailable_or_symlink"
    assert scan("smb", {"server": "host", "share": "approved", "subpath": "../other"})[0]["reason"] == "invalid_smb_path"


def make_database(path):
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE visits (id INTEGER PRIMARY KEY, mrn TEXT, diagnosis TEXT, notes TEXT, attachment BLOB)")
        connection.executemany("INSERT INTO visits VALUES (?, ?, ?, ?, ?)", [
            (1, "H123456", "diabetes", "first note", b"secret attachment"),
            (2, "H223456", "hypertension", "second note", None),
            (3, "H323456", "carcinoma", "third note", None),
        ])


def test_sqlite_is_read_only_sampling_and_row_context(tmp_path):
    path = (tmp_path / "fixture.sqlite").resolve()
    make_database(path)
    before = path.read_bytes()
    results = scan("sqlite", {"path": str(path)}, {"table_sample_rows": 2})
    by_path = {item["location"]: item for item in results}
    assert path.read_bytes() == before
    assert by_path["main/visits/diagnosis"]["status"] == "sampled"
    assert by_path["main/visits/diagnosis"]["examined"] == 2
    assert by_path["main/visits/diagnosis"]["findings"][0]["classification"] == "patient_linked_health"
    assert by_path["main/visits/attachment"]["status"] == "unsupported"
    assert all(item["metadata"]["read_only"] for item in results)
    assert "H123456" not in json.dumps(results)
    assert "first note" not in json.dumps(results)


def test_sqlite_cell_truncation_and_table_filter_injection_are_visible(tmp_path):
    path = (tmp_path / "fixture.sqlite").resolve()
    make_database(path)
    results = scan("sqlite", {"path": str(path)}, {"max_text_chars": 5})
    assert any(item["reason"] == "cell_text_limit_reached" for item in results)
    missing = scan("sqlite", {"path": str(path), "tables": ['visits"; DROP TABLE visits;--']})
    assert missing[0]["reason"] == "requested_table_not_discovered"
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT count(*) FROM visits").fetchone()[0] == 3


def test_changed_file_during_detector_work_is_partial(tmp_path):
    root = tmp_path.resolve()
    path = root / "changing.txt"
    path.write_text("ordinary text")

    class ChangingDetector:
        def analyze(self, _):
            path.write_text("different and longer text")
            return []

    result = scan("filesystem", {"root": str(root)}, detector=ChangingDetector())[0]
    assert result["reason"] == "file_changed_during_scan"
    assert result["status"] == "partial"
    assert not result["metadata"]["source_stable"]


def test_full_scan_request_cannot_remove_production_sampling_cap():
    assert scan("sqlite", {"path": "/unused"}, {"full_scan": True})[0]["reason"] == "full_scan_not_approved"
    assert scan("sqlite", {"path": "/unused", "full_scan_allowed": True}, {"full_scan": True})[0]["reason"] == "full_scan_requires_explicit_tables"
    assert scan("sqlite", {"path": "/unused"}, {"table_sample_rows": 1001})[0]["reason"] == "invalid_scan_options"


def test_database_location_identity_cannot_collide_on_legal_identifier_slashes(tmp_path):
    path = (tmp_path / "identifiers.sqlite").resolve()
    with sqlite3.connect(path) as connection:
        connection.execute('CREATE TABLE "a/b" ("c" TEXT)')
        connection.execute('CREATE TABLE "a" ("b/c" TEXT)')
        connection.execute('INSERT INTO "a/b" VALUES (\'first@example.test\')')
        connection.execute('INSERT INTO "a" VALUES (\'second@example.test\')')
    results = scan("sqlite", {"path": str(path)})
    assert len(results) == 2
    assert len({item["object_key"] for item in results}) == 2
    assert {item["location"] for item in results} == {"main/a%2Fb/c", "main/a/b%2Fc"}


def test_explicit_full_scan_streams_beyond_sample_limit_and_honors_cancel(tmp_path):
    path = (tmp_path / "fixture.sqlite").resolve()
    make_database(path)
    config = {"path": str(path), "tables": ["visits"], "full_scan_allowed": True}
    full = scan("sqlite", config, {"full_scan": True, "table_sample_rows": 1, "batch_size": 1})
    inspected = [item for item in full if item["status"] != "unsupported"]
    assert inspected and all(item["status"] == "full" and item["examined"] == 3 for item in inspected)
    assert all(item["metadata"]["sampling_method"] == "full_stream" for item in inspected)
    calls = 0

    def control():
        nonlocal calls
        calls += 1
        return "running" if calls <= 2 else "cancelled"

    cancelled = scan("sqlite", config, {"full_scan": True, "batch_size": 1}, control=control)
    assert cancelled and all(item["status"] == "partial" for item in cancelled)
    assert all(item["reason"] == "scan_cancelled" for item in cancelled)


def test_declared_foreign_key_and_explicit_hospital_identifier_context(tmp_path):
    path = (tmp_path / "fixture.sqlite").resolve()
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE patients (id INTEGER PRIMARY KEY)")
        connection.execute("CREATE TABLE labs (id INTEGER PRIMARY KEY, subject INTEGER REFERENCES patients(id), diagnosis TEXT)")
        connection.execute("INSERT INTO patients VALUES (1)")
        connection.execute("INSERT INTO labs VALUES (1, 1, 'uncommon clinical condition')")
        connection.execute("CREATE TABLE custom_labs (local_ref TEXT, diagnosis TEXT)")
        connection.execute("INSERT INTO custom_labs VALUES ('X123', 'uncommon clinical condition')")
    results = scan("sqlite", {"path": str(path), "patient_identifier_columns": {"custom_labs": ["local_ref"]}})
    diagnoses = [item for item in results if item["location"].endswith("/diagnosis")]
    assert len(diagnoses) == 2
    assert all(item["findings"][0]["classification"] == "patient_linked_health" for item in diagnoses)
    assert all(item["metadata"]["patient_linkage_evidence"] for item in diagnoses)
    references = [item for item in results if item["location"].endswith(("/subject", "/local_ref"))]
    assert len(references) == 2
    assert all(any(finding["entity_type"] == "PATIENT_REFERENCE" for finding in item["findings"]) for item in references)


def test_file_evidence_opt_in_and_extraction_limit_are_enforced(tmp_path):
    root = tmp_path.resolve()
    (root / "notes.txt").write_text("MRN: H123456; diabetes\fMRN: H999999; hypertension")
    assert all("evidence" not in finding for result in scan("filesystem", {"root": str(root)}) for finding in result["findings"])
    results = scan("filesystem", {"root": str(root)}, {"capture_evidence": True, "max_text_chars": 21})
    assert results[0]["status"] == "partial"
    evidence = [example for finding in results[0]["findings"] for example in finding["evidence"]]
    assert any(item["value"] == "H123456" for item in evidence)
    assert "H999999" not in json.dumps(results)
    for invalid in ("true", "false", 1, None):
        assert scan("filesystem", {"root": str(root)}, {"capture_evidence": invalid})[0]["reason"] == "invalid_scan_options"


def test_database_evidence_is_actual_cell_content_and_bounded_across_rows(tmp_path):
    path = (tmp_path / "evidence.sqlite").resolve()
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE visits (id INTEGER PRIMARY KEY, mrn TEXT, diagnosis TEXT, dob TEXT, notes TEXT)")
        connection.executemany("INSERT INTO visits VALUES (?, ?, ?, ?, ?)", [
            (index, f"H1234{index}", "diabetes" if index != 2 else "uncommon condition",
             "1980-01-23", f"ONLY_RECORD_{index} first{index}@example.test\fSECOND_SEGMENT_{index} other{index}@example.test")
            for index in range(1, 6)])
    config = {"path": str(path)}
    before = path.read_bytes()
    without = scan("sqlite", config)
    results = scan("sqlite", config, {"capture_evidence": True})
    assert path.read_bytes() == before
    by_path = {item["location"]: item for item in results}
    all_examples = [example for item in results for finding in item["findings"] for example in finding["evidence"]]
    assert all(example["offset_scope"] == "segment" and example["segment"].startswith("scan_row:") for example in all_examples)
    assert all(len(finding["evidence"]) <= 3 for item in results for finding in item["findings"])
    mrn = by_path["main/visits/mrn"]["findings"][0]
    assert mrn["match_count"] == 5 and len(mrn["evidence"]) == 3
    assert [item["value"] for item in mrn["evidence"]] == ["H12341", "H12342", "H12343"]
    assert all(item["excerpt"] == item["value"] and item["start"] == 0 for item in mrn["evidence"])
    health = by_path["main/visits/diagnosis"]["findings"][0]
    assert health["classification"] == "patient_linked_health"
    assert all(item["value"] == item["excerpt"] == "diabetes" for item in health["evidence"])
    assert all("scan_row:2/" not in item["segment"] for item in health["evidence"])
    dob = by_path["main/visits/dob"]["findings"][0]
    assert all(item["value"] == "1980-01-23" and item["start"] == 0 and item["end"] == 10 for item in dob["evidence"])
    notes = by_path["main/visits/notes"]["findings"][0]
    assert len(notes["evidence"]) == 3 and notes["match_count"] == 10
    for item in notes["evidence"]:
        assert not ("ONLY_RECORD" in item["excerpt"] and "SECOND_SEGMENT" in item["excerpt"])
        assert "H1234" not in item["excerpt"] and "diagnosis:" not in item["excerpt"] and "notes:" not in item["excerpt"]
    clean_results = [{**item, "findings": [{k: v for k, v in finding.items() if k != "evidence"}
                                         for finding in item["findings"]]} for item in results]
    assert clean_results == without


def test_metadata_only_findings_have_no_fabricated_value_evidence(tmp_path):
    path = (tmp_path / "metadata.sqlite").resolve()
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE labs (subject INTEGER, diagnosis TEXT)")
        connection.execute("INSERT INTO labs VALUES (42, 'uncommon disorder')")
    results = scan("sqlite", {"path": str(path), "patient_identifier_columns": {"labs": ["subject"]}}, {"capture_evidence": True})
    findings = [finding for item in results for finding in item["findings"]]
    assert {item["entity_type"] for item in findings} == {"PATIENT_REFERENCE", "HEALTH_INFORMATION"}
    assert all(item["evidence"] == [] for item in findings)
    assert "uncommon disorder" not in json.dumps(results)


def test_enabled_evidence_still_never_echoes_raw_exceptions(tmp_path, caplog):
    root = tmp_path.resolve()
    (root / "notes.txt").write_text("MRN: H123456")

    class BrokenDetector:
        def analyze(self, *_, **__):
            raise RuntimeError("private patient content and secret password")

    results = scan("filesystem", {"root": str(root)}, {"capture_evidence": True}, detector=BrokenDetector())
    assert results[0]["status"] == "failed"
    assert "private patient" not in json.dumps(results) + caplog.text
