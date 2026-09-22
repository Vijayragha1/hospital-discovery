"""Compare recorded finding groups without treating missing coverage as removal."""
import hashlib
import json

from cryptography.fernet import Fernet
import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session

from app import comparison
from app.db import Base
from app.models import Finding, FindingEvidence, Scan, ScanObject, Source
from test_api import scan, source_and_policy, system  # noqa: F401 — shared isolated API fixture


KNOWN = "test-detector/runtime-local-" + "a" * 64
OTHER_KNOWN = "test-detector/runtime-local-" + "b" * 64


@pytest.fixture
def catalog(monkeypatch):
    cipher = Fernet(Fernet.generate_key())

    def encrypt(value):
        return cipher.encrypt(json.dumps(value).encode()).decode()

    monkeypatch.setattr(comparison, "decrypt", lambda value: json.loads(cipher.decrypt(value.encode())))
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        source = Source(name_encrypted=encrypt("Synthetic source"), kind="filesystem",
                        config_encrypted=encrypt({"secret": "SOURCE_SECRET_MUST_NOT_APPEAR"}))
        db.add(source)
        db.flush()
        old = Scan(source_id=source.id, status="completed", detector_version=KNOWN, options={})
        new = Scan(source_id=source.id, status="completed", detector_version=KNOWN, options={})
        db.add_all([old, new])
        db.flush()

        def add(scan, location="synthetic.txt", status="full", examined=100, fingerprint="same", findings=()):
            obj = ScanObject(scan_id=scan.id, object_key=hashlib.sha256(location.encode()).hexdigest(),
                             location_encrypted=encrypt(location), status=status, examined=examined,
                             unit="characters", fingerprint=fingerprint, metadata_encrypted=encrypt({}))
            db.add(obj)
            db.flush()
            for value in findings:
                kind, count, *detail = value
                classification = detail[0] if detail else "personal_data"
                reason = detail[1] if len(detail) > 1 else "synthetic_recognizer"
                segment = detail[2] if len(detail) > 2 else "segment:1"
                finding = Finding(scan_id=scan.id, object_id=obj.id, entity_type=kind,
                                  classification=classification, confidence=.9, match_count=count,
                                  reason_encrypted=encrypt(reason), segment_encrypted=encrypt(segment))
                db.add(finding)
                db.flush()
                db.add(FindingEvidence(finding_id=finding.id,
                    payload_encrypted=encrypt({"value": "RAW_MATCH_MUST_NOT_APPEAR", "excerpt": "RAW_EXCERPT_MUST_NOT_APPEAR"})))
            db.flush()
            return obj

        yield db, old, new, add
    engine.dispose()


def test_removed_finding_type_is_visible_when_another_type_remains(catalog):
    db, old, new, add = catalog
    add(old, findings=[("MRN", 2), ("EMAIL_ADDRESS", 1)])
    add(new, fingerprint="new", findings=[("EMAIL_ADDRESS", 1)])
    result = comparison.compare_scans(db, old, new)
    assert result["summary"] == {"changed": 1}
    assert result["finding_summary"] == {"unchanged": 1, "no_longer_observed": 1}
    item = result["changes"][0]
    assert item["finding_comparison"] == "comparable"
    mrn = next(delta for delta in item["finding_deltas"] if delta["entity_type"] == "MRN")
    assert mrn == {"entity_type": "MRN", "classification": "personal_data", "reason": "synthetic_recognizer",
                   "segment": "segment:1", "before_count": 2, "after_count": 0, "change": "no_longer_observed"}


def test_new_finding_type_and_changed_match_count_are_separate(catalog):
    db, old, new, add = catalog
    add(old, findings=[("MRN", 1)])
    add(new, findings=[("MRN", 3), ("EMAIL_ADDRESS", 1)])
    result = comparison.compare_scans(db, old, new)
    assert result["finding_summary"] == {"changed": 1, "new": 1}
    rows = {item["entity_type"]: item for item in result["changes"][0]["finding_deltas"]}
    assert (rows["MRN"]["before_count"], rows["MRN"]["after_count"]) == (1, 3)
    assert (rows["EMAIL_ADDRESS"]["before_count"], rows["EMAIL_ADDRESS"]["after_count"]) == (0, 1)
    assert result["finding_summary_unit"] == "finding_groups"
    assert result["finding_count_unit"] == "recognizer_matches_not_unique_values_or_patients"


def test_new_full_object_can_report_new_observations_after_complete_baseline(catalog):
    db, old, new, add = catalog
    add(old, findings=[])
    add(new, findings=[])
    add(new, location="new-object.txt", findings=[("MRN", 1)])
    result = comparison.compare_scans(db, old, new)
    row = next(item for item in result["changes"] if item["location"] == "new-object.txt")
    assert row["change"] == "new" and row["finding_comparison"] == "comparable"
    assert row["finding_deltas"][0]["change"] == "new"
    assert "not necessarily newly created" in row["finding_comparison_reason"]


def test_new_object_after_baseline_gap_has_no_attributed_finding_delta(catalog):
    db, old, new, add = catalog
    add(old, location="[root]", status="inaccessible")
    add(new, findings=[("MRN", 1)])
    result = comparison.compare_scans(db, old, new)
    row = next(item for item in result["changes"] if item["location"] == "synthetic.txt")
    assert row["finding_comparison"] == "not_comparable" and row["finding_deltas"] == []
    assert "baseline has coverage gaps" in row["finding_comparison_reason"]


def test_absent_object_never_implies_removed_findings_even_after_full_other_reads(catalog):
    db, old, new, add = catalog
    add(old, location="absent.txt", findings=[("MRN", 1)])
    add(old, location="retained.txt")
    add(new, location="retained.txt")
    result = comparison.compare_scans(db, old, new)
    row = next(item for item in result["changes"] if item["location"] == "absent.txt")
    assert row["change"] == "coverage_lost"
    assert row["finding_comparison"] == "not_comparable" and row["finding_deltas"] == []
    assert not result["finding_summary"]


@pytest.mark.parametrize("before,after", [
    ("full", "sampled"), ("sampled", "sampled"), ("sampled", "full"),
    ("full", "partial"), ("partial", "full"), ("partial", "partial"),
    ("full", "inaccessible"), ("full", "unsupported"), ("full", "excluded"), ("full", "failed"),
])
def test_incomplete_read_never_produces_disappearing_finding_delta(catalog, before, after):
    db, old, new, add = catalog
    add(old, status=before, findings=[("MRN", 1)])
    add(new, status=after, examined=20, findings=[])
    result = comparison.compare_scans(db, old, new)
    row = result["changes"][0]
    assert row["finding_comparison"] == "not_comparable"
    assert row["finding_deltas"] == [] and result["finding_summary"] == {}
    assert row["change"] != "no_longer_observed"


@pytest.mark.parametrize("change", ["detector", "policy", "legacy", "pending", "unverified"])
def test_detector_policy_and_unknown_provenance_block_finding_attribution(catalog, change):
    db, old, new, add = catalog
    add(old, findings=[("MRN", 1)])
    add(new, findings=[("EMAIL_ADDRESS", 1)])
    if change == "detector":
        new.detector_version = OTHER_KNOWN
    elif change == "policy":
        new.options = {"max_text_chars": 100}
    else:
        old.detector_version = new.detector_version = {
            "legacy": "hospital-rules/1.0+sha256-test", "pending": "pending",
            "unverified": "test-detector/runtime-unverified"}[change]
    result = comparison.compare_scans(db, old, new)
    assert result["summary"] == {"not_comparable": 1}
    assert result["changes"][0]["finding_deltas"] == []
    assert result["detector_provenance_unknown"] is (change in {"legacy", "pending", "unverified"})
    if result["detector_provenance_unknown"]:
        assert result["changes"][0]["finding_comparison_reason"] == "Processing runtime identity was not recorded; run a new baseline."


@pytest.mark.parametrize("change", ["detector", "policy", "provenance"])
def test_new_object_is_not_attributed_when_detector_or_policy_does_not_compare(catalog, change):
    db, old, new, add = catalog
    add(new, findings=[("MRN", 1)])
    if change == "detector":
        new.detector_version = OTHER_KNOWN
    elif change == "policy":
        new.options = {"max_text_chars": 100}
    else:
        old.detector_version = new.detector_version = "legacy"
    result = comparison.compare_scans(db, old, new)
    assert result["changes"][0]["change"] == "not_comparable"
    assert result["changes"][0]["finding_deltas"] == []


def test_evidence_capture_policy_alone_does_not_change_finding_comparability(catalog):
    db, old, new, add = catalog
    old.options = {"capture_evidence": False}
    new.options = {"capture_evidence": True}
    add(old, findings=[("MRN", 1)])
    add(new, findings=[("MRN", 1)])
    result = comparison.compare_scans(db, old, new)
    assert result["options_changed"] is False
    assert result["changes"][0]["finding_deltas"][0]["change"] == "unchanged"


def test_classification_reason_and_segment_are_part_of_finding_identity(catalog):
    db, old, new, add = catalog
    add(old, findings=[("HEALTH_INFORMATION", 1, "clinical_content", "terms", "segment:1"),
                       ("MRN", 1, "personal_data", "pattern", "segment:1")])
    add(new, findings=[("HEALTH_INFORMATION", 1, "patient_linked_health", "patient_reference", "segment:1"),
                       ("MRN", 1, "personal_data", "pattern", "segment:2")])
    result = comparison.compare_scans(db, old, new)
    assert result["finding_summary"] == {"no_longer_observed": 2, "new": 2}
    assert len(result["changes"][0]["finding_deltas"]) == 4


def test_duplicate_finding_groups_aggregate_counts_without_raw_evidence_access(catalog):
    db, old, new, add = catalog
    add(old, findings=[("MRN", 1), ("MRN", 2)])
    add(new, findings=[("MRN", 3)])

    def deny_evidence_read(_, __, statement, ___, ____, _____):
        assert "finding_evidence" not in statement.lower()

    event.listen(db.bind, "before_cursor_execute", deny_evidence_read)
    result = comparison.compare_scans(db, old, new)
    event.remove(db.bind, "before_cursor_execute", deny_evidence_read)
    delta = result["changes"][0]["finding_deltas"][0]
    assert (delta["before_count"], delta["after_count"], delta["change"]) == (3, 3, "unchanged")
    serialized = json.dumps(result)
    assert all(secret not in serialized for secret in
               ("RAW_MATCH_MUST_NOT_APPEAR", "RAW_EXCERPT_MUST_NOT_APPEAR", "SOURCE_SECRET_MUST_NOT_APPEAR"))


@pytest.mark.parametrize("status", ["queued", "running", "paused", "interrupted", "cancelled", "failed"])
def test_unfinished_scan_still_cannot_be_compared(catalog, status):
    db, old, new, _ = catalog
    new.status = status
    with pytest.raises(ValueError, match="Both scans must be completed"):
        comparison.compare_scans(db, old, new)


def test_original_files_reach_finding_deltas_through_authenticated_api(system):
    client, folder, _ = system
    document = folder / "reference.txt"
    document.write_text("MRN: SYN12345; first@example.test")
    source = source_and_policy(client, folder)
    baseline = scan(client, source, capture_evidence=True)
    document.write_text("UHID: SYN67890; first@example.test; second@example.test")
    current = scan(client, source, capture_evidence=True)
    response = client.get("/api/compare", params={"baseline": baseline["id"], "current": current["id"]})
    assert response.status_code == 200
    result = response.json()
    assert result["detector_provenance_unknown"] is False
    assert result["summary"] == {"changed": 1}
    rows = {row["entity_type"]: row for row in result["changes"][0]["finding_deltas"]}
    assert rows["MRN"]["change"] == "no_longer_observed"
    assert rows["UHID"]["change"] == "new"
    assert (rows["EMAIL_ADDRESS"]["before_count"], rows["EMAIL_ADDRESS"]["after_count"]) == (1, 2)
    assert rows["EMAIL_ADDRESS"]["change"] == "changed"
    assert all(value not in response.text for value in ("SYN12345", "SYN67890", "first@example.test", "second@example.test"))
