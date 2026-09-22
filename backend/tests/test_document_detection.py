"""Patient association and evidence stay within one inferred geometric record."""
import pytest

from app.detection import Detector


PREFIX = "frame:1/channel:ocr/region:1"


def health(rows):
    return [row for row in rows if row["entity_type"] == "HEALTH_INFORMATION"]


def test_labelled_record_can_link_across_its_own_demographic_and_clinical_paragraphs():
    detector = Detector("rules")
    rows = detector.analyze_layout_region("UHID: FX100001\n\nDiagnosis: diabetes", prefix=PREFIX,
        association_candidate=True, capture_evidence=True)
    assert health(rows)[0]["classification"] == "patient_linked_health"
    assert health(rows)[0]["segment"] == PREFIX + "/record"
    assert all(row["segment"] == PREFIX + "/record" for row in rows)
    assert detector._layout_scope is None


@pytest.mark.parametrize("identifier", ["AB1234@abdm", "Previous UHID: FX100001", "Doctor MRN: FX100001"])
def test_bare_or_narrative_identifiers_never_anchor_a_document_record(identifier):
    rows = Detector("rules").analyze_layout_region(identifier + "\nDiagnosis: diabetes", prefix=PREFIX,
        association_candidate=True)
    assert any(row["classification"] == "personal_data" for row in rows)
    assert all(row["classification"] == "clinical_content" for row in health(rows))


def test_distinct_identifiers_inside_one_region_are_ambiguous():
    rows = Detector("rules").analyze_layout_region("UHID: FX100001\nMRN: FX200002\nDiagnosis: diabetes",
        prefix=PREFIX, association_candidate=True)
    assert health(rows)[0]["classification"] == "clinical_content"
    assert health(rows)[0]["reason"] == "clinical_content_with_ambiguous_patient_references"


def test_residuals_do_not_gain_linkage_and_a_later_region_cannot_inherit_an_anchor():
    detector = Detector("rules")
    first = detector.analyze_layout_region("UHID: FX100001\nDiagnosis: diabetes", prefix=PREFIX,
        association_candidate=False)
    assert health(first)[0]["reason"] == "clinical_content_with_unverified_patient_layout"
    later = detector.analyze_layout_region("Diagnosis: diabetes", prefix="frame:2/channel:ocr/region:1",
        association_candidate=True)
    assert health(later)[0]["classification"] == "clinical_content"


def test_original_region_ids_scope_observers_and_examples_without_crossing_records():
    observations, associations = [], []
    detector = Detector("rules", _observation_sink=observations.append, _association_sink=associations.append)
    with detector._association_context("synthetic.png", document={}):
        with detector._observation_context("synthetic.png"):
            first = detector.analyze_layout_region("UHID: FX100001\nDiagnosis: diabetes", prefix=PREFIX,
                association_candidate=True, capture_evidence=True)
            second = detector.analyze_layout_region("UHID: FX200002\nDiagnosis: asthma",
                prefix="frame:1/channel:ocr/region:2", association_candidate=True, capture_evidence=True)
    assert {row["segment"] for row in first}.isdisjoint(row["segment"] for row in second)
    assert all("FX200002" not in example["excerpt"] for row in first for example in row["evidence"])
    assert all("FX100001" not in example["excerpt"] for row in second for example in row["evidence"])
    events = [event for event in associations if event["event"] == "clinical"]
    assert [event["anchors"] for event in events] == [[("UHID", "FX100001")], [("UHID", "FX200002")]]
    assert [event["source_segment"] for event in events] == [PREFIX + "/record", "frame:1/channel:ocr/region:2/record"]
    assert {event["segment"] for event in observations} == {row["segment"] for row in first + second}


def test_invalid_region_prefix_rejected_and_scope_restored_on_detector_failure(monkeypatch):
    detector = Detector("rules")
    with pytest.raises(ValueError, match="invalid_document_region"):
        detector.analyze_layout_region("synthetic", prefix="contains patient text", association_candidate=True)
    def fail(*args, **kwargs):
        raise RuntimeError("synthetic failure")
    monkeypatch.setattr(detector, "analyze", fail)
    with pytest.raises(RuntimeError, match="synthetic failure"):
        detector.analyze_layout_region("synthetic", prefix=PREFIX, association_candidate=True)
    assert detector._layout_scope is None
