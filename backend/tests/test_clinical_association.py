from types import SimpleNamespace

from app.detection import Detector
from app.scanning import _column_results, _options


def health(findings):
    return [item for item in findings if item["entity_type"] == "HEALTH_INFORMATION"]


def test_distinct_patient_identifiers_are_ambiguous_even_across_types():
    for text in ("MRN: SYN100; MRN: SYN200; diagnosis: diabetes",
                 "MRN: SYN100; UHID: SYN200; diagnosis: diabetes"):
        results = health(Detector("rules").analyze(text))
        assert results and all(item["classification"] == "clinical_content" for item in results)
        assert results[0]["reason"] == "clinical_content_with_ambiguous_patient_references"


def test_distinct_identifiers_across_chunks_do_not_blindly_link_a_record():
    text = "MRN: SYN100; " + "word " * 2500 + "MRN: SYN200; diagnosis: diabetes"
    assert health(Detector("rules").analyze(text))[0]["classification"] == "clinical_content"


def test_staff_or_relative_name_is_not_a_patient_anchor():
    detector = Detector("rules")
    text = "Patient guidance. Doctor Demo Name discusses diabetes."
    detector._analyzer = SimpleNamespace(analyze=lambda **_: [SimpleNamespace(
        entity_type="PERSON", start=text.index("Demo Name"), end=text.index("Demo Name") + 9, score=.9)])
    assert health(detector.analyze(text))[0]["classification"] == "clinical_content"
    patient = "Patient Name: Demo Name; diagnosis: diabetes"
    detector._analyzer = SimpleNamespace(analyze=lambda **_: [SimpleNamespace(
        entity_type="PERSON", start=patient.index("Demo Name"), end=patient.index("Demo Name") + 9, score=.9)])
    assert health(detector.analyze(patient))[0]["classification"] == "patient_linked_health"


def test_explicit_patient_labels_survive_original_json_key_quotes():
    detector = Detector("rules")
    detector._analyzer = SimpleNamespace(analyze=lambda **kw: [SimpleNamespace(entity_type="PERSON",
        start=kw["text"].index("Demo Name"), end=kw["text"].index("Demo Name") + 9, score=.9)])
    assert health(detector.analyze('{"patient_name":"Demo Name","diagnosis":"diabetes"}'))[0]["classification"] == "patient_linked_health"
    findings = Detector("rules").analyze('{"patient_aadhaar":"234567890124","diagnosis":"diabetes"}')
    assert health(findings)[0]["classification"] == "patient_linked_health"


def test_unverified_page_layout_suppresses_links_without_losing_pii_or_clinical():
    findings = Detector("rules").analyze("MRN: SYN100; diabetes", context="patient_linkage_unverified")
    assert any(item["entity_type"] == "MRN" for item in findings)
    assert health(findings)[0]["classification"] == "clinical_content"
    assert health(findings)[0]["reason"] == "clinical_content_with_unverified_patient_layout"


def test_empty_database_clinical_cells_are_not_positive_from_column_label():
    objects = list(_column_results("main/records", ["MRN", "diagnosis"],
        [("SYN100", ""), ("SYN200", None), ("SYN300", "  ")], options=_options({}),
        detector=Detector("rules"), control=lambda: "running", metadata={}))
    assert objects[1]["findings"] == []


def test_private_association_events_do_not_change_default_retention():
    events = []
    detector = Detector("rules", _association_sink=events.append)
    with detector._association_context("synthetic.txt", document={"synthetic": True}):
        observed = detector.analyze("MRN: SYN100; diagnosis: diabetes")
    assert observed == Detector("rules").analyze("MRN: SYN100; diagnosis: diabetes")
    assert events[-1]["anchors"] == [("MRN", "SYN100")]
    assert all("anchors" not in finding and "evidence" not in finding for finding in observed)
    assert detector._association_scope is None
