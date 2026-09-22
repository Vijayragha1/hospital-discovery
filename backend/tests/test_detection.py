import builtins
import json

import pytest

from app.detection import Detector, DetectorUnavailable, source_segments, valid_aadhaar


def test_aadhaar_checksum_rejects_bad_and_repeated_numbers():
    # Standard Verhoeff-valid synthetic sequence; it is not an issuance assertion.
    assert valid_aadhaar("2345 6789 0124")
    assert not valid_aadhaar("2345 6789 0123")
    assert not valid_aadhaar("111111111111")
    assert not valid_aadhaar("23456789012499")


def test_indian_identifiers_and_never_values_in_findings():
    findings = Detector("rules").analyze(
        "Aadhaar: 2345 6789 0124, PAN: ABCPD1234E. ABHA: 91-1234-1234-1234. UHID: H123456."
    )
    kinds = {item["entity_type"] for item in findings}
    assert {"IN_AADHAAR", "IN_PAN", "ABHA", "UHID"} <= kinds
    serialized = json.dumps(findings)
    for value in ("2345", "ABCPD1234E", "H123456", "91-1234"):
        assert value not in serialized


def test_abha_address_insurance_and_overlapping_chunk_boundary():
    detector = Detector("rules")
    findings = detector.analyze("patient.demo@abdm insurance ID: INS123456")
    assert {item["entity_type"] for item in findings} == {"ABHA_ADDRESS", "INSURANCE_ID"}
    text = "x " * 5997 + "MRN: H123456. contact: sample@example.test " + "x " * 100
    findings = detector.analyze(text)
    assert sum(item["match_count"] for item in findings if item["entity_type"] == "MRN") == 1
    assert sum(item["match_count"] for item in findings if item["entity_type"] == "EMAIL_ADDRESS") == 1


@pytest.mark.parametrize("prefix_length", [11738, 11744, 11985, 11990, 11995])
def test_artificial_chunks_never_count_partial_identifiers(prefix_length):
    text = " " * prefix_length + "MRN: H1234567890 " + "x" * 400
    findings = Detector("rules").analyze(text)
    assert sum(item["match_count"] for item in findings if item["entity_type"] == "MRN") == 1


def test_installed_production_detector_operates_without_network(monkeypatch):
    spacy = pytest.importorskip("spacy")
    pytest.importorskip("presidio_analyzer")
    if not spacy.util.is_package("en_core_web_lg"):
        pytest.skip("Production model is provisioned separately for offline use")
    import socket

    def forbidden(*args, **kwargs):
        raise AssertionError("Network is disabled during local inference")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    source = "Patient John Smith. MRN: H12345. Diagnosis: diabetes. Contact: sample@example.test"
    findings = Detector().analyze(source, capture_evidence=True)
    assert {"PERSON", "MRN", "EMAIL_ADDRESS", "HEALTH_INFORMATION"} <= {item["entity_type"] for item in findings}
    person = next(item for item in findings if item["entity_type"] == "PERSON")
    assert person["evidence"][0]["value"] == "John Smith"
    assert source[person["evidence"][0]["start"]:person["evidence"][0]["end"]] == "John Smith"


def test_negative_nonclinical_content_and_bad_identifier():
    detector = Detector("rules")
    assert detector.analyze("The maintenance team replaced the elevator motor on Tuesday.") == []
    assert not any(item["entity_type"] == "IN_AADHAAR" for item in detector.analyze("Aadhaar: 234567890123"))


def test_clinical_article_is_not_automatically_patient_linked():
    findings = Detector("rules").analyze("This medical article reviews diabetes and hypertension.")
    assert {item["classification"] for item in findings} == {"clinical_content"}


def test_multi_patient_pages_and_paragraphs_do_not_cross_link():
    findings = Detector("rules").analyze("MRN: R12345\fResearch article about diabetes.")
    health = [item for item in findings if item["entity_type"] == "HEALTH_INFORMATION"]
    assert len(health) == 1
    assert health[0]["classification"] == "clinical_content"
    assert health[0]["segment"].startswith("segment:2/")
    both = Detector("rules").analyze("MRN: R12345. Diagnosis: diabetes.\fMRN: R54321. Diagnosis: hypertension.")
    health = [item for item in both if item["entity_type"] == "HEALTH_INFORMATION"]
    assert len(health) == 2
    assert all(item["classification"] == "patient_linked_health" for item in health)
    assert health[0]["segment"] != health[1]["segment"]


def test_database_clinical_field_context_and_patient_reference():
    detector = Detector("rules")
    findings = detector.analyze("diagnosis: example uncommon disorder", context="column diagnosis; patient_reference_present")
    assert findings[-1]["classification"] == "patient_linked_health"
    assert detector.analyze('{"mrn":"H123456"}')[0]["entity_type"] == "MRN"


def test_rules_mode_is_explicitly_limited_and_production_does_not_fallback(monkeypatch):
    assert not Detector("rules").capabilities["name_detection"]
    import hashlib
    from pathlib import Path
    import app.detection
    expected = hashlib.sha256(b"".join(name.encode() + b"\x00" + Path(app.detection.__file__).with_name(name).read_bytes()
                                       for name in ("detection.py", "extraction.py", "ocr_accounting.py", "pdf_reconciliation.py",
                                                    "document_channels.py", "document_layout.py", "document_analysis.py",
                                                    "scanning.py", "database_connectors.py", "cloud_connectors.py", "provenance.py"))).hexdigest()
    assert expected in Detector("rules").version
    original = builtins.__import__

    def unavailable(name, *args, **kwargs):
        if name == "spacy":
            raise ImportError("secret patient and DSN must not escape")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", unavailable)
    with pytest.raises(DetectorUnavailable, match="^presidio_or_local_model_unavailable$"):
        Detector()


def test_evidence_is_explicit_and_all_local_matches_are_actual_spans():
    text = ("Aadhaar: 2345 6789 0124; PAN: ABCPD1234E; ABHA: 91-1234-1234-1234; "
            "UHID: H123456; MRN: M567890; person.demo@abdm; insurance ID: INS123456; "
            "sample@example.test; phone: +91 9876543210; DOB: 1980-01-23; diabetes.")
    detector = Detector("rules")
    default = detector.analyze(text)
    assert default == detector.analyze(text, capture_evidence=False)
    assert all("evidence" not in finding for finding in default)
    for invalid in ("false", "true", 1, None):
        with pytest.raises(ValueError, match="^invalid_capture_evidence_option$"):
            detector.analyze(text, capture_evidence=invalid)
    findings = detector.analyze(text, capture_evidence=True)
    assert {item["entity_type"] for item in findings} == {
        "IN_AADHAAR", "IN_PAN", "ABHA", "UHID", "MRN", "ABHA_ADDRESS", "INSURANCE_ID",
        "EMAIL_ADDRESS", "PHONE_NUMBER", "DATE_OF_BIRTH", "HEALTH_INFORMATION"}
    assert [{k: v for k, v in item.items() if k != "evidence"} for item in findings] == default
    for finding in findings:
        assert finding["evidence"]
        for evidence in finding["evidence"]:
            assert evidence["value"] == text[evidence["start"]:evidence["end"]]
            assert evidence["value"] in evidence["excerpt"]
            assert len(evidence["value"]) <= 256 and len(evidence["excerpt"]) <= 400
            assert evidence["offset_scope"] == "segment"
            assert evidence["segment"] == finding["segment"]
    dob = next(item for item in findings if item["entity_type"] == "DATE_OF_BIRTH")
    assert dob["evidence"][0]["value"] == "1980-01-23"


@pytest.mark.parametrize("boundary", ["\f", "\n\n", "\n"])
def test_evidence_never_crosses_page_paragraph_or_patient_header(boundary):
    text = "MRN: A12345; first_patient_only diabetes." + boundary + "MRN: B67890; second_patient_only hypertension."
    segments = dict(source_segments(text))
    findings = Detector("rules").analyze(text, capture_evidence=True)
    assert len({finding["segment"] for finding in findings}) == 2
    for finding in findings:
        for evidence in finding["evidence"]:
            assert not ("first_patient_only" in evidence["excerpt"] and "second_patient_only" in evidence["excerpt"])
            assert segments[evidence["segment"]][evidence["start"]:evidence["end"]] == evidence["value"]


def test_evidence_caps_examples_and_deduplicates_overlap_with_segment_offsets():
    text = " " * 11990 + "MRN: H1234567890 " + " " * 400
    findings = Detector("rules").analyze(text, capture_evidence=True)
    mrn = next(item for item in findings if item["entity_type"] == "MRN")
    assert mrn["match_count"] == 1 and len(mrn["evidence"]) == 1
    assert mrn["evidence"][0]["start"] == text.index("H1234567890")
    text = "sample@example.test " * 6 + " " * 12000 + "other@example.test"
    email = next(item for item in Detector("rules").analyze(text, capture_evidence=True) if item["entity_type"] == "EMAIL_ADDRESS")
    assert email["match_count"] == 7
    assert len(email["evidence"]) == 3
    assert len({item["start"] for item in email["evidence"]}) == 3


def test_long_match_is_bounded_and_context_only_health_has_no_fabricated_evidence():
    from types import SimpleNamespace
    detector = Detector("rules")

    class Analyzer:
        def analyze(self, **_):
            return [SimpleNamespace(entity_type="PERSON", start=80, end=580, score=.9)]

    detector._analyzer = Analyzer()
    source = "x" * 80 + "Z" * 500 + "y" * 500
    finding = detector.analyze(source, capture_evidence=True)[0]
    evidence = finding["evidence"][0]
    assert len(evidence["value"]) == 256 and len(evidence["excerpt"]) == 400
    assert evidence["end"] - evidence["start"] == 500
    health = Detector("rules").analyze("an uncommon disorder", context="column diagnosis; patient_reference_present", capture_evidence=True)
    assert health[0]["classification"] == "patient_linked_health"
    assert health[0]["evidence"] == []


def test_patient_name_header_starts_an_independent_record():
    text = "MRN: A12345\nFIRST_RECORD_ONLY\nPatient Name: Anonymous Person\nSECOND_RECORD_ONLY diabetes"
    findings = Detector("rules").analyze(text, capture_evidence=True)
    health = [item for item in findings if item["entity_type"] == "HEALTH_INFORMATION"]
    assert health and all(item["classification"] == "clinical_content" for item in health)
    assert all(not ("FIRST_RECORD_ONLY" in example["excerpt"] and "SECOND_RECORD_ONLY" in example["excerpt"])
               for finding in findings for example in finding["evidence"])


@pytest.mark.parametrize("nested", [False, True])
def test_raw_json_api_never_propagates_outer_patient_context(nested):
    records = [{"mrn": "A12345", "notes": "FIRST_RECORD_ONLY"},
               {"notes": "SECOND_RECORD_ONLY diabetes"}]
    text = json.dumps({"outer_id": "OUTER123", "records": records} if nested else records)
    findings = Detector("rules").analyze(text, context="column payload; patient_reference_present", capture_evidence=True)
    health = [item for item in findings if item["entity_type"] == "HEALTH_INFORMATION"]
    assert health and all(item["classification"] == "clinical_content" for item in health)
    assert all(not ("FIRST_RECORD_ONLY" in example["excerpt"] and "SECOND_RECORD_ONLY" in example["excerpt"])
               for finding in findings for example in finding["evidence"])


@pytest.mark.parametrize("as_native_json", [False, True])
def test_database_structured_cells_keep_record_boundaries_and_evidence(as_native_json):
    from app.scanning import _column_results, _options
    records = [{"mrn": "A12345", "notes": "FIRST_RECORD_ONLY"},
               {"notes": "SECOND_RECORD_ONLY diabetes"}]
    value = records if as_native_json else json.dumps(records)
    objects = list(_column_results("main/reference", ["patient_id", "payload"], [("OUTER123", value)],
        options=_options({"capture_evidence": True}), detector=Detector("rules"), control=lambda: "running", metadata={}))
    payload = objects[1]
    assert payload["status"] == "full"
    health = [item for item in payload["findings"] if item["entity_type"] == "HEALTH_INFORMATION"]
    assert health and all(item["classification"] == "clinical_content" for item in health)
    evidence = [example for finding in payload["findings"] for example in finding["evidence"]]
    assert any(example["value"] == "A12345" for example in evidence)
    assert all(example["segment"].startswith("scan_row:1/") for example in evidence)
    assert all(not ("FIRST_RECORD_ONLY" in example["excerpt"] and "SECOND_RECORD_ONLY" in example["excerpt"]) for example in evidence)


def test_database_malformed_json_is_a_visible_partial_object():
    from app.scanning import _column_results, _options
    objects = list(_column_results("main/reference", ["patient_id", "payload"],
        [("OUTER123", '[{"mrn":"A12345"},{"notes":"diabetes"}')], options=_options({}),
        detector=Detector("rules"), control=lambda: "running", metadata={}))
    assert objects[1]["status"] == "partial"
    assert objects[1]["reason"] == "structured_cell_boundaries_unverified"
    assert not any(item["classification"] == "patient_linked_health" for item in objects[1]["findings"])


def test_database_abha_and_diagnosis_code_label_variants():
    from app.scanning import _column_results, _options
    objects = list(_column_results("main/reference", ["patient_id", "abha_number", "diagnosis_code"],
        [("OUTER123", "91-1234-1234-1234", "J18.9")], options=_options({}),
        detector=Detector("rules"), control=lambda: "running", metadata={}))
    assert any(item["entity_type"] == "ABHA" for item in objects[1]["findings"])
    assert any(item["reason"] == "clinical_content_with_ambiguous_patient_references" for item in objects[2]["findings"])
    single = list(_column_results("main/reference", ["abha_number", "diagnosis_code"],
        [("91-1234-1234-1234", "J18.9")], options=_options({}),
        detector=Detector("rules"), control=lambda: "running", metadata={}))
    assert any(item["classification"] == "patient_linked_health" for item in single[1]["findings"])
