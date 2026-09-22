"""Original synthetic sources exercise nested cells and unverified OCR layouts."""
import csv
import io
import json
import re
from types import SimpleNamespace

import pytest

from app.detection import Detector, source_segments
from app.extraction import ExtractionResult, extract_bytes
from app.scanning import scan_source


def csv_bytes(rows, delimiter=","):
    stream = io.StringIO(newline="")
    csv.writer(stream, delimiter=delimiter).writerows(rows)
    return stream.getvalue().encode()


def scan_original(tmp_path, data, suffix=".csv", detector=None):
    (tmp_path / ("original" + suffix)).write_bytes(data)
    objects = list(scan_source("filesystem", {"root": str(tmp_path)}, {"capture_evidence": True},
                               detector or Detector("rules"), lambda: "running"))
    assert len(objects) == 1
    return objects[0]


def clinical_events(events):
    return [event for event in events if event["event"] == "clinical"]


def evidence(result):
    return [example for finding in result["findings"] for example in finding.get("evidence", [])]


@pytest.mark.parametrize("suffix,delimiter", [(".csv", ","), (".tsv", "\t")])
@pytest.mark.parametrize("nested", [
    json.dumps([{"notes": "UNLINKED_ONLY diabetes"}, {"mrn": "INNER200", "notes": "INNER_ONLY hypertension"}], indent=2),
    '<records>\n<record><notes>UNLINKED_ONLY diabetes</notes></record>\n'
    '<record><mrn>INNER200</mrn><notes>INNER_ONLY hypertension</notes></record></records>',
])
def test_original_csv_nested_cells_preserve_scalar_and_inner_records(tmp_path, suffix, delimiter, nested):
    data = csv_bytes([["mrn", "notes", "payload"],
                      ["OUTER100", 'OUTER_ONLY\nquoted "remark", diabetes', nested],
                      ["NEXT300", "NEXT_ONLY hypertension", ""]], delimiter)
    events = []
    result = scan_original(tmp_path, data, suffix, Detector("rules", _association_sink=events.append))
    assert result["status"] == "full"
    clinical = clinical_events(events)
    linked = [event for event in clinical if event["classification"] == "patient_linked_health"]
    assert len(linked) == 3
    assert {tuple(event["anchors"][0]) for event in linked} == {
        ("MRN", "OUTER100"), ("MRN", "INNER200"), ("MRN", "NEXT300")}
    unlinked = [event for event in clinical if event["classification"] == "clinical_content"]
    assert len(unlinked) == 1 and unlinked[0]["anchors"] == []
    assert {example["value"] for example in evidence(result)} >= {"OUTER100", "INNER200", "NEXT300"}
    for example in evidence(result):
        assert sum(marker in example["excerpt"] for marker in
                   ("OUTER_ONLY", "UNLINKED_ONLY", "INNER_ONLY", "NEXT_ONLY")) <= 1


@pytest.mark.parametrize("nested", [
    '{"mrn":"INNER200","notes":"INNER_ONLY diabetes"',
    '<record><mrn>INNER200</mrn><notes>INNER_ONLY diabetes</record>',
])
def test_malformed_nested_csv_cell_is_partial_and_keeps_available_detections(tmp_path, nested):
    data = csv_bytes([["mrn", "payload"], ["OUTER100", nested]])
    extracted = extract_bytes(data, ".csv")
    assert extracted.metadata["structured_cell_boundaries_verified"] is False
    assert extracted.metadata["patient_linkage_context_verified"] is False
    result = scan_original(tmp_path, data)
    assert result["status"] == "partial"
    assert result["reason"] == "csv_structured_cell_boundaries_unverified"
    assert {finding["entity_type"] for finding in result["findings"]} >= {"MRN", "HEALTH_INFORMATION"}
    assert all(finding["classification"] != "patient_linked_health" for finding in result["findings"])
    assert all(not ("OUTER100" in example["excerpt"] and "INNER_ONLY" in example["excerpt"])
               for example in evidence(result))


def test_headerless_first_csv_nested_cell_is_retained_and_bounded():
    data = csv_bytes([["MRN: OUTER100", '{"notes":"UNLINKED_ONLY diabetes"}']])
    extracted = extract_bytes(data, ".csv")
    assert extracted.status == "full"
    assert extracted.metadata["first_record_retained"] is True
    assert extracted.metadata["structured_cells"] == 1
    findings = Detector("rules").analyze(extracted.text)
    assert {finding["entity_type"] for finding in findings} >= {"MRN", "HEALTH_INFORMATION"}
    assert all(finding["classification"] != "patient_linked_health" for finding in findings)
    bounded = extract_bytes(data, ".csv", {"max_text_chars": 20})
    assert bounded.status == "partial"
    assert len(bounded.text) <= 20


@pytest.mark.parametrize("suffix", [".png", ".tiff"])
def test_accounted_raster_completion_does_not_assert_patient_record_layout(tmp_path, monkeypatch, suffix):
    # The parser response is mocked here; live original-image OCR is a separate
    # integration check. Completing frames cannot prove a two-column association.
    monkeypatch.setenv("PAGE_OCR_URL", "http://127.0.0.1:9997")
    monkeypatch.setattr("app.ocr_accounting.extract_accounted", lambda *_: ExtractionResult(
        text="Record A             Record B\nMRN: SYN100          Diagnosis: diabetes",
        status="full", examined=1, unit="frames", metadata={"page_accounting_complete": True}))
    extracted = extract_bytes(b"synthetic raster", suffix)
    assert extracted.status == "full"
    assert extracted.metadata["patient_linkage_context_verified"] is False
    result = scan_original(tmp_path, b"synthetic raster", suffix)
    assert result["status"] == "full"
    assert any(finding["entity_type"] == "MRN" for finding in result["findings"])
    health = [finding for finding in result["findings"] if finding["entity_type"] == "HEALTH_INFORMATION"]
    assert health and all(finding["classification"] == "clinical_content" for finding in health)
    assert all(finding["reason"] == "clinical_content_with_unverified_patient_layout" for finding in health)


@pytest.mark.parametrize("separator", ["=", ":", "#"])
def test_explicit_patient_name_headers_isolate_actual_name_links_and_evidence(tmp_path, separator):
    events = []
    detector = Detector("rules", _association_sink=events.append)
    detector._analyzer = SimpleNamespace(analyze=lambda **kwargs: [
        SimpleNamespace(entity_type="PERSON", start=match.start(), end=match.end(), score=.99)
        for match in re.finditer(r"Demo (?:Alpha|Beta)", kwargs["text"])])
    text = (f"Patient Name {separator} Demo Alpha\nALPHA_ONLY diabetes\n"
            f"Patient Name {separator} Demo Beta\nBETA_ONLY hypertension")
    result = scan_original(tmp_path, text.encode(), ".txt", detector)
    clinical = clinical_events(events)
    assert len(clinical) == 2
    assert all(event["classification"] == "patient_linked_health" for event in clinical)
    assert {tuple(event["anchors"][0]) for event in clinical} == {("PERSON", "Demo Alpha"), ("PERSON", "Demo Beta")}
    assert all(not ("ALPHA_ONLY" in example["excerpt"] and "BETA_ONLY" in example["excerpt"])
               for example in evidence(result))


@pytest.mark.parametrize("newline", ["\n", "\r\n", "\r"])
def test_equals_patient_header_does_not_inherit_prior_records_identifier(newline):
    text = newline.join(["MRN: SYN100", "Administrative record only",
                         "Patient Name = Demo Other", "Diagnosis: diabetes"])
    assert len(list(source_segments(text))) == 2
    findings = Detector("rules").analyze(text)
    health = [finding for finding in findings if finding["entity_type"] == "HEALTH_INFORMATION"]
    assert health and all(finding["classification"] == "clinical_content" for finding in health)


@pytest.mark.parametrize("newline", ["\n", "\r\n", "\r"])
def test_single_line_break_preserves_own_record_but_blank_paragraph_separates(newline):
    for separator, expected in [(newline, "patient_linked_health"),
                                (newline + " \t" + newline, "clinical_content")]:
        text = "MRN: SYN100" + separator + "Diagnosis: diabetes"
        segments = list(source_segments(text))
        assert len(segments) == (1 if separator == newline else 2)
        # Source text is not normalized: v3 references use original offsets.
        if separator == newline:
            assert segments[0][1] == text
        health = [finding for finding in Detector("rules").analyze(text)
                  if finding["entity_type"] == "HEALTH_INFORMATION"]
        assert health and all(finding["classification"] == expected for finding in health)


@pytest.mark.parametrize("prose", ["The patient name = a database field", "Patient Name is a database field"])
def test_patient_name_prose_does_not_create_an_arbitrary_record_boundary(prose):
    segments = list(source_segments("First line\n" + prose + "\nlast line"))
    assert len(segments) == 1


def test_equals_patient_aadhaar_label_remains_a_supported_patient_anchor():
    findings = Detector("rules").analyze("Patient Aadhaar = 234567890124; diagnosis: diabetes")
    health = [finding for finding in findings if finding["entity_type"] == "HEALTH_INFORMATION"]
    assert health and all(finding["classification"] == "patient_linked_health" for finding in health)
