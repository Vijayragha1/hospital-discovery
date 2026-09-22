import json
import pytest

from app.detection import Detector
from app.extraction import extract_bytes


def test_native_text_truncation_and_invalid_encoding():
    result = extract_bytes(b"patient data follows", ".txt", {"max_text_chars": 7})
    assert result.text == "patient"
    assert result.status == "partial"
    assert result.reason == "text_limit_reached"
    invalid = extract_bytes(b"hello\xff", ".txt")
    assert invalid.status == "partial"
    assert invalid.reason == "encoding_replacement"


def test_archives_not_automatically_extracted_and_tika_is_explicit(monkeypatch):
    monkeypatch.delenv("TIKA_URL", raising=False)
    assert extract_bytes(b"fake", ".zip").status == "excluded"
    assert extract_bytes(b"%PDF", ".pdf").reason == "tika_not_configured"
    assert extract_bytes(b"MZ", ".exe").status == "unsupported"
    assert extract_bytes(b"a\x00b", ".txt").status == "unsupported"


def test_csv_records_keep_clinical_association_within_row():
    result = extract_bytes(b"mrn,diagnosis\nR12345,diabetes\n,hypertension\n", ".csv")
    findings = Detector("rules").analyze(result.text)
    health = [item for item in findings if item["entity_type"] == "HEALTH_INFORMATION"]
    assert [item["classification"] for item in health] == ["clinical_content", "patient_linked_health", "clinical_content"]
    assert len({item["segment"] for item in health}) == 3


def test_headerless_csv_retains_first_patient_and_bounds_expansion():
    result = extract_bytes(b"person.synthetic@abdm,diabetes\nother.synthetic@abdm,hypertension\n", ".csv")
    findings = Detector("rules").analyze(result.text)
    assert sum(item["match_count"] for item in findings if item["entity_type"] == "ABHA_ADDRESS") == 2
    assert result.metadata["first_record_retained"] is True
    bounded = extract_bytes(b"mrn,diagnosis\n" + b"R12345,diabetes\n" * 1000, ".csv", {"max_text_chars": 50})
    assert len(bounded.text) == 50
    assert bounded.status == "partial"
    assert bounded.reason == "text_limit_reached"


def test_tika_mixed_pdf_cannot_claim_page_completeness(monkeypatch):
    monkeypatch.setenv("TIKA_URL", "http://127.0.0.1:9998")
    requests_seen = []

    class Response:
        status_code = 200

        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def iter_content(self, _):
            yield json.dumps([{"X-TIKA:content": '<html><body><div class="page"><p>MRN: R12345</p></div><div class="page"><p>Research article about diabetes</p><div class="ocr">English printed scan</div></div></body></html>', "xmpTPg:NPages": "3"}]).encode()

    class Session:
        trust_env = True

        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def put(self, url, **kwargs):
            requests_seen.append((url, kwargs, self.trust_env))
            return Response()

    monkeypatch.setattr("requests.Session", Session)
    result = extract_bytes(b"%PDF synthetic", ".pdf")
    assert result.status == "partial"
    assert result.examined == 0
    assert result.metadata["reported_page_count"] == 3
    assert result.metadata["completeness_verified"] is False
    url, kwargs, trust_env = requests_seen[0]
    assert url.endswith("/rmeta")
    assert kwargs["headers"]["X-Tika-PDFOcrStrategy"] == "ocr_and_text"
    assert kwargs["headers"]["writeLimit"] == "1000000"
    assert kwargs["headers"]["maxEmbeddedResources"] == "100"
    assert kwargs["allow_redirects"] is False
    assert trust_env is False
    assert "R12345" not in json.dumps(result.metadata)
    assert result.metadata["observed_page_boundaries"] == 2
    health = [item for item in Detector("rules").analyze(result.text) if item["entity_type"] == "HEALTH_INFORMATION"]
    assert health and all(item["classification"] == "clinical_content" for item in health)
    findings = Detector("rules").analyze(result.text, capture_evidence=True)
    evidence = [example for finding in findings for example in finding["evidence"]]
    assert evidence
    assert all(not ("R12345" in item["excerpt"] and "diabetes" in item["excerpt"]) for item in evidence)


def test_tika_xhtml_table_rows_are_independent_and_links_are_not_fetched():
    from app.extraction import _xhtml_text
    text, pages = _xhtml_text('<html><head><title>metadata_not_body</title></head><body><div class="page"><table><tr><td>MRN: R12345</td></tr><tr><td>Research: diabetes</td></tr></table><img src="https://outside.example/secret"/><script>do_not_extract</script></div></body></html>')
    assert pages == 1
    assert "outside.example" not in text
    assert "do_not_extract" not in text
    assert "metadata_not_body" not in text
    health = [item for item in Detector("rules").analyze(text) if item["entity_type"] == "HEALTH_INFORMATION"]
    assert health and all(item["classification"] == "clinical_content" for item in health)


def test_public_tika_endpoint_rejected_before_content_request(monkeypatch):
    monkeypatch.setenv("TIKA_URL", "https://outside.example")
    monkeypatch.setattr("app.extraction.private_host", lambda _: False)
    assert extract_bytes(b"sensitive", ".pdf").reason == "tika_endpoint_not_private"


def test_csv_and_jsonl_evidence_stays_inside_extracted_record():
    for suffix, data in [
        (".csv", b"mrn,diagnosis,notes\nA12345,diabetes,FIRST_RECORD_ONLY\nB67890,hypertension,SECOND_RECORD_ONLY\n"),
        (".jsonl", b'{"mrn":"A12345","notes":"FIRST_RECORD_ONLY diabetes"}\n{"mrn":"B67890","notes":"SECOND_RECORD_ONLY hypertension"}\n'),
    ]:
        extracted = extract_bytes(data, suffix)
        findings = Detector("rules").analyze(extracted.text, capture_evidence=True)
        evidence = [example for finding in findings for example in finding["evidence"]]
        assert any(item["value"] == "A12345" for item in evidence)
        assert any(item["value"] == "B67890" for item in evidence)
        assert all(not ("FIRST_RECORD_ONLY" in item["excerpt"] and "SECOND_RECORD_ONLY" in item["excerpt"]) for item in evidence)
        assert all(not ("A12345" in item["excerpt"] and "B67890" in item["excerpt"]) for item in evidence)


@pytest.mark.parametrize("suffix,data", [
    (".json", b'[{"mrn":"A12345","notes":"FIRST_RECORD_ONLY"},{"notes":"SECOND_RECORD_ONLY diabetes"}]'),
    (".json", b'{"mrn":"A12345","notes":"FIRST_RECORD_ONLY","records":[{"notes":"SECOND_RECORD_ONLY diabetes"}]}'),
    (".jsonl", b'[{"mrn":"A12345","notes":"FIRST_RECORD_ONLY"},{"notes":"SECOND_RECORD_ONLY diabetes"}]\n'),
    (".xml", b'<records><record><mrn>A12345</mrn><notes>FIRST_RECORD_ONLY</notes></record><record><notes>SECOND_RECORD_ONLY diabetes</notes></record></records>'),
])
def test_structured_sibling_and_nested_records_do_not_inherit_patient_identity(suffix, data):
    extracted = extract_bytes(data, suffix)
    assert extracted.status == "full"
    assert extracted.metadata["structured_boundaries_verified"] is True
    assert extracted.metadata["parent_child_patient_linkage_inferred"] is False
    findings = Detector("rules").analyze(extracted.text, capture_evidence=True)
    health = [item for item in findings if item["entity_type"] == "HEALTH_INFORMATION"]
    assert health and all(item["classification"] == "clinical_content" for item in health)
    assert any(item["entity_type"] == "MRN" for item in findings)
    for finding in findings:
        for example in finding["evidence"]:
            assert not ("FIRST_RECORD_ONLY" in example["excerpt"] and "SECOND_RECORD_ONLY" in example["excerpt"])


@pytest.mark.parametrize("suffix,data", [
    (".json", b'[{"mrn":"A12345","notes":"diabetes"},{"mrn":"B67890","notes":"hypertension"}]'),
    (".xml", b'<records><record mrn="A12345"><notes>diabetes</notes></record><record mrn="B67890"><notes>hypertension</notes></record></records>'),
])
def test_structured_records_still_link_their_own_scalar_fields(suffix, data):
    extracted = extract_bytes(data, suffix)
    findings = Detector("rules").analyze(extracted.text, capture_evidence=True)
    health = [item for item in findings if item["entity_type"] == "HEALTH_INFORMATION"]
    assert len(health) == 2
    assert all(item["classification"] == "patient_linked_health" for item in health)
    assert len({item["segment"] for item in health}) == 2
    assert all(not ("A12345" in example["excerpt"] and "B67890" in example["excerpt"])
               for finding in findings for example in finding["evidence"])


@pytest.mark.parametrize("suffix,data", [
    (".json", b'[{"mrn":"A12345","notes":"FIRST_RECORD_ONLY"},{"notes":"SECOND_RECORD_ONLY diabetes"}'),
    (".json", b'{"mrn":"A12345","mrn":"B67890","notes":"diabetes"}'),
    (".xml", b'<records><record><mrn>A12345</mrn></record><record><notes>diabetes</notes></records>'),
    (".xml", b'<!DOCTYPE records [<!ENTITY leak SYSTEM "http://example.invalid/secret">]><records>&leak;</records>'),
])
def test_invalid_or_unsafe_structure_is_partial_and_does_not_cross_link(suffix, data):
    extracted = extract_bytes(data, suffix)
    assert extracted.status == "partial"
    assert extracted.reason == "structured_record_boundaries_unverified"
    assert extracted.metadata["structured_boundaries_verified"] is False
    assert not any(item["classification"] == "patient_linked_health"
                   for item in Detector("rules").analyze(extracted.text))


def test_structured_limits_remain_visible_and_bound_returned_text():
    data = json.dumps([{"mrn": "A12345", "notes": "diabetes"}] * 100).encode()
    extracted = extract_bytes(data, ".json", {"max_text_chars": 100})
    assert extracted.status == "partial"
    assert extracted.reason == "structured_text_limit_reached"
    assert len(extracted.text) <= 100
    deep = b"[" * 70 + b'{"mrn":"A12345","notes":"diabetes"}' + b"]" * 70
    assert extract_bytes(deep, ".json").status == "partial"


def test_original_structured_sources_flow_through_file_connector(tmp_path):
    from app.scanning import scan_source
    records = [{"mrn": "A12345", "notes": "FIRST_RECORD_ONLY"}, {"notes": "SECOND_RECORD_ONLY diabetes"}]
    (tmp_path / "records.json").write_text(json.dumps(records))
    (tmp_path / "nested.json").write_text(json.dumps({"mrn": "OUTER123", "embedded": json.dumps(records)}))
    (tmp_path / "xml.json").write_text(json.dumps({"mrn": "OUTER123", "embedded":
        "<records><record><mrn>A12345</mrn></record><record><notes>diabetes</notes></record></records>"}))
    (tmp_path / "malformed.json").write_text(json.dumps(records)[:-1])
    objects = list(scan_source("filesystem", {"root": str(tmp_path)}, {"capture_evidence": True},
                               Detector("rules"), lambda: "running"))
    assert {item["location"] for item in objects} == {"records.json", "nested.json", "xml.json", "malformed.json"}
    for item in objects:
        assert item["status"] == ("partial" if item["location"] == "malformed.json" else "full")
        assert item["findings"]
        assert not any(finding["classification"] == "patient_linked_health" for finding in item["findings"])
        assert all(not ("FIRST_RECORD_ONLY" in example["excerpt"] and "SECOND_RECORD_ONLY" in example["excerpt"])
                   for finding in item["findings"] for example in finding["evidence"])
