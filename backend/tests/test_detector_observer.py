"""The private evaluator sees all real matches, while production retention stays bounded."""
from types import SimpleNamespace

import pytest

from app.detection import Detector


def test_observer_is_opt_in_and_does_not_change_or_retain_normal_findings():
    text = " ".join(f"synthetic{i}@example.test" for i in range(9))
    baseline = Detector("rules").analyze(text)
    events = []
    detector = Detector("rules", _observation_sink=events.append)
    assert detector.analyze(text) == baseline
    assert events == []  # A caller must also supply private source context.
    with detector._observation_context("original.txt"):
        observed = detector.analyze(text)
    assert observed == baseline
    assert len(events) == 9
    assert all("value" not in finding and "evidence" not in finding for finding in observed)
    assert detector._observation_scope is None


def test_observer_is_not_the_three_example_or_256_character_evidence_view():
    events = []
    detector = Detector("rules", _observation_sink=events.append)
    text = " ".join(f"synthetic{i}@example.test" for i in range(9))
    with detector._observation_context("original.txt"):
        findings = detector.analyze(text, capture_evidence=True)
    assert len(events) == 9
    assert len(findings[0]["evidence"]) == 3
    long_name = "A" * 500
    detector._analyzer = SimpleNamespace(analyze=lambda **kw: [SimpleNamespace(
        entity_type="PERSON", start=0, end=len(kw["text"]), score=.9)])
    events.clear()
    with detector._observation_context("name.txt"):
        findings = detector.analyze(long_name, capture_evidence=True)
    assert events[0]["value"] == long_name
    assert len(findings[0]["evidence"][0]["value"]) == 256


def test_chunk_overlap_is_deduplicated_but_repeated_original_occurrences_are_not():
    events = []
    detector = Detector("rules", _observation_sink=events.append)
    email = "repeat@example.test"
    text = "x " * 5900 + email + " " * 100 + email + " " * 500
    with detector._observation_context("original.txt"):
        findings = detector.analyze(text)
    assert [item["value"] for item in events] == [email, email]
    assert sum(item["match_count"] for item in findings) == 2


def test_duplicate_ner_predictions_do_not_create_multiple_occurrences():
    events = []
    detector = Detector("rules", _observation_sink=events.append)
    entity = SimpleNamespace(entity_type="PERSON", start=0, end=9, score=.9)
    detector._analyzer = SimpleNamespace(analyze=lambda **_: [entity, entity])
    with detector._observation_context("original.txt"):
        findings = detector.analyze("Demo Name")
    assert len(events) == 1
    assert findings[0]["match_count"] == 1


def test_synthetic_column_label_is_not_an_original_value_and_context_is_restored():
    events = []
    detector = Detector("rules", _observation_sink=events.append)
    with detector._observation_context("main/table/value", finding_segment="column", prefix_length=22):
        detector.analyze("metadata@example.test: plain text")
    assert len(events) == 1
    assert events[0]["value"] is None
    assert not events[0]["source_span_valid"]
    assert events[0]["segment"] == "column"
    with pytest.raises(RuntimeError):
        with detector._observation_context("temporary"):
            raise RuntimeError("synthetic failure")
    assert detector._observation_scope is None


def test_observer_argument_must_be_callable():
    with pytest.raises(ValueError, match="^invalid_observation_sink$"):
        Detector("rules", _observation_sink=True)
