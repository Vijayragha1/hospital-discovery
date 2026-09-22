"""Original synthetic files/SQLite exports exercise extraction -> detection -> final findings -> scoring."""
from collections import Counter
import json
import sqlite3
from types import SimpleNamespace

import pytest

from evaluate import acceptance_blockers, evaluate, validate_manifest
from instance_evaluation import (InstanceObserver, NORMALIZATION, UNIT, normalize_value,
    occurrence_metrics, validate_instance_manifest)
from app.detection import Detector


LABEL = "personal_data:EMAIL_ADDRESS"


def annotation(value, entity="EMAIL_ADDRESS", **fields):
    return {"classification": "personal_data", "entity_type": entity, "value": value, **fields}


def manifest_data(samples, *, kind="filesystem", category="digital", config=None, options=None):
    return {"schema_version": 2, "split": "calibration", "synthetic": True,
        "instance_scoring": {"unit": UNIT, "normalization": NORMALIZATION, "annotations_complete": True},
        "priority_classes": {category: [LABEL]}, "sources": [{"kind": kind, "category": category,
            "config": config or {"root": "originals"}, "options": options or {}, "samples": samples}]}


def sample(location, values, *, expected=None, **fields):
    return {"id": "private-reference-" + location, "location": location,
        "expected": expected if expected is not None else sorted({"personal_data:" + value["entity_type"] for value in values}),
        "instances": values, **fields}


def run_files(tmp_path, files, values, *, options=None, statuses=None, category="digital", patch=None):
    base = tmp_path.resolve()
    originals = base / "originals"
    originals.mkdir()
    for name, content in files.items():
        (originals / name).write_bytes(content.encode() if isinstance(content, str) else content)
    samples = [sample(name, values[name], **({"expected_status": statuses[name]} if statuses and name in statuses else {}))
               for name in files]
    data = manifest_data(samples, options=options, category=category)
    if patch:
        patch(data)
    path = base / "private-gold.json"
    path.write_text(json.dumps(data))
    return evaluate(path, "rules", minimum=1)


def email_row(report):
    return next(item for item in report["instance_scoring"]["results"] if item["label"] == LABEL)


def test_one_of_100_real_original_values_has_one_percent_recall(tmp_path, monkeypatch):
    class FirstOnly(Detector):
        def analyze(self, text, **kwargs):
            return super().analyze(text.splitlines()[0], **kwargs)

    monkeypatch.setattr("app.detection.Detector", FirstOnly)
    emails = [f"original{i}@example.test" for i in range(100)]
    report = run_files(tmp_path, {"one.txt": "\n".join(emails)}, {"one.txt": list(map(annotation, emails))})
    assert report["results"][0]["recall"] == 1  # Old diagnostic cannot establish instance recall.
    assert report["object_presence_diagnostic_only"]
    row = email_row(report)
    assert (row["tp"], row["fn"], row["fp"], row["recall"]) == (1, 99, 0, .01)
    assert row["positive_samples"] == 1  # A hundred mentions do not supply 100 independent objects.
    assert not report["acceptance_candidate"]


def test_wrong_value_of_right_class_is_fp_and_fn(tmp_path):
    report = run_files(tmp_path, {"one.txt": "wrong@example.test"},
        {"one.txt": [annotation("expected@example.test")]})
    row = email_row(report)
    assert report["results"][0]["recall"] == 1
    assert (row["tp"], row["fp"], row["fn"], row["recall"]) == (0, 1, 1, 0)


def test_repeated_values_match_one_to_one_and_uncapped(tmp_path):
    value = "repeat@example.test"
    report = run_files(tmp_path, {"one.txt": " ".join([value] * 9)},
        {"one.txt": [annotation(value, occurrence_id=str(i)) for i in range(7)]},
        options={"capture_evidence": True})
    row = email_row(report)
    assert (row["tp"], row["fp"], row["fn"], row["observed_occurrences"]) == (7, 2, 0, 9)
    assert "evidence" not in report


def test_equal_values_in_different_original_objects_cannot_cross_match(tmp_path):
    report = run_files(tmp_path, {"one.txt": "expected@example.test", "two.txt": "No entity here"},
        {"one.txt": [], "two.txt": [annotation("expected@example.test")]})
    row = email_row(report)
    assert (row["tp"], row["fp"], row["fn"], row["negative_samples_with_false_positives"]) == (0, 1, 1, 1)


def test_unexpected_detection_on_reviewed_negative_is_not_hidden(tmp_path):
    report = run_files(tmp_path, {"one.txt": "false.positive@example.test", "two.txt": "expected@example.test"},
        {"one.txt": [], "two.txt": [annotation("expected@example.test")]})
    row = email_row(report)
    assert (row["tp"], row["fp"], row["fn"], row["precision"]) == (1, 1, 0, .5)


@pytest.mark.parametrize(("name", "status"), [("one.unknown", "unsupported"), ("one.zip", "excluded")])
def test_unsupported_original_objects_keep_missing_gold_and_coverage_visible(tmp_path, name, status):
    report = run_files(tmp_path, {name: "missing@example.test"}, {name: [annotation("missing@example.test")]},
                       statuses={name: status})
    row = email_row(report)
    assert report["coverage_expectations_met"]  # Expected failure is accounted for, not accuracy success.
    assert (row["tp"], row["fn"], row["observed_occurrences"]) == (0, 1, 0)
    assert row["coverage_incomplete"] and row["result"] == "unvalidated"


def test_observations_from_detector_that_then_fails_are_not_predictions(tmp_path, monkeypatch):
    class FailsAfterObserving(Detector):
        def analyze(self, text, **kwargs):
            super().analyze(text, **kwargs)
            raise RuntimeError("synthetic@example.test must not escape")

    monkeypatch.setattr("app.detection.Detector", FailsAfterObserving)
    report = run_files(tmp_path, {"one.txt": "synthetic@example.test"},
        {"one.txt": [annotation("synthetic@example.test")]})
    assert report["samples"][0]["status"] == "failed"
    row = email_row(report)
    assert (row["tp"], row["fn"], row["observed_occurrences"]) == (0, 1, 0)
    assert "synthetic@example.test" not in json.dumps(report)


def test_partial_extraction_scores_all_original_gold_but_cannot_pass(tmp_path):
    first, second = "first@example.test", "second@example.test"
    report = run_files(tmp_path, {"one.txt": first + " " * 30 + second},
        {"one.txt": [annotation(first), annotation(second)]}, options={"max_text_chars": len(first) + 1})
    row = email_row(report)
    assert (row["tp"], row["fn"], row["recall"]) == (1, 1, .5)
    assert report["samples"][0]["status"] == "partial"
    assert row["coverage_incomplete"] and row["result"] == "unvalidated"


def test_sqlite_original_rows_count_duplicate_values_without_global_dedup(tmp_path):
    base = tmp_path.resolve()
    database = base / "original.sqlite"
    with sqlite3.connect(database) as connection:
        connection.execute("create table records(contact text)")
        connection.executemany("insert into records values (?)", [("repeat@example.test",)] * 3)
    data = manifest_data([sample("main/records/contact", [annotation("repeat@example.test")] * 3)],
        kind="sqlite", category="database", config={"path": database.name})
    path = base / "private-gold.json"
    path.write_text(json.dumps(data))
    report = evaluate(path, "rules", minimum=1)
    assert email_row(report)["tp"] == 3
    assert report["instance_scoring"]["observations_complete"]


def test_sampled_sqlite_counts_unsampled_original_gold_as_missed(tmp_path):
    base = tmp_path.resolve()
    database = base / "original.sqlite"
    with sqlite3.connect(database) as connection:
        connection.execute("create table records(contact text)")
        connection.executemany("insert into records values (?)", [(f"row{i}@example.test",) for i in range(4)])
    data = manifest_data([sample("main/records/contact", [annotation(f"row{i}@example.test") for i in range(4)])],
        kind="sqlite", category="database", config={"path": database.name}, options={"table_sample_rows": 2})
    path = base / "private-gold.json"
    path.write_text(json.dumps(data))
    report = evaluate(path, "rules", minimum=1)
    row = email_row(report)
    assert (row["tp"], row["fn"], row["recall"]) == (2, 2, .5)
    assert row["coverage_incomplete"] and report["samples"][0]["status"] == "sampled"


def test_nested_sqlite_records_keep_duplicate_occurrences_without_cross_patient_linkage(tmp_path):
    base = tmp_path.resolve()
    database = base / "original.sqlite"
    original = json.dumps([{"MRN": "SYN100", "contact": "repeat@example.test"},
                           {"diagnosis": "diabetes", "contact": "repeat@example.test"}])
    with sqlite3.connect(database) as connection:
        connection.execute("create table records(patient_id text, payload text)")
        connection.execute("insert into records values (?, ?)", ("SYN900", original))
    data = manifest_data([sample("main/records/patient_id", [annotation("SYN900", "MRN")]),
                          sample("main/records/payload", [annotation("SYN100", "MRN"), annotation("repeat@example.test"),
                                                          annotation("repeat@example.test")])],
        kind="sqlite", category="database", config={"path": database.name})
    path = base / "private-gold.json"
    path.write_text(json.dumps(data))
    report = evaluate(path, "rules", minimum=1)
    assert email_row(report)["tp"] == 2
    assert report["instance_scoring"]["observations_complete"]
    assert "clinical_content:HEALTH_INFORMATION" in report["samples"][1]["actual"]
    assert "patient_linked_health:HEALTH_INFORMATION" not in report["samples"][1]["actual"]


def test_failure_after_one_sqlite_cell_discards_unreturned_column_observations(tmp_path, monkeypatch):
    class FailsOnSecondCell(Detector):
        calls = 0
        def analyze(self, text, **kwargs):
            self.calls += 1
            findings = super().analyze(text, **kwargs)
            if self.calls == 2:
                raise RuntimeError("private.synthetic@example.test")
            return findings

    monkeypatch.setattr("app.detection.Detector", FailsOnSecondCell)
    base = tmp_path.resolve()
    database = base / "original.sqlite"
    with sqlite3.connect(database) as connection:
        connection.execute("create table records(contact text)")
        connection.executemany("insert into records values (?)", [("first@example.test",), ("second@example.test",)])
    data = manifest_data([sample("main/records/contact", [annotation("first@example.test"), annotation("second@example.test")])],
        kind="sqlite", category="database", config={"path": database.name})
    path = base / "private-gold.json"
    path.write_text(json.dumps(data))
    report = evaluate(path, "rules", minimum=1)
    assert (email_row(report)["tp"], email_row(report)["fn"], email_row(report)["observed_occurrences"]) == (0, 2, 0)
    assert report["samples"][0]["status"] == "failed" and report["unexpected_objects"] == 1


def test_column_label_only_match_is_a_false_positive_not_a_source_value(tmp_path):
    base = tmp_path.resolve()
    database = base / "original.sqlite"
    with sqlite3.connect(database) as connection:
        connection.execute('create table records("label@example.test" text)')
        connection.execute('insert into records values ("no contact value")')
    data = manifest_data([sample("main/records/label%40example.test", [])],
        kind="sqlite", category="database", config={"path": database.name})
    path = base / "private-gold.json"
    path.write_text(json.dumps(data))
    report = evaluate(path, "rules", minimum=1)
    assert (email_row(report)["tp"], email_row(report)["fp"], email_row(report)["fn"]) == (0, 1, 0)


def test_reference_changes_after_returned_finding_invalidate_metrics(tmp_path, monkeypatch):
    from app.scanning import scan_source as real_scan
    def changed_source(kind, config, options, detector, control):
        yield from real_scan(kind, config, options, detector, control)
        from pathlib import Path
        (Path(config["root"]) / "one.txt").write_text("changed@example.test")
    monkeypatch.setattr("app.scanning.scan_source", changed_source)
    report = run_files(tmp_path, {"one.txt": "original@example.test"}, {"one.txt": [annotation("original@example.test")]})
    assert not report["instance_scoring"]["original_inputs_unchanged"]
    assert "reference_inputs_changed_during_evaluation" in report["instance_scoring"]["incomplete_reasons"]
    assert email_row(report)["result"] == "unvalidated"


def test_nested_multi_patient_original_does_not_claim_record_or_linkage_accuracy(tmp_path):
    original = json.dumps([{"MRN": "SYN100", "contact": "repeat@example.test"},
                           {"diagnosis": "diabetes", "contact": "repeat@example.test"}])
    report = run_files(tmp_path, {"patients.json": original},
        {"patients.json": [annotation("SYN100", "MRN"), annotation("repeat@example.test"), annotation("repeat@example.test")]})
    assert email_row(report)["tp"] == 2
    assert "clinical_content:HEALTH_INFORMATION" in report["samples"][0]["actual"]
    assert "patient_linked_health:HEALTH_INFORMATION" not in report["samples"][0]["actual"]
    assert report["instance_scoring"]["unit"] == "object_value_occurrence"
    assert any("PII occurrences do not measure original span, page or record identity" in item for item in report["limitations"])


def test_report_copies_no_private_values_ids_locations_or_occurrence_ids(tmp_path, capsys):
    value = "private.synthetic@example.test"
    location = "private-record-path.txt"
    report = run_files(tmp_path, {location: value},
        {location: [annotation(value, occurrence_id="private-record-id")]})
    serialized = json.dumps(report)
    for secret in (value, location, "private-record-id", str(tmp_path)):
        assert secret not in serialized
    assert report["samples"][0]["id"] == "sample-000001"
    assert capsys.readouterr() == ("", "")


def test_exact_normalization_does_not_forgive_ocr_errors_or_case(tmp_path):
    assert normalize_value("Cafe\u0301") == normalize_value("Caf\u00e9")
    assert normalize_value("SYN10") != normalize_value("SYN1O")
    assert normalize_value(" Demo ") != normalize_value("Demo")
    report = run_files(tmp_path, {"one.txt": "Upper@example.test"},
        {"one.txt": [annotation("upper@example.test")]})
    row = email_row(report)
    assert (row["tp"], row["fp"], row["fn"]) == (0, 1, 1)


def test_nfc_equivalent_full_original_names_match_without_truncation(tmp_path, monkeypatch):
    class NameDetector(Detector):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._analyzer = SimpleNamespace(analyze=lambda **kw: [SimpleNamespace(
                entity_type="PERSON", start=0, end=len(kw["text"]), score=.9)])

    monkeypatch.setattr("app.detection.Detector", NameDetector)
    value = "Cafe\u0301" + "A" * 300
    report = run_files(tmp_path, {"one.txt": value}, {"one.txt": [annotation("Caf\u00e9" + "A" * 300, "PERSON")]})
    row = next(row for row in report["instance_scoring"]["results"] if row["label"] == "personal_data:PERSON")
    assert (row["tp"], row["fp"], row["fn"]) == (1, 0, 0)


@pytest.mark.parametrize("field", ["record_id", "page", "start", "end", "scope"])
def test_unsupported_record_page_and_span_annotation_scope_is_rejected(field):
    data = manifest_data([sample("one.txt", [annotation("expected@example.test", **{field: "private"})])])
    with pytest.raises(ValueError, match="Unsupported occurrence annotation fields or scope"):
        validate_manifest(data)


@pytest.mark.parametrize("mutation", [
    lambda d: d.update(schema_version=2.0),
    lambda d: d["instance_scoring"].update(annotations_complete=1),
    lambda d: d["instance_scoring"].update(normalization="fuzzy"),
    lambda d: d["sources"][0]["samples"][0].pop("instances"),
    lambda d: d["sources"][0]["samples"][0].update(record_id="unmapped"),
    lambda d: d["sources"][0]["samples"][0]["instances"][0].update(entity_type="HEALTH_INFORMATION"),
    lambda d: d["sources"][0]["samples"][0]["instances"][0].update(entity_type="PATIENT_REFERENCE"),
    lambda d: d["sources"][0].update(category="database"),
])
def test_manifest_rejects_ambiguous_units_and_incomplete_gold(mutation):
    data = manifest_data([sample("one.txt", [annotation("expected@example.test")])])
    mutation(data)
    with pytest.raises(ValueError):
        validate_manifest(data)


def test_optional_private_occurrence_ids_unique_but_duplicate_values_allowed():
    data = manifest_data([sample("one.txt", [annotation("same@example.test", occurrence_id="one"),
                                             annotation("same@example.test", occurrence_id="two")])])
    validate_manifest(data)
    data["sources"][0]["samples"][0]["instances"][1]["occurrence_id"] = "one"
    with pytest.raises(ValueError, match="occurrence IDs"):
        validate_manifest(data)


def test_gold_presence_cannot_disagree_with_diagnostic_presence():
    data = manifest_data([sample("one.txt", [], expected=[LABEL])])
    with pytest.raises(ValueError, match="must agree"):
        validate_manifest(data)


def test_scoring_observation_limit_blocks_even_matching_object_labels(tmp_path, monkeypatch):
    monkeypatch.setattr("evaluate.InstanceObserver", lambda: InstanceObserver(maximum=1))
    report = run_files(tmp_path, {"one.txt": "first@example.test second@example.test"},
        {"one.txt": [annotation("first@example.test"), annotation("second@example.test")]})
    assert not report["instance_scoring"]["observations_complete"]
    assert "instance_observation_limit_reached" in report["instance_scoring"]["incomplete_reasons"]
    assert "instance_observations_incomplete" in report["acceptance_blockers"]


def test_final_finding_count_must_reconcile_with_private_observations(tmp_path, monkeypatch):
    class WrongCount(Detector):
        def analyze(self, text, **kwargs):
            findings = super().analyze(text, **kwargs)
            findings[0]["match_count"] += 1
            return findings

    monkeypatch.setattr("app.detection.Detector", WrongCount)
    report = run_files(tmp_path, {"one.txt": "first@example.test"}, {"one.txt": [annotation("first@example.test")]})
    assert "final_finding_observations_mismatch" in report["instance_scoring"]["incomplete_reasons"]
    assert email_row(report)["observed_occurrences"] == 0


def test_plain_text_cannot_supply_ocr_acceptance_evidence(tmp_path):
    report = run_files(tmp_path, {"one.txt": "first@example.test"},
        {"one.txt": [annotation("first@example.test")]}, category="ocr")
    assert "ocr_source_path_not_verified" in report["instance_scoring"]["incomplete_reasons"]
    assert email_row(report)["result"] == "unvalidated"


def test_actual_values_never_move_between_runs_and_private_state_is_discarded():
    one, two = InstanceObserver(), InstanceObserver()
    assert one.gold([annotation("private@example.test")]) != two.gold([annotation("private@example.test")])
    one.close()
    assert one.pending == {} and one._key == b"" and one.source is None


def test_acceptance_uses_occurrences_and_independent_positive_negative_objects():
    data = {"synthetic": False, "split": "evaluation", "priority_classes": {
        category: [LABEL] for category in ("database", "digital", "ocr")}}
    samples = [{"category": category, "gold": Counter({(LABEL, b"correct"): 1}) if i < 30 else Counter(),
        "observed": Counter({(LABEL, b"correct"): 1}) if i < 30 else Counter(),
        "status": "full", "observation_complete": True}
        for category in data["priority_classes"] for i in range(60)]
    results = occurrence_metrics(samples, data["priority_classes"])
    def blockers(rows=results, complete=True):
        return acceptance_blockers(data, "presidio", [], True, .95, 30,
            instance_results=rows, instance_enabled=True, instance_complete=complete)
    assert blockers() == []
    samples[0]["observed"] = Counter({(LABEL, b"wrong"): 1})
    samples[1]["observed"] = Counter({(LABEL, b"wrong"): 1})
    assert "priority_instance_metrics_unvalidated_or_below_target" in blockers(occurrence_metrics(samples, data["priority_classes"]))
    assert "instance_observations_incomplete" in blockers(complete=False)
    data["priority_classes"]["digital"].append("patient_linked_health:HEALTH_INFORMATION")
    assert "priority_instance_unit_unsupported" in blockers()


def test_single_object_many_mentions_cannot_satisfy_independent_sample_floor():
    rows = occurrence_metrics([{"category": "digital", "gold": Counter({(LABEL, b"x"): 100}),
        "observed": Counter({(LABEL, b"x"): 100}), "status": "full", "observation_complete": True}], {"digital": [LABEL]})
    assert rows[0]["positive_samples"] == 1 and rows[0]["result"] == "unvalidated"


def test_legacy_instance_annotations_cannot_silently_be_ignored():
    data = manifest_data([sample("one.txt", [annotation("first@example.test")])])
    data.pop("schema_version")
    with pytest.raises(ValueError, match="schema version 2"):
        validate_instance_manifest(data)


def test_duplicate_private_manifest_fields_are_rejected_without_echo(tmp_path):
    path = tmp_path / "gold.json"
    path.write_text('{"private@example.test": 1, "private@example.test": 2}')
    with pytest.raises(ValueError, match="^Reference manifest has duplicate object fields$"):
        evaluate(path, "rules")
