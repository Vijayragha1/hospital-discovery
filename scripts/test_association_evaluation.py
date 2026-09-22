"""Synthetic original records exercise clinical classification and exact patient-reference association."""
import json
import sqlite3

import pytest

from app.detection import Detector
from association_evaluation import CLINICAL, LINKED, UNIT
from evaluate import evaluate, validate_manifest
from test_instance_evaluation import annotation, manifest_data, sample


def record(locator, clinical=False, value=None, entity="MRN"):
    return {"locator": locator, "clinical": clinical,
            "patient_reference": {"entity_type": entity, "value": value} if value is not None else None}


def add_records(item, mapping, records):
    return {**item, "records": {"mapping": mapping, "items": records}}


def v3(samples, *, kind="filesystem", config=None):
    data = manifest_data(samples, kind=kind, category="database" if kind == "sqlite" else "digital", config=config)
    data["schema_version"] = 3
    data["association_scoring"] = {"unit": UNIT, "normalization": "exact_nfc_v1", "annotations_complete": True}
    data["priority_classes"] = {"database" if kind == "sqlite" else "digital": [LINKED]}
    return data


def run_manifest(tmp_path, data):
    path = tmp_path.resolve() / "private-gold.json"
    path.write_text(json.dumps(data))
    return evaluate(path, "rules", minimum=1)


def run_json(tmp_path, original, gold, *, pii=None, detector_patch=None):
    root = tmp_path.resolve() / "originals"
    root.mkdir()
    (root / "patients.json").write_text(json.dumps(original))
    item = add_records(sample("patients.json", pii or []), "json_pointer_v1", gold)
    return run_manifest(tmp_path, v3([item]))


def metrics(report, label=LINKED):
    return next(row for row in report["association_scoring"]["results"] if row["label"] == label)


def test_multi_patient_document_has_record_denominator_not_keyword_counts(tmp_path):
    original = [{"MRN": "SYN100", "diagnosis": "diabetes hypertension carcinoma"},
                {"MRN": "SYN200"}, {"diagnosis": "hypertension"}, {"notice": "Lift maintenance"}]
    gold = [record({"json_pointer": "/0"}, True, "SYN100"), record({"json_pointer": "/1"}),
            record({"json_pointer": "/2"}, True), record({"json_pointer": "/3"})]
    report = run_json(tmp_path, original, gold, pii=[annotation("SYN100", "MRN"), annotation("SYN200", "MRN")])
    assert report["association_scoring"]["mapping_complete"]
    assert (metrics(report, CLINICAL)["tp"], metrics(report, CLINICAL)["positive_records"]) == (2, 2)
    assert (metrics(report)["tp"], metrics(report)["fp"], metrics(report)["fn"]) == (1, 0, 0)
    assert metrics(report)["negative_records"] == 3
    assert not report["acceptance_candidate"]


def test_equal_patient_values_in_separate_original_records_are_distinct_associations(tmp_path):
    report = run_json(tmp_path, [{"MRN": "SYN100", "diagnosis": "diabetes"}, {"MRN": "SYN100", "diagnosis": "hypertension"}],
        [record({"json_pointer": "/0"}, True, "SYN100"), record({"json_pointer": "/1"}, True, "SYN100")],
        pii=[annotation("SYN100", "MRN")] * 2)
    assert metrics(report)["tp"] == 2
    assert metrics(report, CLINICAL)["tp"] == 2


def test_clinical_false_positive_and_wrong_unlinked_record_are_visible(tmp_path):
    # A software glossary mentioning a clinical keyword is a reviewed negative;
    # aggregate keyword detection must not be mistaken for a correct gold record.
    report = run_json(tmp_path, {"MRN": "SYN100", "notice": "Software glossary example: diabetes"},
        [record({"json_pointer": ""})], pii=[annotation("SYN100", "MRN")])
    assert (metrics(report, CLINICAL)["tp"], metrics(report, CLINICAL)["fp"]) == (0, 1)
    assert (metrics(report)["tp"], metrics(report)["fp"]) == (0, 1)


def test_no_patient_association_is_invented_for_other_persons_clinical_record(tmp_path):
    # Gold declares clinical material but no demonstrated link to this ID.
    report = run_json(tmp_path, {"MRN": "SYN100", "notes": "Teaching case: diabetes"},
        [record({"json_pointer": ""}, True)], pii=[annotation("SYN100", "MRN")])
    assert metrics(report, CLINICAL)["tp"] == 1
    assert metrics(report)["fp"] == 1


def test_swapped_actual_patient_associations_fail_despite_perfect_object_values(tmp_path, monkeypatch):
    class SwappedDetector(Detector):
        def __init__(self, *args, _association_sink=None, **kwargs):
            def swap(event):
                if event.get("event") == "clinical" and event.get("anchors"):
                    kind, value = event["anchors"][0]
                    event = {**event, "anchors": [(kind, "SYN200" if value == "SYN100" else "SYN100")]}
                _association_sink(event)
            super().__init__(*args, _association_sink=swap, **kwargs)
    monkeypatch.setattr("app.detection.Detector", SwappedDetector)
    report = run_json(tmp_path, [{"MRN": "SYN100", "diagnosis": "diabetes"}, {"MRN": "SYN200", "diagnosis": "hypertension"}],
        [record({"json_pointer": "/0"}, True, "SYN100"), record({"json_pointer": "/1"}, True, "SYN200")],
        pii=[annotation("SYN100", "MRN"), annotation("SYN200", "MRN")])
    assert report["instance_scoring"]["results"][0]["recall"] == 1
    assert metrics(report, CLINICAL)["tp"] == 2
    assert (metrics(report)["tp"], metrics(report)["fp"], metrics(report)["fn"]) == (0, 2, 2)
    assert metrics(report)["precision"] == metrics(report)["recall"] == 0


def test_same_patient_value_moved_to_another_record_cannot_match(tmp_path):
    original = [{"MRN": "SYN100", "diagnosis": "diabetes"}, {"MRN": "SYN100"}]
    # A deliberately wrong record annotation must not pass just because the ID is present in both.
    report = run_json(tmp_path, original, [record({"json_pointer": "/0"}), record({"json_pointer": "/1"}, True, "SYN100")],
        pii=[annotation("SYN100", "MRN")] * 2)
    assert (metrics(report)["tp"], metrics(report)["fp"], metrics(report)["fn"]) == (0, 1, 1)


def test_nested_json_does_not_inherit_parent_or_sibling_patient(tmp_path):
    original = {"MRN": "OUTER100", "patients": [{"MRN": "INNER200"}, {"diagnosis": "diabetes"},
                {"MRN": "INNER300", "diagnosis": "hypertension"}]}
    report = run_json(tmp_path, original, [record({"json_pointer": ""}), record({"json_pointer": "/patients/0"}),
        record({"json_pointer": "/patients/1"}, True), record({"json_pointer": "/patients/2"}, True, "INNER300")],
        pii=[annotation(value, "MRN") for value in ("OUTER100", "INNER200", "INNER300")])
    assert report["association_scoring"]["mapping_complete"]
    assert (metrics(report)["tp"], metrics(report)["fp"], metrics(report)["fn"]) == (1, 0, 0)
    assert metrics(report, CLINICAL)["tp"] == 2


@pytest.mark.parametrize("newline", ["\n", "\r\n", "\r"])
def test_original_text_spans_map_multi_patient_paragraphs_independently(tmp_path, newline):
    first = "MRN: SYN100" + newline + "diagnosis: diabetes"
    second = "MRN: SYN200" + newline + "diagnosis: hypertension"
    separator = newline * 2
    text = first + separator + second + separator + "Lift maintenance"
    root = tmp_path.resolve() / "originals"
    root.mkdir()
    (root / "records.txt").write_bytes(text.encode())
    records = [record({"start": 0, "end": len(first)}, True, "SYN100"),
        record({"start": len(first) + len(separator), "end": len(first) + len(separator) + len(second)}, True, "SYN200"),
        record({"start": len(first) + len(second) + 2 * len(separator), "end": len(text)})]
    item = add_records(sample("records.txt", [annotation("SYN100", "MRN"), annotation("SYN200", "MRN")]), "text_spans_v1", records)
    report = run_manifest(tmp_path, v3([item]))
    assert report["association_scoring"]["mapping_complete"]
    assert metrics(report)["tp"] == 2 and metrics(report)["negative_records"] == 1


@pytest.mark.parametrize("case", ["gap", "crossing"])
def test_original_text_layout_gaps_or_segments_crossing_gold_records_block_acceptance(tmp_path, case):
    text = "MRN: SYN100; diagnosis: diabetes and hypertension"
    root = tmp_path.resolve() / "originals"
    root.mkdir()
    (root / "records.txt").write_text(text)
    records = [record({"start": 0, "end": 10}, True, "SYN100")]
    if case == "crossing":
        records.append(record({"start": 10, "end": len(text)}))
    item = add_records(sample("records.txt", [annotation("SYN100", "MRN")]), "text_spans_v1", records)
    report = run_manifest(tmp_path, v3([item]))
    assert not report["association_scoring"]["mapping_complete"]
    assert "original_record_association_mapping_incomplete" in report["acceptance_blockers"]


def test_unannotated_original_negative_record_is_a_visible_inventory_gap(tmp_path):
    report = run_json(tmp_path, [{"MRN": "SYN100", "diagnosis": "diabetes"}, {"notice": "No clinical content"}],
        [record({"json_pointer": "/0"}, True, "SYN100")], pii=[annotation("SYN100", "MRN")])
    assert "original_record_inventory_not_fully_mapped" in report["association_scoring"]["incomplete_reasons"]


def db_report(tmp_path, rows, gold_by_column, *, primary=True, options=None, journal=False):
    base = tmp_path.resolve()
    with sqlite3.connect(base / "original.sqlite") as connection:
        connection.execute("create table records(id" + (" primary key" if primary else "") + ", MRN text, diagnosis text, payload text)")
        connection.executemany("insert into records values (?, ?, ?, ?)", rows)
    if journal:
        (base / "original.sqlite-wal").write_bytes(b"")
    samples = []
    for column in ("id", "MRN", "diagnosis", "payload"):
        pii, records = gold_by_column[column]
        samples.append(add_records(sample("main/records/" + column, pii), "database_primary_key_v1", records))
    data = v3(samples, kind="sqlite", config={"path": "original.sqlite"})
    data["sources"][0]["options"] = options or {}
    return run_manifest(tmp_path, data)


def test_database_pk_rows_nulls_and_nested_json_use_distinct_original_records(tmp_path):
    rows = [(1, "SYN100", "diabetes", json.dumps([{"MRN": "INNER200"}, {"diagnosis": "hypertension"}])),
            (2, "SYN200", None, None), (3, "SYN300", "", "")]
    negative = [record({"primary_key": {"id": i}}) for i in (1, 2, 3)]
    gold = {"id": ([], negative), "MRN": ([annotation(row[1], "MRN") for row in rows], negative),
        "diagnosis": ([], [record({"primary_key": {"id": 1}}, True, "SYN100"), *negative[1:]]),
        "payload": ([annotation("INNER200", "MRN")], [record({"primary_key": {"id": 1}, "json_pointer": "/0"}),
            record({"primary_key": {"id": 1}, "json_pointer": "/1"}, True), *negative[1:]])}
    report = db_report(tmp_path, rows, gold)
    assert report["association_scoring"]["mapping_complete"], report["association_scoring"]["incomplete_reasons"]
    assert (metrics(report)["tp"], metrics(report)["fp"], metrics(report)["fn"]) == (1, 0, 0)
    assert metrics(report, CLINICAL)["tp"] == 2


def test_database_numeric_and_string_primary_keys_do_not_collide(tmp_path):
    rows = [(1, "SYN100", "diabetes", None), ("1", "SYN100", "hypertension", None)]
    negative = [record({"primary_key": {"id": key}}) for key in (1, "1")]
    gold = {"id": ([], negative), "MRN": ([annotation("SYN100", "MRN")] * 2, negative),
        "diagnosis": ([], [record({"primary_key": {"id": key}}, True, "SYN100") for key in (1, "1")]), "payload": ([], negative)}
    report = db_report(tmp_path, rows, gold)
    assert report["association_scoring"]["mapping_complete"]
    assert metrics(report)["tp"] == 2


def test_database_without_verified_original_primary_key_mapping_is_blocked(tmp_path):
    negative = [record({"primary_key": {"id": 1}})]
    gold = {"id": ([], negative), "MRN": ([annotation("SYN100", "MRN")], negative),
            "diagnosis": ([], [record({"primary_key": {"id": 1}}, True, "SYN100")]), "payload": ([], negative)}
    report = db_report(tmp_path, [(1, "SYN100", "diabetes", None)], gold, primary=False)
    assert not report["association_scoring"]["mapping_complete"]
    assert metrics(report)["fn"] == 1


def test_sampled_database_keeps_unseen_record_associations_in_denominator(tmp_path):
    rows = [(1, "SYN100", "diabetes", None), (2, "SYN200", "hypertension", None)]
    negative = [record({"primary_key": {"id": key}}) for key in (1, 2)]
    gold = {"id": ([], negative), "MRN": ([annotation(row[1], "MRN") for row in rows], negative),
        "diagnosis": ([], [record({"primary_key": {"id": row[0]}}, True, row[1]) for row in rows]), "payload": ([], negative)}
    report = db_report(tmp_path, rows, gold, options={"table_sample_rows": 1})
    assert (metrics(report)["tp"], metrics(report)["fn"], metrics(report)["recall"]) == (1, 1, .5)
    assert metrics(report)["coverage_incomplete"]
    assert not report["association_scoring"]["mapping_complete"]


def test_database_journal_export_cannot_claim_snapshot_verified(tmp_path):
    negative = [record({"primary_key": {"id": 1}})]
    gold = {"id": ([], negative), "MRN": ([annotation("SYN100", "MRN")], negative),
        "diagnosis": ([], [record({"primary_key": {"id": 1}}, True, "SYN100")]), "payload": ([], negative)}
    report = db_report(tmp_path, [(1, "SYN100", "diabetes", None)], gold, journal=True)
    assert "database_reference_snapshot_unverified" in report["association_scoring"]["incomplete_reasons"]


def test_pdf_text_does_not_imply_original_patient_record_mapping(tmp_path, monkeypatch):
    from app.extraction import ExtractionResult
    text = "MRN: SYN100; diagnosis: diabetes"
    root = tmp_path.resolve() / "originals"
    root.mkdir()
    (root / "records.pdf").write_text(text)
    monkeypatch.setattr("app.scanning.extract_bytes", lambda *args: ExtractionResult(
        text=text, status="full", metadata={"patient_linkage_context_verified": False}))
    item = add_records(sample("records.pdf", [annotation("SYN100", "MRN")]), "text_spans_v1",
        [record({"start": 0, "end": len(text)}, True, "SYN100")])
    report = run_manifest(tmp_path, v3([item]))
    assert not report["association_scoring"]["mapping_complete"]
    assert LINKED not in report["samples"][0]["actual"]
    assert metrics(report)["tp"] == 0 and metrics(report)["fn"] == 1


def test_association_observation_limit_blocks_acceptance(tmp_path, monkeypatch):
    from association_evaluation import AssociationObserver
    monkeypatch.setattr("evaluate.AssociationObserver", lambda token: AssociationObserver(token, maximum=1))
    report = run_json(tmp_path, {"MRN": "SYN100", "diagnosis": "diabetes"},
        [record({"json_pointer": ""}, True, "SYN100")], pii=[annotation("SYN100", "MRN")])
    assert "association_observation_limit_reached" in report["association_scoring"]["incomplete_reasons"]
    assert not report["association_scoring"]["mapping_complete"]


def test_failed_final_object_discards_provisional_clinical_associations(tmp_path, monkeypatch):
    class FailsAfterObserving(Detector):
        def analyze(self, text, **kwargs):
            super().analyze(text, **kwargs)
            raise RuntimeError("private-patient-content")
    monkeypatch.setattr("app.detection.Detector", FailsAfterObserving)
    report = run_json(tmp_path, {"MRN": "SYN100", "diagnosis": "diabetes"},
        [record({"json_pointer": ""}, True, "SYN100")], pii=[annotation("SYN100", "MRN")])
    assert (metrics(report)["tp"], metrics(report)["fp"], metrics(report)["fn"]) == (0, 0, 1)
    assert metrics(report)["coverage_incomplete"]
    assert "private-patient-content" not in json.dumps(report)


def test_final_health_count_must_reconcile_with_private_observations(tmp_path, monkeypatch):
    class WrongCount(Detector):
        def analyze(self, text, **kwargs):
            findings = super().analyze(text, **kwargs)
            for finding in findings:
                if finding["entity_type"] == "HEALTH_INFORMATION":
                    finding["match_count"] += 1
            return findings
    monkeypatch.setattr("app.detection.Detector", WrongCount)
    report = run_json(tmp_path, {"MRN": "SYN100", "diagnosis": "diabetes"},
        [record({"json_pointer": ""}, True, "SYN100")], pii=[annotation("SYN100", "MRN")])
    assert "final_clinical_findings_observations_mismatch" in report["association_scoring"]["incomplete_reasons"]
    assert metrics(report)["tp"] == 0 and metrics(report)["fn"] == 1


def test_public_report_contains_no_original_keys_locators_or_patient_values(tmp_path):
    report = run_json(tmp_path, {"private/path": [{"MRN": "SECRET-SYN100", "diagnosis": "diabetes"}]},
        [record({"json_pointer": "/private~1path/0"}, True, "SECRET-SYN100")], pii=[annotation("SECRET-SYN100", "MRN")])
    serialized = json.dumps(report)
    for value in ("private/path", "private~1path", "SECRET-SYN100", "patients.json", str(tmp_path)):
        assert value not in serialized


@pytest.mark.parametrize("mutate", [
    lambda item: item["records"].update(mapping="pdf_page_guess"),
    lambda item: item["records"]["items"][0]["locator"].update(segment="segment:1"),
    lambda item: item["records"]["items"][0].update(clinical=1),
    lambda item: item["records"]["items"][0].update(clinical=False),
    lambda item: item["records"]["items"].append(item["records"]["items"][0]),
])
def test_manifest_rejects_unsupported_ambiguous_or_incomplete_record_contract(mutate):
    item = add_records(sample("patients.json", [annotation("SYN100", "MRN")]), "json_pointer_v1",
                       [record({"json_pointer": ""}, True, "SYN100")])
    mutate(item)
    with pytest.raises(ValueError):
        validate_manifest(v3([item]))


def test_acceptance_requires_passing_both_record_measures_and_full_mapping():
    from association_evaluation import association_metrics
    from evaluate import acceptance_blockers
    priorities = {category: [LINKED] for category in ("database", "digital", "ocr")}
    samples = []
    for category in priorities:
        for index in range(60):
            key = str(index).encode()
            values = {"records": {key}, "clinical": {key} if index < 30 else set(),
                      "links": {(key, "MRN", b"correct")} if index < 30 else set()}
            samples.append({"category": category, "gold": values, "observed": {k: set(v) for k, v in values.items()}, "status": "full"})
    data = {"schema_version": 3, "synthetic": False, "split": "evaluation", "priority_classes": priorities}
    def blockers(complete=True):
        rows = association_metrics(samples, priorities, .95, 30, complete)
        return acceptance_blockers(data, "presidio", [], True, .95, 30,
            instance_enabled=True, instance_complete=True, association_enabled=True,
            association_complete=complete, association_results=rows)
    assert blockers() == []
    for item in samples[:2]:
        key = next(iter(item["observed"]["records"]))
        item["observed"]["links"] = {(key, "MRN", b"wrong")}
    assert "priority_record_association_metrics_unvalidated_or_below_target" in blockers()
    assert "original_record_association_mapping_incomplete" in blockers(False)
