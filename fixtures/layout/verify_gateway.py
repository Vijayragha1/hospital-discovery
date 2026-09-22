#!/usr/bin/env python3
"""Original PNG/TIFF/PDF -> private parser -> real detector -> committed gold scoring.

Run inside the API image with /app/backend (built or explicit source overlay),
read-only /app/scripts, --fixtures and --reference mounts, and private
PAGE_OCR_URL plus TIKA_URL. Only --output needs writable transient storage.
This is a bounded synthetic source-object harness, not directory inventory or
hospital accuracy acceptance. Gold is authored from original source canvases.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys


def _code(value):
    return value if isinstance(value, str) and re.fullmatch(r"[a-z][a-z0-9_]{0,159}", value) else None


def _counts(gold, observed):
    if isinstance(gold, Counter):
        tp = sum((gold & observed).values())
        return {"tp": tp, "fp": sum(observed.values()) - tp, "fn": sum(gold.values()) - tp}
    return {"tp": len(gold & observed), "fp": len(observed - gold), "fn": len(gold - observed)}


def evaluate(fixtures, reference, mode):
    from app.detection import Detector
    from app.scanning import DEFAULTS, _file_result
    from association_evaluation import AssociationObserver, association_metrics, validate_association_manifest
    from instance_evaluation import InstanceObserver, occurrence_metrics, validate_instance_manifest
    from evaluate import acceptance_blockers

    data = json.loads(reference.read_text())
    if data.get("synthetic") is not True or data.get("split") != "calibration":
        raise ValueError("synthetic_calibration_reference_required")
    validate_instance_manifest(data)
    validate_association_manifest(data)
    samples = [sample for source in data["sources"] for sample in source["samples"]]
    if len(samples) != 10 or len({sample["location"] for sample in samples}) != len(samples):
        raise ValueError("fixture_inventory_mismatch")

    instances = InstanceObserver()
    associations = AssociationObserver(instances._token)
    # A single model load for the entire run, including the Presidio option.
    detector = Detector(mode, _observation_sink=instances.observe, _association_sink=associations.observe)
    reference_hash = hashlib.sha256(reference.read_bytes()).hexdigest()
    private_values = {item["value"] for sample in samples for item in sample["instances"]}
    private_values.update({"diabetes", "asthma", "insulin", "inhaler"})
    association_samples, instance_samples, public_samples = [], [], []
    exact_checks = []
    all_association_reasons = set()
    try:
        for source_index, source in enumerate(data["sources"]):
            instances.begin_source(source_index)
            associations.begin_source(source)
            for sample in source["samples"]:
                name = sample["location"]
                if Path(name).name != name:
                    raise ValueError("fixture_location_invalid")
                path = fixtures / name
                initial_stat = path.stat()
                original = path.read_bytes()
                original_hash = hashlib.sha256(original).hexdigest()
                if original_hash != sample["records"]["document"]["sha256"]:
                    raise ValueError("fixture_original_binding_mismatch")
                # Keep per-object reasons as well as the aggregate union, so a
                # repeated gap cannot disappear behind a previous object's code.
                associations.reasons.clear()
                obj = _file_result(name, original, initial_stat, path.stat(), dict(DEFAULTS), detector)
                final_stat = path.stat()
                unchanged = (initial_stat.st_size, initial_stat.st_mtime_ns, initial_stat.st_ino) == (
                    final_stat.st_size, final_stat.st_mtime_ns, final_stat.st_ino)
                unchanged = unchanged and hashlib.sha256(path.read_bytes()).hexdigest() == original_hash
                gold, actual = associations.gold(sample), associations.commit(obj)
                associations.check_inventory(gold, actual)
                mapping_reasons = sorted(associations.reasons)
                all_association_reasons.update(mapping_reasons)
                occurrence_gold = instances.gold(sample["instances"])
                occurrence_actual, occurrence_complete = instances.commit(obj)
                clinical = _counts(gold["clinical"], actual["clinical"])
                links = _counts(gold["links"], actual["links"])
                # Mandatory exact identifier checks are not hidden by other NLP
                # labels. Every extra observed class remains in public metrics.
                uhid_gold = Counter({key: count for key, count in occurrence_gold.items() if key[0] == "personal_data:UHID"})
                uhid_actual = Counter({key: count for key, count in occurrence_actual.items() if key[0] == "personal_data:UHID"})
                uhids = _counts(uhid_gold, uhid_actual)
                persisted = json.dumps(obj, ensure_ascii=True)
                no_values = not any(value in persisted for value in private_values)
                no_transient_geometry = not any(key in persisted for key in (
                    '"document_units"', '"ocr_words"', '"native_words"', '"word_spans"'))
                no_evidence = all("evidence" not in finding for finding in obj["findings"])
                item_checks = {
                    "original_bytes_unchanged": unchanged,
                    "coverage_expectation_met": obj["status"] == sample["expected_status"],
                    "all_original_records_mapped": gold["records"] == actual["records"],
                    "original_mapping_complete": not mapping_reasons,
                    "exact_clinical_records": clinical == {"tp": len(gold["clinical"]), "fp": 0, "fn": 0},
                    "exact_patient_reference_associations": links == {"tp": len(gold["links"]), "fp": 0, "fn": 0},
                    "exact_uhid_occurrences": uhids == {"tp": sum(uhid_gold.values()), "fp": 0, "fn": 0},
                    "complete_occurrence_observations": occurrence_complete,
                    "no_values_or_evidence_retained": no_values and no_evidence,
                    "no_word_geometry_retained": no_transient_geometry,
                }
                exact_checks.extend(item_checks.values())
                association_samples.append({"category": source["category"], "gold": gold, "observed": actual,
                    "status": obj["status"]})
                instance_samples.append({"category": source["category"], "gold": occurrence_gold,
                    "observed": occurrence_actual, "status": obj["status"], "observation_complete": occurrence_complete})
                additional = Counter()
                for (label, _), count in occurrence_actual.items():
                    if label != "personal_data:UHID":
                        additional[label] += count
                public_samples.append({"sample": f"sample-{len(public_samples) + 1:03d}",
                    "format": path.suffix, "category": source["category"],
                    "original_units": len(sample["records"]["document"]["units"]),
                    "annotated_records": len(gold["records"]), "mapped_records": len(actual["records"]),
                    "status": obj["status"], "reason": _code(obj.get("reason")),
                    "expected_status": sample["expected_status"], "clinical_records": clinical,
                    "patient_reference_associations": links, "uhid_occurrences": uhids,
                    "additional_observed_pii_occurrences": dict(sorted(additional.items())),
                    "mapping_reasons": mapping_reasons, "checks": item_checks})
        association_complete, instance_complete = not all_association_reasons, instances.complete
        association_reasons = sorted(all_association_reasons)
        instance_reasons = sorted(instances.incomplete_reasons)
        association_results = association_metrics(association_samples, data["priority_classes"], .95, 30, association_complete)
        instance_results = occurrence_metrics(instance_samples, data["priority_classes"], .95, 30, instance_complete)
        coverage_met = all(sample["checks"]["coverage_expectation_met"] for sample in public_samples)
        blockers = acceptance_blockers(data, mode, [], coverage_met, .95, 30,
            instance_enabled=True, instance_complete=instance_complete, instance_results=instance_results,
            association_enabled=True, association_complete=association_complete, association_results=association_results)
        if any(sample["status"] != "full" for sample in public_samples):
            blockers.append("original_document_coverage_incomplete")
        reference_unchanged = reference_hash == hashlib.sha256(reference.read_bytes()).hexdigest()
        if not reference_unchanged:
            blockers.append("reference_inputs_changed_during_evaluation")
        report = {"created_utc": datetime.now(timezone.utc).isoformat(),
            "synthetic": True, "hospital_validated": False,
            "scope": "original_document_gateway_scanner_and_private_gold_collectors",
            "detector_mode": mode, "detector_version": detector.version,
            "reference_sha256": reference_hash, "reference_unchanged": reference_unchanged,
            "sample_count": len(public_samples), "coverage_counts": dict(Counter(row["status"] for row in public_samples)),
            "bounded_gateway_checks_passed": bool(exact_checks) and all(exact_checks)
                and association_complete and instance_complete and reference_unchanged,
            "all_exact_accuracy_checks_passed": all(exact_checks) and association_complete and instance_complete and reference_unchanged,
            "acceptance_candidate": False, "acceptance_blockers": blockers,
            "association_scoring": {"mapping_complete": association_complete,
                "incomplete_reasons": association_reasons, "results": association_results},
            "instance_scoring": {"observations_complete": instance_complete,
                "incomplete_reasons": instance_reasons, "results": instance_results},
            "samples": public_samples,
            "limitations": ["Synthetic calibration fixtures are not held-out hospital accuracy evidence",
                "Clinical presence and exact patient-reference association do not measure semantic diagnosis extraction",
                "The minimum 30 positive and 30 negative original objects per required class/category is not met",
                "Native PDF partial coverage remains partial even when visible records are mapped correctly",
                "PII occurrences are recognizer matches, not unique entities or patients",
                "Additional NLP PII predictions remain visible in occurrence metrics and may be false positives",
                "This bounded file-object runner does not validate source inventory, access controls, or deployment readiness"]}
        if any(value in json.dumps(report) for value in private_values):
            raise ValueError("report_value_leak")
        return report
    finally:
        associations.close()
        instances.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--reference", type=Path, default=Path(__file__).resolve().parent / "reference.json")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--scripts", type=Path, default=Path("/app/scripts"))
    parser.add_argument("--mode", choices=("rules", "presidio"), default="rules")
    args = parser.parse_args()
    sys.path.insert(0, str(args.scripts.resolve()))
    try:
        report = evaluate(args.fixtures.resolve(), args.reference.resolve(), args.mode)
    except Exception:
        # Never print exception text: parser/source errors may contain values.
        report = {"synthetic": True, "hospital_validated": False, "acceptance_candidate": False,
            "bounded_gateway_checks_passed": False, "error": "original_document_evaluation_failed",
            "acceptance_blockers": ["evaluation_incomplete"]}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: report[key] for key in ("bounded_gateway_checks_passed", "acceptance_candidate")}))
    return 0 if report["bounded_gateway_checks_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
