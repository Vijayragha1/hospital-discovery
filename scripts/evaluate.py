#!/usr/bin/env python3
"""Run original sources through the real scanner; report no patient text or value hashes."""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

from instance_evaluation import (InstanceObserver, NORMALIZATION, UNIT,
    occurrence_acceptance_blockers, occurrence_metrics, validate_instance_manifest)
from association_evaluation import (AssociationObserver, UNIT as ASSOCIATION_UNIT,
    association_blockers, association_metrics, validate_association_manifest)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
REQUIRED_CATEGORIES = {"database", "digital", "ocr"}


def metrics(samples, target=.95, minimum=30, priority_classes=None):
    priority_classes = priority_classes or {}
    categories = defaultdict(list)
    for sample in samples:
        categories[sample["category"]].append(sample)
    rows = []
    for category in sorted(categories.keys() | priority_classes.keys()):
        group = categories[category]
        labels = set(priority_classes.get(category, []))
        labels.update(set().union(*(set(s["expected"]) | set(s["actual"]) for s in group)))
        for label in sorted(labels):
            tp = sum(label in s["expected"] and label in s["actual"] for s in group)
            fp = sum(label not in s["expected"] and label in s["actual"] for s in group)
            fn = sum(label in s["expected"] and label not in s["actual"] for s in group)
            tn = len(group) - tp - fp - fn
            precision = tp / (tp + fp) if tp + fp else None
            recall = tp / (tp + fn) if tp + fn else None
            insufficient = tp + fn < minimum or tn + fp < minimum
            incomplete = any(s["status"] != "full" for s in group)
            meets = (precision is not None and recall is not None and precision >= target and recall >= target)
            verdict = "unvalidated" if insufficient or incomplete else ("target_met" if meets else "below_target")
            rows.append({"category": category, "label": label, "sample_count": len(group),
                         "priority": label in priority_classes.get(category, []),
                         "positive_samples": tp + fn, "negative_samples": tn + fp,
                         "tp": tp, "fp": fp, "fn": fn, "tn": tn,
                         "precision": precision, "recall": recall, "target": target,
                         "minimum_positive_and_negative_samples": minimum,
                         "insufficient_samples": insufficient, "coverage_incomplete": incomplete,
                         "result": verdict})
    return rows


def validate_manifest(data, split=None):
    if not isinstance(data, dict):
        raise ValueError("Reference manifest must be an object")
    if data.get("split") not in {"calibration", "evaluation"} or (split and data["split"] != split):
        raise ValueError("Manifest split must be explicitly calibration or evaluation")
    if not isinstance(data.get("synthetic"), bool):
        raise ValueError("Manifest must explicitly declare synthetic true/false")
    priorities = data.get("priority_classes", {})
    if not isinstance(priorities, dict) or set(priorities) - REQUIRED_CATEGORIES:
        raise ValueError("Priority classes must be declared by database, digital, or ocr category")
    for labels in priorities.values():
        if (not isinstance(labels, list) or not labels or not all(isinstance(label, str) and label for label in labels)
                or len(labels) != len(set(labels))):
            raise ValueError("Each declared category needs a nonempty list of unique priority labels")
    ids = set()
    sources = data.get("sources")
    if not isinstance(sources, list):
        raise ValueError("Reference sources must be a list")
    for source in sources:
        if not isinstance(source, dict):
            raise ValueError("Reference source must be an object")
        if source.get("kind") not in {"filesystem", "sqlite"}:
            raise ValueError("Evaluation accepts local reference files or SQLite exports only")
        if source.get("category") not in REQUIRED_CATEGORIES:
            raise ValueError("Set source category to database, digital, or ocr")
        if not isinstance(source.get("config", {}), dict) or not isinstance(source.get("options", {}), dict):
            raise ValueError("Reference configuration and scan options must be objects")
        if not isinstance(source.get("samples"), list):
            raise ValueError("Reference samples must be a list")
        for sample in source["samples"]:
            if not isinstance(sample, dict):
                raise ValueError("Reference sample must be an object")
            sid = sample.get("id")
            if not isinstance(sid, str) or not sid or sid in ids:
                raise ValueError("Sample IDs must be unique within the manifest")
            ids.add(sid)
            expected = sample.get("expected")
            if not isinstance(expected, list) or not all(isinstance(x, str) for x in expected):
                raise ValueError("Expected labels must be a list of strings")
    if not ids:
        raise ValueError("Reference manifest contains no samples")
    validate_instance_manifest(data)
    return ids


def acceptance_blockers(data, mode, scored, coverage_met, target, minimum, *,
                        instance_results=(), instance_enabled=False, instance_complete=False,
                        association_results=(), association_enabled=False, association_complete=False):
    """A component smoke test must not look like whole-pilot accuracy evidence."""
    blockers = []
    priorities = data.get("priority_classes", {})
    if data["synthetic"]:
        blockers.append("synthetic_reference_set")
    if data["split"] != "evaluation":
        blockers.append("not_held_out_evaluation")
    if mode != "presidio":
        blockers.append("production_detector_not_evaluated")
    for category in sorted(REQUIRED_CATEGORIES - priorities.keys()):
        blockers.append("priority_classes_not_declared:" + category)
    if target < .95 or minimum < 30:
        blockers.append("acceptance_evidence_floor_lowered")
    if not coverage_met:
        blockers.append("coverage_expectations_not_met")
    # Object-presence metrics are diagnostics, never an accuracy acceptance gate.
    blockers.extend(occurrence_acceptance_blockers(data, instance_results, instance_enabled, instance_complete))
    blockers.extend(association_blockers(data, association_results, association_enabled, association_complete))
    return blockers


def input_fingerprints(data, base, *, snapshot=False):
    fingerprints = {}
    seen_objects = set()
    for source in data["sources"]:
        config = source["config"]
        if source["kind"] == "sqlite":
            paths = [(base / config["path"]).resolve(strict=True)]
            original = paths[0].stat()
            identities = [(original.st_dev, original.st_ino, sample["location"]) for sample in source["samples"]]
        else:
            directory = (base / config["root"]).resolve(strict=True)
            paths = [(directory / item["location"]).resolve(strict=True) for item in source["samples"]]
            if any(not path.is_relative_to(directory) for path in paths):
                raise ValueError("Reference sample path escapes its source")
            identities = [(path.stat().st_dev, path.stat().st_ino, "file") for path in paths]
        for identity in identities:
            if identity in seen_objects:
                raise ValueError("The same source object cannot count as multiple reference samples")
            seen_objects.add(identity)
        for path in paths:
            if path.is_file():
                with path.open("rb") as handle:
                    digest = hashlib.file_digest(handle, "sha256").hexdigest() if sys.version_info >= (3, 11) else hashlib.sha256(handle.read()).hexdigest()
                fingerprints[str(path)] = digest
    return fingerprints if snapshot else set(fingerprints.values())


def _read_manifest(path):
    # Gold annotations are local secrets. Bound the input and never copy them
    # (including freeform IDs/locations) into the public v2 report.
    with path.open("rb") as handle:
        raw = handle.read(16 * 1024 * 1024 + 1)
    if len(raw) > 16 * 1024 * 1024:
        raise ValueError("Reference manifest size limit exceeded")
    def unique_fields(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("Reference manifest has duplicate object fields")
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=unique_fields)


def evaluate(manifest, mode, calibration=None, target=.95, minimum=30):
    from app.detection import Detector
    from app.scanning import scan_source

    if not 0 < target <= 1 or minimum < 1:
        raise ValueError("Invalid accuracy target or sample floor")
    data = _read_manifest(manifest)
    ids = validate_manifest(data)
    instance_enabled = validate_instance_manifest(data)
    association_enabled = validate_association_manifest(data)
    initial_inputs = input_fingerprints(data, manifest.parent, snapshot=True)
    if data["split"] == "evaluation":
        if calibration is None:
            raise ValueError("Held-out evaluation requires --calibration manifest to check separation")
        previous = _read_manifest(calibration)
        prior_ids = validate_manifest(previous, "calibration")
        if ids & prior_ids:
            raise ValueError("Calibration and evaluation sample IDs overlap")
        if input_fingerprints(data, manifest.parent) & input_fingerprints(previous, calibration.parent):
            raise ValueError("Calibration and evaluation content overlaps")
    observer = InstanceObserver() if instance_enabled else None
    associations = AssociationObserver(observer._token) if association_enabled else None
    detector = Detector(mode=mode, **({"_observation_sink": observer.observe} if observer else {}),
                        **({"_association_sink": associations.observe} if associations else {}))
    evaluated = []
    instances = []
    association_samples = []
    unexpected_objects = 0
    duplicate_objects = 0
    try:
        for source_index, source in enumerate(data["sources"]):
            config = dict(source["config"])
            key = "root" if source["kind"] == "filesystem" else "path"
            config[key] = str((manifest.parent / config[key]).resolve(strict=True))
            if observer:
                observer.begin_source(source_index)
            if associations:
                associations.begin_source(source)
                if source["kind"] == "sqlite" and any(Path(config[key] + suffix).exists() for suffix in ("-wal", "-journal")):
                    associations.reasons.add("database_reference_snapshot_unverified")
            scanned, committed, association_committed = {}, {}, {}
            # Evidence examples are deliberately disabled: complete observations
            # use the private callback, not capped/truncated persisted evidence.
            options = {**source.get("options", {}), "capture_evidence": False}
            for obj in scan_source(source["kind"], config, options, detector, lambda: "running"):
                location = obj["location"]
                if location in scanned:
                    duplicate_objects += 1
                    if observer:
                        observer.incomplete_reasons.add("duplicate_scanner_object")
                scanned[location] = obj
                if observer:
                    committed[location] = observer.commit(obj)
                if associations:
                    association_committed[location] = associations.commit(obj)
            if associations and source["kind"] == "sqlite" and any(Path(config[key] + suffix).exists() for suffix in ("-wal", "-journal")):
                associations.reasons.add("database_reference_snapshot_unverified")
            expected_locations = {sample["location"] for sample in source["samples"]}
            unexpected_objects += len(set(scanned) - expected_locations)
            for sample in source["samples"]:
                obj = scanned.get(sample["location"], {})
                actual = sorted({f["classification"] + ":" + f["entity_type"] for f in obj.get("findings", [])})
                evaluated.append({"id": f"sample-{len(evaluated) + 1:06d}" if observer else sample["id"],
                    "category": source["category"], "expected": sorted(set(sample["expected"])), "actual": actual,
                    "status": obj.get("status", "failed"), "reason": obj.get("reason", "object_not_returned") if not obj else obj.get("reason"),
                    "coverage_expectation_met": obj.get("status") == sample.get("expected_status", "full")})
                if observer:
                    observed, complete = committed.get(sample["location"], (Counter(), True))
                    # An OCR label alone cannot turn a plain-text fixture into
                    # evidence that the original OCR path was evaluated.
                    if source["category"] == "ocr" and obj.get("metadata", {}).get("ocr_requested") is not True:
                        observer.incomplete_reasons.add("ocr_source_path_not_verified")
                    instances.append({"category": source["category"], "gold": observer.gold(sample["instances"]),
                        "observed": observed, "status": obj.get("status", "failed"), "observation_complete": complete})
                if associations:
                    gold = associations.gold(sample)
                    observed = association_committed.get(sample["location"], {"records": set(), "clinical": set(), "links": set()})
                    associations.check_inventory(gold, observed)
                    association_samples.append({"category": source["category"], "gold": gold, "observed": observed,
                                                "status": obj.get("status", "failed")})
        inputs_unchanged = initial_inputs == input_fingerprints(data, manifest.parent, snapshot=True)
        if observer and not inputs_unchanged:
            observer.incomplete_reasons.add("reference_inputs_changed_during_evaluation")
        if associations and not inputs_unchanged:
            associations.reasons.add("reference_inputs_changed_during_evaluation")
        instance_complete = bool(observer and observer.complete)
        instance_reasons = sorted(observer.incomplete_reasons) if observer else []
        instance_results = occurrence_metrics(instances, data.get("priority_classes", {}), target, minimum,
                                              instance_complete) if observer else []
        association_complete = bool(associations and associations.complete and not duplicate_objects)
        association_reasons = sorted(associations.reasons) if associations else []
        association_results = association_metrics(association_samples, data.get("priority_classes", {}), target,
                                                  minimum, association_complete) if associations else []
    finally:
        if associations:
            associations.close()
        if observer:
            observer.close()
    scored = metrics(evaluated, target, minimum, data.get("priority_classes"))
    coverage_met = all(s["coverage_expectation_met"] for s in evaluated) and not unexpected_objects and not duplicate_objects
    blockers = acceptance_blockers(data, mode, scored, coverage_met, target, minimum,
        instance_results=instance_results, instance_enabled=instance_enabled, instance_complete=instance_complete,
        association_results=association_results, association_enabled=association_enabled, association_complete=association_complete)
    return {"created_utc": datetime.now(timezone.utc).isoformat(), "split": data["split"],
            "synthetic": data["synthetic"], "hospital_validated": False,
            "unit": "object-level classification/entity presence, not entity spans or individual patients",
            "object_presence_diagnostic_only": True,
            "instance_scoring": {"enabled": instance_enabled, "unit": UNIT, "normalization": NORMALIZATION,
                "observations_complete": instance_complete, "incomplete_reasons": instance_reasons,
                "original_inputs_unchanged": inputs_unchanged,
                "results": instance_results},
            "association_scoring": {"enabled": association_enabled, "unit": ASSOCIATION_UNIT,
                "normalization": NORMALIZATION, "mapping_complete": association_complete,
                "incomplete_reasons": association_reasons, "results": association_results},
            "detector_version": detector.version, "detector_mode": mode,
            "sample_count": len(evaluated), "unexpected_objects": unexpected_objects, "duplicate_scanner_objects": duplicate_objects,
            "coverage_counts": dict(Counter(s["status"] for s in evaluated)),
            "coverage_expectations_met": coverage_met,
            "results": scored, "samples": evaluated,
            "priority_classes": data.get("priority_classes", {}),
            "acceptance_blockers": blockers, "acceptance_candidate": not blockers,
            "limitations": ["Instance scoring matches class and exact NFC-normalized value one-to-one within each source object",
                "PII occurrences do not measure original span, page or record identity",
                "Clinical association requires v3 supported original record mappings; no semantic diagnosis extraction accuracy",
                "Unmapped PDF/OCR/Office layouts and schema-only PII instance units remain unsupported",
                "Repeated values count as occurrences, not unique entities or patients",
                "Object-label metrics are diagnostic only and do not establish instance recall or OCR character accuracy",
                "Hospital reviewer sign-off required"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--calibration", type=Path)
    parser.add_argument("--mode", choices=("presidio", "rules"), default="presidio")
    parser.add_argument("--minimum-samples", type=int, default=30)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.minimum_samples < 1:
        parser.error("minimum-samples must be positive")
    try:
        report = evaluate(args.manifest.resolve(), args.mode, args.calibration.resolve() if args.calibration else None, minimum=args.minimum_samples)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n")
    except Exception:
        # Source/driver exception text can include patient values or credentials.
        print("Evaluation failed; check manifest separation, local source access, and selected detector availability.", file=sys.stderr)
        return 2
    print(f"Evaluated {report['sample_count']} samples; synthetic={report['synthetic']}; acceptance_candidate={report['acceptance_candidate']}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
