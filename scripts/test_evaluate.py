import unittest
import json
import tempfile
from pathlib import Path
from evaluate import metrics, validate_manifest, evaluate, acceptance_blockers, input_fingerprints


class EvaluationTests(unittest.TestCase):
    def test_false_positive_false_negative_and_true_negative(self):
        samples = [
            {"category": "digital", "expected": ["a"], "actual": ["a"], "status": "full"},
            {"category": "digital", "expected": ["a"], "actual": [], "status": "full"},
            {"category": "digital", "expected": [], "actual": ["a"], "status": "full"},
            {"category": "digital", "expected": [], "actual": [], "status": "full"},
        ]
        row = metrics(samples, minimum=1)[0]
        self.assertEqual((row["tp"], row["fp"], row["fn"], row["tn"]), (1, 1, 1, 1))
        self.assertEqual((row["precision"], row["recall"]), (.5, .5))
        self.assertEqual(row["result"], "below_target")

    def test_incomplete_extraction_cannot_pass(self):
        samples = [{"category": "ocr", "expected": ["a"], "actual": ["a"], "status": "partial"},
                   {"category": "ocr", "expected": [], "actual": [], "status": "full"}]
        self.assertEqual(metrics(samples, minimum=1)[0]["result"], "unvalidated")

    def test_zero_predictions_are_not_perfect_precision(self):
        row = metrics([{"category": "database", "expected": ["a"], "actual": [], "status": "failed"}], minimum=1)[0]
        self.assertIsNone(row["precision"])
        self.assertEqual(row["recall"], 0)

    def test_category_metrics_do_not_hide_ocr_failure(self):
        rows = metrics([
            {"category": "digital", "expected": ["a"], "actual": ["a"], "status": "full"},
            {"category": "ocr", "expected": ["a"], "actual": [], "status": "failed"},
        ])
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["recall"], 1)
        self.assertEqual(rows[1]["recall"], 0)

    def test_duplicate_ids_rejected(self):
        with self.assertRaises(ValueError):
            validate_manifest({"split": "evaluation", "synthetic": True, "sources": [{
                "kind": "filesystem", "category": "digital", "samples": [
                    {"id": "x", "expected": []}, {"id": "x", "expected": []}]}]})

    def test_missing_priority_class_and_category_remain_visible(self):
        rows = metrics([
            {"category": "digital", "expected": ["email"], "actual": ["email"], "status": "full"},
            {"category": "digital", "expected": [], "actual": [], "status": "full"},
        ], minimum=1, priority_classes={"digital": ["email", "aadhaar"], "ocr": ["email"]})
        indexed = {(row["category"], row["label"]): row for row in rows}
        self.assertEqual(indexed[("digital", "email")]["result"], "target_met")
        self.assertEqual(indexed[("digital", "aadhaar")]["result"], "unvalidated")
        self.assertEqual(indexed[("ocr", "email")]["sample_count"], 0)
        self.assertEqual(indexed[("ocr", "email")]["result"], "unvalidated")

    def test_acceptance_requires_production_detector_coverage_and_full_priority_scope(self):
        data = {"synthetic": False, "split": "evaluation",
                "priority_classes": {category: ["email"] for category in ("database", "digital", "ocr")}}
        samples = [{"category": category, "expected": ["email"] if i < 30 else [],
                    "actual": ["email"] if i < 30 else [], "status": "full"}
                   for category in data["priority_classes"] for i in range(60)]
        rows = metrics(samples, priority_classes=data["priority_classes"])
        self.assertEqual(acceptance_blockers(data, "presidio", rows, True, .95, 30), ["instance_annotations_required"])
        self.assertIn("production_detector_not_evaluated", acceptance_blockers(data, "rules", rows, True, .95, 30))
        self.assertIn("coverage_expectations_not_met", acceptance_blockers(data, "presidio", rows, False, .95, 30))
        self.assertIn("acceptance_evidence_floor_lowered", acceptance_blockers(data, "presidio", rows, True, .95, 1))
        partial = {**data, "priority_classes": {"digital": ["email"]}}
        self.assertIn("priority_classes_not_declared:ocr", acceptance_blockers(partial, "presidio", rows, True, .95, 30))

    def test_same_original_object_cannot_supply_multiple_samples(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "one.txt").write_text("Synthetic reference only")
            manifest = {"sources": [{"kind": "filesystem", "config": {"root": "."},
                                    "samples": [{"location": "one.txt"}, {"location": "./one.txt"}]}]}
            with self.assertRaisesRegex(ValueError, "same source object"):
                input_fingerprints(manifest, base)

    def test_hard_links_cannot_supply_independent_reference_samples(self):
        import os
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "one.txt").write_text("Synthetic reference only")
            os.link(base / "one.txt", base / "alias.txt")
            manifest = {"sources": [{"kind": "filesystem", "config": {"root": "."},
                                    "samples": [{"location": "one.txt"}, {"location": "alias.txt"}]}]}
            with self.assertRaisesRegex(ValueError, "same source object"):
                input_fingerprints(manifest, base)

    def test_real_scanner_evaluation_reports_omitted_priorities_without_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            for dirname, content in (("cal", "separate calibration text"), ("held", "fixture@example.test")):
                (base / dirname).mkdir()
                (base / dirname / "record.txt").write_text(content)
            cal = {"split": "calibration", "synthetic": True, "sources": [{
                "kind": "filesystem", "category": "digital", "config": {"root": "cal"},
                "samples": [{"id": "cal-1", "location": "record.txt", "expected": []}]}]}
            held = {"split": "evaluation", "synthetic": True,
                    "priority_classes": {"digital": ["personal_data:EMAIL_ADDRESS", "personal_data:IN_AADHAAR"],
                                         "ocr": ["personal_data:EMAIL_ADDRESS"]},
                    "sources": [{"kind": "filesystem", "category": "digital", "config": {"root": "held"},
                                 "samples": [{"id": "held-1", "location": "record.txt", "expected": ["personal_data:EMAIL_ADDRESS"]}]}]}
            (base / "cal.json").write_text(json.dumps(cal))
            (base / "held.json").write_text(json.dumps(held))
            result = evaluate(base / "held.json", "rules", base / "cal.json")
            self.assertFalse(result["acceptance_candidate"])
            self.assertEqual(result["samples"][0]["actual"], ["personal_data:EMAIL_ADDRESS"])
            self.assertTrue(any(row["category"] == "ocr" and row["sample_count"] == 0 for row in result["results"]))
            self.assertNotIn("fixture@example.test", json.dumps(result))


if __name__ == "__main__":
    unittest.main()
