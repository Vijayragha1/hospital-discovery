"""Private, bounded occurrence scoring. Values/tokens never enter public reports.

Schema v2 adds instance_scoring={unit: object_value_occurrence,
normalization: exact_nfc_v1, annotations_complete: true}; every sample supplies
instances=[{entity_type, classification: personal_data, value, occurrence_id?}].
Repeated entries are repeated original occurrences, not a set of unique values.
Record/page/span annotations are deliberately unsupported until the scanner can
map those original scopes. Clinical keyword counts are not diagnosis instances.
"""
from collections import Counter, defaultdict
import hashlib
import hmac
import secrets
import unicodedata


VALUE_ENTITY_TYPES = frozenset({"IN_AADHAAR", "IN_PAN", "ABHA", "ABHA_ADDRESS", "INSURANCE_ID", "MRN", "UHID",
    "EMAIL_ADDRESS", "PHONE_NUMBER", "DATE_OF_BIRTH", "PERSON", "LOCATION", "CREDIT_CARD"})
VALUE_LABELS = frozenset("personal_data:" + name for name in VALUE_ENTITY_TYPES)
KNOWN_LABELS = VALUE_LABELS | {"personal_data:PATIENT_REFERENCE", "clinical_content:HEALTH_INFORMATION",
                             "patient_linked_health:HEALTH_INFORMATION"}
NORMALIZATION = "exact_nfc_v1"
UNIT = "object_value_occurrence"
MAX_GOLD_INSTANCES = 100000
MAX_OBSERVATIONS = 200000
MAX_VALUE_CHARACTERS = 65536


def validate_instance_manifest(data):
    version = data.get("schema_version", 1)
    if type(version) is not int or version not in {1, 2, 3}:
        raise ValueError("Unsupported evaluation schema version")
    if version == 1:
        if "instance_scoring" in data or any("instances" in sample for source in data.get("sources", [])
                                              for sample in source.get("samples", [])):
            raise ValueError("Instance annotations require schema version 2")
        return False
    config = data.get("instance_scoring")
    if (not isinstance(config, dict) or config.get("annotations_complete") is not True or
            config != {"unit": UNIT, "normalization": NORMALIZATION, "annotations_complete": True}):
        raise ValueError("Declare complete object-value annotations and the supported exact normalization profile")
    if set(data) - ({"schema_version", "split", "synthetic", "instance_scoring", "priority_classes", "sources"}
                    | ({"association_scoring"} if version == 3 else set())):
        raise ValueError("Unsupported instance manifest fields or scope")
    total = 0
    for labels in data.get("priority_classes", {}).values():
        if any(label not in KNOWN_LABELS for label in labels):
            raise ValueError("Unknown priority label in instance manifest")
    for source in data.get("sources", []):
        if set(source) - {"kind", "category", "config", "options", "samples"}:
            raise ValueError("Unsupported reference source fields or scope")
        if (source["kind"] == "sqlite") != (source["category"] == "database"):
            raise ValueError("Database evaluation requires SQLite original exports; documents require a file category")
        for sample in source.get("samples", []):
            if set(sample) - ({"id", "location", "expected", "expected_status", "instances"}
                              | ({"records"} if version == 3 else set())):
                raise ValueError("Only object scope is supported; record, page and span annotations are not accepted")
            if any(label not in KNOWN_LABELS for label in sample.get("expected", [])):
                raise ValueError("Unknown diagnostic label in instance manifest")
            if not isinstance(sample.get("location"), str) or not sample["location"]:
                raise ValueError("Every reference object requires its private location")
            if sample.get("expected_status", "full") not in {"full", "sampled", "partial", "inaccessible", "unsupported", "excluded", "failed"}:
                raise ValueError("Unsupported coverage expectation")
            annotations = sample.get("instances")
            if not isinstance(annotations, list):
                raise ValueError("Every sample requires exhaustive instances, including an empty list for reviewed negatives")
            seen_ids = set()
            for annotation in annotations:
                if not isinstance(annotation, dict) or set(annotation) - {"entity_type", "classification", "value", "occurrence_id"}:
                    raise ValueError("Unsupported occurrence annotation fields or scope")
                if annotation.get("entity_type") not in VALUE_ENTITY_TYPES or annotation.get("classification") != "personal_data":
                    raise ValueError("Occurrence annotations require a supported value-bearing entity class")
                value = annotation.get("value")
                if not isinstance(value, str) or not value or len(value) > MAX_VALUE_CHARACTERS:
                    raise ValueError("Occurrence values must be nonempty bounded text")
                if "occurrence_id" in annotation:
                    identifier = annotation["occurrence_id"]
                    if not isinstance(identifier, str) or not identifier or len(identifier) > 128 or identifier in seen_ids:
                        raise ValueError("Optional occurrence IDs must be unique bounded strings within a sample")
                    seen_ids.add(identifier)
                total += 1
                if total > MAX_GOLD_INSTANCES:
                    raise ValueError("Reference instance limit exceeded")
            annotated_labels = {"personal_data:" + item["entity_type"] for item in annotations}
            if set(sample.get("expected", [])) & VALUE_LABELS != annotated_labels:
                raise ValueError("Diagnostic value labels must agree with the exhaustive occurrence annotations")
    if version == 3:
        from association_evaluation import validate_association_manifest
        validate_association_manifest(data)
    return True


def normalize_value(value):
    # No trimming, case folding, punctuation stripping, edit distance or O/0
    # substitution: OCR mistakes remain missed and incorrect occurrences.
    return unicodedata.normalize("NFC", value)


class InstanceObserver:
    """Transient keyed counters, committed only against final scanner findings."""
    def __init__(self, maximum=MAX_OBSERVATIONS):
        self._key = secrets.token_bytes(32)
        self.maximum = maximum
        self.count = 0
        self.source = None
        self.pending = defaultdict(lambda: defaultdict(Counter))
        self.incomplete_reasons = set()

    @property
    def complete(self):
        return not self.incomplete_reasons

    def begin_source(self, index):
        # Unreturned/failed objects cannot contribute provisional observations.
        self.pending.clear()
        self.source = index

    def _token(self, value):
        return hmac.new(self._key, normalize_value(value).encode("utf-8"), hashlib.sha256).digest()

    def gold(self, annotations):
        return Counter(("personal_data:" + item["entity_type"], self._token(item["value"])) for item in annotations)

    def observe(self, observation):
        self.count += 1
        if self.count > self.maximum:
            self.incomplete_reasons.add("instance_observation_limit_reached")
            return
        entity_type = observation.get("entity_type")
        if entity_type not in VALUE_ENTITY_TYPES or observation.get("classification") != "personal_data":
            self.incomplete_reasons.add("unsupported_observed_instance_class")
            return
        if self.source is None or not isinstance(observation.get("location"), str):
            self.incomplete_reasons.add("instance_source_context_missing")
            return
        value = observation.get("value")
        valid = observation.get("source_span_valid") is True and isinstance(value, str) and 0 < len(value) <= MAX_VALUE_CHARACTERS
        # None cannot match a gold token, so an invalid/label-only prediction is FP.
        token = self._token(value) if valid else None
        group = (entity_type, observation["classification"], observation["reason"], observation["segment"])
        self.pending[(self.source, observation["location"])][group][("personal_data:" + entity_type, token)] += 1

    def commit(self, obj):
        observed = self.pending.pop((self.source, obj["location"]), {})
        if obj.get("status") not in {"full", "sampled", "partial"}:
            return Counter(), True
        final = Counter()
        for finding in obj.get("findings", []):
            if finding["classification"] == "personal_data" and finding["entity_type"] in VALUE_ENTITY_TYPES:
                final[(finding["entity_type"], finding["classification"], finding["reason"], finding["segment"])] += finding["match_count"]
        actual = Counter()
        for group, count in final.items():
            candidates = observed.get(group, Counter())
            if count != sum(candidates.values()):
                self.incomplete_reasons.add("final_finding_observations_mismatch")
                return Counter(), False
            actual.update(candidates)
        # Groups absent from final findings are deliberately discarded. A parser
        # or detector may have failed after producing provisional observations.
        return actual, True

    def close(self):
        self.pending.clear()
        self._key = b""
        self.source = None


def occurrence_metrics(samples, priorities, target=.95, minimum=30, observations_complete=True):
    categories = defaultdict(list)
    for sample in samples:
        categories[sample["category"]].append(sample)
    result = []
    for category in sorted(categories.keys() | priorities.keys()):
        group = categories[category]
        labels = set(priorities.get(category, [])) & VALUE_LABELS
        labels.update(label for sample in group for label, _ in sample["gold"].keys() | sample["observed"].keys())
        for label in sorted(labels):
            tp = fp = fn = positives = negative_fp = 0
            for sample in group:
                gold = Counter({key: count for key, count in sample["gold"].items() if key[0] == label})
                actual = Counter({key: count for key, count in sample["observed"].items() if key[0] == label})
                matched = sum((gold & actual).values())
                tp += matched
                fn += sum(gold.values()) - matched
                fp += sum(actual.values()) - matched
                positives += bool(gold)
                negative_fp += not gold and bool(actual)
            negatives = len(group) - positives
            precision = tp / (tp + fp) if tp + fp else None
            recall = tp / (tp + fn) if tp + fn else None
            insufficient = positives < minimum or negatives < minimum
            incomplete = any(sample["status"] != "full" for sample in group)
            observation_gap = not observations_complete or any(not sample["observation_complete"] for sample in group)
            meets = precision is not None and recall is not None and precision >= target and recall >= target
            result.append({"category": category, "label": label, "priority": label in priorities.get(category, []),
                "unit": UNIT, "normalization": NORMALIZATION, "sample_count": len(group),
                "positive_samples": positives, "negative_samples": negatives, "negative_samples_with_false_positives": negative_fp,
                "expected_occurrences": tp + fn, "observed_occurrences": tp + fp, "tp": tp, "fp": fp, "fn": fn,
                "precision": precision, "recall": recall, "target": target,
                "minimum_positive_and_negative_samples": minimum, "insufficient_samples": insufficient,
                "coverage_incomplete": incomplete, "observations_incomplete": observation_gap,
                "result": "unvalidated" if insufficient or incomplete or observation_gap else "target_met" if meets else "below_target"})
    return result


def occurrence_acceptance_blockers(data, results, enabled, complete):
    if not enabled:
        return ["instance_annotations_required"]
    blockers = []
    if not complete:
        blockers.append("instance_observations_incomplete")
    priorities = data.get("priority_classes", {})
    required = {(category, label) for category, labels in priorities.items() for label in labels}
    unsupported = required - {(category, label) for category, label in required if label in VALUE_LABELS}
    association = set()
    if data.get("schema_version") == 3:
        from association_evaluation import LABELS
        association = {key for key in required if key[1] in LABELS}
        unsupported -= association
    if unsupported:
        # Health/schema classes need record-classification annotations, not a
        # fabricated clinical-keyword or patient-reference entity denominator.
        blockers.append("priority_instance_unit_unsupported")
    indexed = {(row["category"], row["label"]): row for row in results}
    supported = required - unsupported - association
    if (not supported and not association) or any(indexed.get(key, {}).get("result") != "target_met" for key in supported):
        blockers.append("priority_instance_metrics_unvalidated_or_below_target")
    return blockers
