"""Private original-record gold and clinical association scoring (never diagnosis extraction)."""
from collections import Counter, defaultdict
import hashlib
import json
import math
import re

from instance_evaluation import NORMALIZATION

UNIT = "original_record_clinical_association_v1"
CLINICAL = "clinical_content:HEALTH_INFORMATION"
LINKED = "patient_linked_health:HEALTH_INFORMATION"
LABELS = {CLINICAL, LINKED}
ANCHORS = {"MRN", "UHID", "ABHA", "ABHA_ADDRESS", "IN_AADHAAR", "PERSON", "PATIENT_REFERENCE"}
MAPPINGS = {"json_pointer_v1", "text_spans_v1", "database_primary_key_v1", "document_rectangles_v1"}
LIMIT = 10000


def _rectangle(value):
    if (not isinstance(value, list) or len(value) != 4
            or any(type(number) not in {int, float} or not math.isfinite(number) or not 0 <= number <= 1 for number in value)
            or not value[0] < value[2] or not value[1] < value[3]):
        raise ValueError("Document records require normalized nonempty rectangles")
    return value


def _document_gold(records):
    document = records.get("document")
    if (not isinstance(document, dict) or set(document) != {"sha256", "unit_kind", "coordinate_space", "units"}
            or not isinstance(document["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", document["sha256"])
            or document["unit_kind"] not in {"page", "frame"}
            or document["coordinate_space"] != "rendered_unit_normalized_v1"
            or not isinstance(document["units"], list) or not 1 <= len(document["units"]) <= 100):
        raise ValueError("Document gold requires original bytes, unit inventory and rendered coordinate space")
    for ordinal, unit in enumerate(document["units"], 1):
        if (not isinstance(unit, dict) or set(unit) != {"ordinal", "pixel_width", "pixel_height"}
                or type(unit["ordinal"]) is not int or unit["ordinal"] != ordinal
                or any(type(unit[key]) is not int or unit[key] <= 0 for key in ("pixel_width", "pixel_height"))
                or unit["pixel_width"] * unit["pixel_height"] > 20_000_000):
            raise ValueError("Document gold requires ordered original-unit dimensions")
    by_unit = defaultdict(list)
    if len(records["items"]) > 1000:
        raise ValueError("Document reference rectangle limit exceeded")
    for item in records["items"]:
        locator = item["locator"]
        _locator(locator, "document_rectangles_v1")
        if locator["unit"] > len(document["units"]):
            raise ValueError("Document record names an absent original unit")
        box = locator["rect"]
        for other in by_unit[locator["unit"]]:
            if box[0] < other[2] and other[0] < box[2] and box[1] < other[3] and other[1] < box[3]:
                raise ValueError("Original document record rectangles cannot overlap")
        by_unit[locator["unit"]].append(box)
    return document


def _locator(value, mapping):
    if not isinstance(value, dict):
        raise ValueError("Record locator must be an object")
    if mapping == "json_pointer_v1":
        if set(value) != {"json_pointer"}:
            raise ValueError("JSON records require an original JSON pointer")
    elif mapping == "text_spans_v1":
        if (set(value) != {"start", "end"} or any(type(value.get(key)) is not int for key in ("start", "end"))
                or not 0 <= value["start"] < value["end"] <= 10_000_000):
            raise ValueError("Text records require bounded original decoded-text offsets")
    elif mapping == "document_rectangles_v1":
        if set(value) != {"unit", "rect"} or type(value["unit"]) is not int or not 1 <= value["unit"] <= 100:
            raise ValueError("Document records require original unit and rectangle")
        _rectangle(value["rect"])
    else:
        if set(value) - {"primary_key", "json_pointer"} or not isinstance(value.get("primary_key"), dict) or not value["primary_key"]:
            raise ValueError("Database records require a typed original primary-key tuple")
        for key, item in value["primary_key"].items():
            if not isinstance(key, str) or not key or len(key) > 256:
                raise ValueError("Invalid private primary-key field")
            if (type(item) not in {str, int, float} or (isinstance(item, str) and (not item or len(item) > 65536))
                    or (type(item) is float and not math.isfinite(item))):
                raise ValueError("Unsupported private primary-key type or value")
    if "json_pointer" in value:
        pointer = value["json_pointer"]
        if not isinstance(pointer, str) or len(pointer) > 4096 or (pointer and not pointer.startswith("/")):
            raise ValueError("Invalid original JSON pointer")
    # Preserve numeric/string PK identity; locator strings are never normalized.
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False)


def validate_association_manifest(data):
    if data.get("schema_version", 1) != 3:
        return False
    config = data.get("association_scoring")
    if (not isinstance(config, dict) or config.get("annotations_complete") is not True or
            config != {"unit": UNIT, "normalization": NORMALIZATION, "annotations_complete": True}):
        raise ValueError("Declare complete original-record clinical association annotations")
    count = 0
    for source in data["sources"]:
        for sample in source["samples"]:
            records = sample.get("records")
            expected = {"mapping", "items", "document"} if isinstance(records, dict) and records.get("mapping") == "document_rectangles_v1" else {"mapping", "items"}
            if not isinstance(records, dict) or set(records) != expected or records.get("mapping") not in MAPPINGS:
                raise ValueError("Unsupported original record mapping")
            mapping = records["mapping"]
            if (mapping == "database_primary_key_v1") != (source["kind"] == "sqlite"):
                raise ValueError("Record mapping does not match original source kind")
            if not isinstance(records["items"], list) or not records["items"]:
                raise ValueError("Annotate all original records, including clinical-negative records")
            seen = set()
            for item in records["items"]:
                if not isinstance(item, dict) or set(item) != {"locator", "clinical", "patient_reference"} or type(item["clinical"]) is not bool:
                    raise ValueError("Record gold requires locator, clinical boolean and patient_reference")
                identity = _locator(item["locator"], mapping)
                if identity in seen:
                    raise ValueError("Duplicate original record annotation")
                seen.add(identity)
                anchor = item["patient_reference"]
                if anchor is not None:
                    if (not item["clinical"] or not isinstance(anchor, dict) or set(anchor) != {"entity_type", "value"}
                            or anchor.get("entity_type") not in ANCHORS or not isinstance(anchor.get("value"), str)
                            or not 0 < len(anchor["value"]) <= 65536):
                        raise ValueError("A clinical record may have one exact patient reference or null")
                count += 1
                if count > 100000:
                    raise ValueError("Original record annotation limit exceeded")
            if mapping == "document_rectangles_v1":
                _document_gold(records)
    return True


def _json_records(original):
    """Independently enumerate original scalar-bearing objects with JSON pointers.

    Rendering is checked against the actual extraction output before any segment
    is mapped. Serialized JSON/XML strings, arrays of scalars and form feeds are
    unsupported; they are never guessed into original record identities.
    """
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate_json_key")
            result[key] = value
        return result
    root = json.loads(original, object_pairs_hook=pairs)
    records = []
    nodes = 0
    def walk(value, pointer, depth):
        nonlocal nodes
        nodes += 1
        if depth > 64 or nodes > 100000 or len(records) >= LIMIT:
            raise ValueError("record_limit")
        if isinstance(value, list):
            for index, item in enumerate(value):
                walk(item, pointer + "/" + str(index), depth + 1)
            return
        if not isinstance(value, dict):
            raise ValueError("non_object_json_record")
        fields, children = [], []
        for key, item in value.items():
            child_pointer = pointer + "/" + key.replace("~", "~0").replace("/", "~1")
            if isinstance(item, (dict, list)):
                children.append((item, child_pointer))
            else:
                from app.extraction import structured_kind
                if isinstance(item, str) and ("\f" in item or structured_kind(item)):
                    raise ValueError("embedded_record_mapping_unsupported")
                rendered = item if isinstance(item, str) else json.dumps(item, ensure_ascii=False)
                fields.append(json.dumps(key, ensure_ascii=False) + ": " + rendered)
        if fields:
            records.append(({"json_pointer": pointer}, " | ".join(fields)))
        for item, child_pointer in children:
            walk(item, child_pointer, depth + 1)
    walk(root, "", 0)
    if not records:
        raise ValueError("empty_record_inventory")
    return records


class AssociationObserver:
    """Raw source/anchor values are transient; only run-keyed counters survive callbacks."""
    def __init__(self, token, maximum=200000):
        self.token = token
        self.maximum = maximum
        self.count = 0
        self.reasons = set()
        self.samples = {}
        self.pending = {}
        self.segments = {}

    @property
    def complete(self):
        return not self.reasons

    def begin_source(self, source):
        self.samples = {sample["location"]: sample for sample in source["samples"]}
        self.pending.clear()
        self.segments.clear()

    def record_key(self, locator, mapping):
        return self.token("record\x00" + _locator(locator, mapping))

    def gold(self, sample):
        records, clinical, links = set(), set(), set()
        for item in sample["records"]["items"]:
            key = self.record_key(item["locator"], sample["records"]["mapping"])
            records.add(key)
            if item["clinical"]:
                clinical.add(key)
            anchor = item["patient_reference"]
            if anchor:
                links.add((key, anchor["entity_type"], self.token(anchor["value"])))
        return {"records": records, "clinical": clinical, "links": links}

    def _pending(self, location):
        return self.pending.setdefault(location, {"records": set(), "groups": Counter(), "events": []})

    def _map_segments(self, text, spans):
        from app.detection import source_segments
        result, cursor, owner = {}, 0, 0
        for segment, value in source_segments(text):
            if not value.strip():
                continue
            start = text.find(value, cursor)
            end = start + len(value)
            if start < 0 or text[cursor:start].strip():
                raise ValueError("unmapped_detector_segment")
            while owner < len(spans) and spans[owner][1] <= start:
                owner += 1
            if owner >= len(spans) or not spans[owner][0] <= start < end <= spans[owner][1]:
                raise ValueError("detector_segment_crosses_original_records")
            result[segment] = spans[owner][2]
            cursor = end
        if text[cursor:].strip():
            raise ValueError("unmapped_detector_tail")
        return result

    def _prepare_document(self, document, sample):
        """Match actual source words to independent original-unit gold rectangles.

        Region prefixes identify actual events only. They never define gold
        records. Mixed/unmapped segments retain unmatched predictions at commit.
        """
        from app.detection import source_segments
        if self._pending(sample["location"]).get("document_prepared"):
            raise ValueError("duplicate_original_document_observation")
        gold = _document_gold(sample["records"])
        raw = document["data"]
        kind = "pdf" if gold["unit_kind"] == "page" else "image"
        if (not isinstance(raw, bytes) or len(raw) > 25 * 1024 * 1024
                or hashlib.sha256(raw).hexdigest() != gold["sha256"]
                or (kind == "pdf" and document["suffix"] != ".pdf")
                or (kind == "image" and document["suffix"] not in {".png", ".jpg", ".jpeg", ".tif", ".tiff", ".bmp"})):
            raise ValueError("original_document_binding_mismatch")
        layout = document.get("layout")
        if (not isinstance(layout, dict) or layout.get("policy") != "explicit_patient_fields_geometry_v1"
                or type(layout.get("complete")) is not bool or not isinstance(layout.get("units"), list)
                or not isinstance(layout.get("regions"), list) or len(layout["regions"]) > LIMIT):
            raise ValueError("document_layout_unavailable")
        if not layout["complete"]:
            self.reasons.add("document_layout_observations_incomplete")
        if len(layout["units"]) != len(gold["units"]):
            raise ValueError("original_document_unit_inventory_mismatch")
        gold_by_unit = defaultdict(list)
        for item in sample["records"]["items"]:
            gold_by_unit[item["locator"]["unit"]].append((item["locator"]["rect"],
                self.record_key(item["locator"], "document_rectangles_v1")))
        words, owners, character_count = {}, {}, 0
        for expected, unit in zip(gold["units"], layout["units"]):
            if (not isinstance(unit, dict) or type(unit.get("ordinal")) is not int
                    or unit["ordinal"] != expected["ordinal"] or unit.get("kind") != kind
                    or not isinstance(unit.get("channels"), list) or len(unit["channels"]) > LIMIT):
                raise ValueError("original_document_unit_inventory_mismatch")
            if (unit.get("coordinate_space") != gold["coordinate_space"]
                    or any(type(unit.get(key)) is not int or unit[key] != expected[key] for key in ("pixel_width", "pixel_height"))):
                self.reasons.add("document_unit_geometry_unavailable_or_mismatched")
                continue
            channel_ids = set()
            for channel in unit["channels"]:
                if (not isinstance(channel, dict) or not isinstance(channel.get("id"), str)
                        or len(channel["id"]) > 40 or not re.fullmatch(r"[a-z]+(?:-[1-9][0-9]*)?", channel["id"])
                        or channel["id"] in channel_ids or not isinstance(channel.get("words"), list)):
                    raise ValueError("invalid_document_channel_inventory")
                channel_ids.add(channel["id"])
                for index, word in enumerate(channel["words"]):
                    if (not isinstance(word, dict) or not isinstance(word.get("text"), str) or not 0 < len(word["text"]) <= 512
                            or any(char.isspace() or ord(char) < 32 or 127 <= ord(char) <= 159 for char in word["text"])
                            or any(type(word.get(key)) is not int or not 1 <= word[key] <= LIMIT for key in ("block", "line"))):
                        raise ValueError("invalid_document_word_inventory")
                    box = _rectangle([word.get(key) for key in ("left", "top", "right", "bottom")])
                    ref = (unit["ordinal"], channel["id"], index)
                    words[ref] = word["text"]
                    character_count += len(word["text"])
                    if len(words) > LIMIT or character_count > 250000:
                        raise ValueError("document_geometry_observation_limit")
                    candidates = [key for rectangle, key in gold_by_unit[unit["ordinal"]]
                                  if rectangle[0] <= box[0] < box[2] <= rectangle[2]
                                  and rectangle[1] <= box[1] < box[3] <= rectangle[3]]
                    owners[ref] = candidates[0] if len(candidates) == 1 else None
                    if owners[ref] is None:
                        self.reasons.add("original_document_words_outside_gold_records")
        if layout["complete"] and (not isinstance(document.get("text"), str)
                or document["text"].split() != list(words.values())):
            self.reasons.add("document_layout_text_conservation_failed")
        uses, segments, prefixes, span_count = Counter(), [], set(), 0
        for region in layout["regions"]:
            if (not isinstance(region, dict) or not isinstance(region.get("prefix"), str)
                    or not isinstance(region.get("channel"), str) or type(region.get("unit")) is not int
                    or not isinstance(region.get("text"), str) or len(region["text"]) > 1_000_000
                    or type(region.get("association_candidate")) is not bool
                    or not isinstance(region.get("word_spans"), list) or len(region["word_spans"]) > LIMIT):
                raise ValueError("invalid_document_region_inventory")
            prefix, text = region["prefix"], region["text"]
            expected_prefix = gold["unit_kind"] + ":" + str(region["unit"]) + "/channel:" + region["channel"] + "/region:"
            if len(prefix) > 160 or prefix in prefixes or not prefix.startswith(expected_prefix) or not re.fullmatch(r"[1-9][0-9]*", prefix[len(expected_prefix):]):
                raise ValueError("invalid_document_region_prefix")
            prefixes.add(prefix)
            spans, cursor = [], 0
            for span in region["word_spans"]:
                if (not isinstance(span, dict) or set(span) != {"index", "start", "end"}
                        or any(type(span[key]) is not int for key in span) or span["index"] < 0
                        or not cursor <= span["start"] < span["end"] <= len(text)
                        or text[cursor:span["start"]].strip()):
                    raise ValueError("invalid_document_word_spans")
                ref = (region["unit"], region["channel"], span["index"])
                if ref not in words or text[span["start"]:span["end"]] != words[ref]:
                    raise ValueError("document_region_word_provenance_mismatch")
                span_count += 1
                if span_count > LIMIT:
                    raise ValueError("document_region_span_limit")
                uses[ref] += 1
                spans.append((span["start"], span["end"], ref))
                cursor = span["end"]
            if text[cursor:].strip():
                raise ValueError("document_region_text_unaccounted")
            actual_segments = [("record", text)] if region["association_candidate"] else source_segments(text)
            cursor = 0
            for segment, value in actual_segments:
                if not value.strip():
                    continue
                start, end = text.find(value, cursor), 0
                if start < 0 or text[cursor:start].strip():
                    raise ValueError("document_segment_provenance_unmapped")
                end = start + len(value)
                if any(left < start < right or left < end < right for left, right, _ in spans):
                    raise ValueError("document_segment_cuts_original_word")
                refs = [ref for left, right, ref in spans if start <= left < right <= end]
                segments.append((prefix + "/" + segment, refs))
                cursor = end
            if text[cursor:].strip():
                raise ValueError("document_segment_tail_unmapped")
        if set(uses) != set(words) or any(count != 1 for count in uses.values()):
            self.reasons.add("document_region_word_conservation_failed")
        mapped, records = {}, set()
        for segment, refs in segments:
            keys = {owners[ref] for ref in refs}
            if refs and len(keys) == 1 and None not in keys and all(uses[ref] == 1 for ref in refs):
                mapped[segment] = next(iter(keys))
                records.update(keys)
            else:
                self.reasons.add("document_segment_crosses_or_misses_gold_records")
        pending = self._pending(sample["location"])
        pending["document_prepared"] = True
        pending["records"].update(records)
        self.segments[sample["location"]] = mapped

    def _prepare(self, event):
        location = event["location"]
        sample = self.samples.get(location)
        if sample is None:
            raise ValueError("unannotated_object")
        mapping = sample["records"]["mapping"]
        document, cell = event.get("document"), event.get("cell")
        spans = []
        if document is not None:
            if mapping == "document_rectangles_v1":
                self._prepare_document(document, sample)
                return
            if len(document["data"]) > 10_000_000:
                raise ValueError("record_source_limit")
            raw = document["data"]
            original = raw.decode("utf-16" if raw.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig")
            text = document["text"]
            if mapping == "json_pointer_v1":
                if document["suffix"] != ".json":
                    raise ValueError("record_format_unsupported")
                pairs = _json_records(original)
                if text != "\f".join(value for _, value in pairs):
                    raise ValueError("original_rendering_mismatch")
                cursor = 0
                for locator, value in pairs:
                    spans.append((cursor, cursor + len(value), self.record_key(locator, mapping)))
                    cursor += len(value) + 1
            elif mapping == "text_spans_v1":
                if document["suffix"] not in {".txt", ".md", ".log"} or original != text:
                    raise ValueError("record_format_or_original_text_unsupported")
                cursor = 0
                for item in sorted(sample["records"]["items"], key=lambda item: item["locator"]["start"]):
                    locator = item["locator"]
                    start, end = locator["start"], locator["end"]
                    if start < cursor or end > len(original) or original[cursor:start].strip() or not original[start:end].strip():
                        raise ValueError("text_record_inventory_gap")
                    spans.append((start, end, self.record_key(locator, mapping)))
                    cursor = end
                if original[cursor:].strip():
                    raise ValueError("text_record_inventory_gap")
            else:
                raise ValueError("document_record_mapping_unsupported")
        elif cell is not None and mapping == "database_primary_key_v1":
            primary_key = cell["primary_key"]
            # _locator enforces original PK type and rejects absent/null/blob keys.
            _locator({"primary_key": primary_key}, mapping)
            text = cell["text"]
            original = cell["original"]
            from app.extraction import structured_kind
            kind = structured_kind(original) if isinstance(original, str) else None
            if kind:
                if kind != "json" or cell["prefix"]:
                    raise ValueError("structured_cell_mapping_unsupported")
                pairs = _json_records(original)
                if text != "\f".join(value for _, value in pairs):
                    raise ValueError("original_cell_rendering_mismatch")
                cursor = 0
                for locator, value in pairs:
                    locator = {"primary_key": primary_key, **locator}
                    spans.append((cursor, cursor + len(value), self.record_key(locator, mapping)))
                    cursor += len(value) + 1
            else:
                expected = cell["prefix"] + (original or "")
                if text != expected:
                    raise ValueError("original_cell_truncated")
                spans.append((0, len(text), self.record_key({"primary_key": primary_key}, mapping)))
        else:
            raise ValueError("original_record_source_missing")
        pending = self._pending(location)
        keys = {key for _, _, key in spans}
        if pending["records"] & keys:
            raise ValueError("duplicate_original_record")
        if len(pending["records"]) + len(keys) > LIMIT:
            raise ValueError("record_limit")
        pending["records"].update(keys)
        self.segments[location] = self._map_segments(text, spans)

    def observe(self, event):
        self.count += 1
        if self.count > self.maximum:
            self.reasons.add("association_observation_limit_reached")
            return
        location = event.get("location")
        if event.get("event") == "source":
            self.segments.pop(location, None)
            try:
                self._prepare(event)
            except Exception:
                # Parser/source/locator errors can contain patient values.
                self.reasons.add("original_record_mapping_incomplete_or_unsupported")
            return
        if event.get("event") != "clinical":
            self.reasons.add("association_observer_event_invalid")
            return
        key = self.segments.get(location, {}).get(event["source_segment"])
        if key is None:
            self.reasons.add("clinical_finding_record_unmapped")
            if self.samples.get(location, {}).get("records", {}).get("mapping") != "document_rectangles_v1":
                return
            # Keep mixed/unmapped actual predictions as FP instead of gaining
            # apparent precision by dropping them. This identity cannot match
            # any gold locator and never appears in the aggregate report.
            key = self.token("unmapped-document-prediction\x00" + location + "\x00" + event["source_segment"])
        group = (event["classification"], event["reason"], event["segment"])
        anchors = event.get("anchors", [])
        anchor = None
        if event["classification"] == "patient_linked_health":
            if len(anchors) != 1 or anchors[0][0] not in ANCHORS or not isinstance(anchors[0][1], str):
                self.reasons.add("clinical_patient_reference_unmapped")
            else:
                anchor = (anchors[0][0], self.token(anchors[0][1]))
        pending = self._pending(location)
        pending["groups"][group] += event["match_count"]
        pending["events"].append((group, key, anchor))

    def commit(self, obj):
        pending = self.pending.pop(obj["location"], {"records": set(), "groups": Counter(), "events": []})
        self.segments.pop(obj["location"], None)
        empty = {"records": set(), "clinical": set(), "links": set()}
        if obj["status"] not in {"full", "partial", "sampled"}:
            return empty
        final = Counter()
        for finding in obj.get("findings", []):
            if finding["entity_type"] == "HEALTH_INFORMATION":
                final[(finding["classification"], finding["reason"], finding["segment"])] += finding["match_count"]
        if any(pending["groups"].get(group) != count for group, count in final.items()):
            self.reasons.add("final_clinical_findings_observations_mismatch")
            return empty
        result = {"records": pending["records"], "clinical": set(), "links": set()}
        for group, record, anchor in pending["events"]:
            if group in final:
                result["clinical"].add(record)
                if anchor:
                    result["links"].add((record, *anchor))
        return result

    def check_inventory(self, gold, actual):
        if gold["records"] != actual["records"]:
            self.reasons.add("original_record_inventory_not_fully_mapped")

    def close(self):
        self.pending.clear()
        self.segments.clear()
        self.samples.clear()
        self.token = None


def association_metrics(samples, priorities, target, minimum, complete):
    categories = defaultdict(list)
    for sample in samples:
        categories[sample["category"]].append(sample)
    results = []
    for category in sorted(categories.keys() | priorities.keys()):
        group = categories[category]
        for label, measure, field in ((CLINICAL, "record_clinical_presence", "clinical"),
                                     (LINKED, "record_patient_reference_association", "links")):
            tp = fp = fn = positive_objects = negative_objects = positive_records = negative_records = 0
            for sample in group:
                gold, actual = sample["gold"][field], sample["observed"][field]
                tp += len(gold & actual)
                fp += len(actual - gold)
                fn += len(gold - actual)
                positive_objects += bool(gold)
                negative_objects += not gold
                positive_records += len(gold)
                negative_records += len(sample["gold"]["records"]) - len(gold)
            precision = tp / (tp + fp) if tp + fp else None
            recall = tp / (tp + fn) if tp + fn else None
            insufficient = positive_objects < minimum or negative_objects < minimum
            coverage = any(sample["status"] != "full" for sample in group)
            passed = precision is not None and recall is not None and precision >= target and recall >= target
            results.append({"category": category, "label": label, "measure": measure, "unit": UNIT,
                "priority": label in priorities.get(category, []) or (label == CLINICAL and LINKED in priorities.get(category, [])),
                "sample_count": len(group), "positive_source_objects": positive_objects, "negative_source_objects": negative_objects,
                "positive_records": positive_records, "negative_records": negative_records,
                "annotated_records": sum(len(sample["gold"]["records"]) for sample in group),
                "mapped_records": sum(len(sample["observed"]["records"]) for sample in group),
                "tp": tp, "fp": fp, "fn": fn, "precision": precision, "recall": recall,
                "target": target, "minimum_positive_and_negative_source_objects": minimum,
                "insufficient_samples": insufficient, "coverage_incomplete": coverage, "mapping_incomplete": not complete,
                "result": "unvalidated" if insufficient or coverage or not complete else "target_met" if passed else "below_target"})
    return results


def association_blockers(data, results, enabled, complete):
    priorities = data.get("priority_classes", {})
    required = {(category, label) for category, labels in priorities.items() for label in labels if label in LABELS}
    required.update((category, CLINICAL) for category, label in list(required) if label == LINKED)
    if not required and not enabled:
        return []
    if not enabled:
        return ["original_record_association_annotations_required"]
    blockers = [] if complete else ["original_record_association_mapping_incomplete"]
    indexed = {(row["category"], row["label"]): row for row in results}
    if any(indexed.get(key, {}).get("result") != "target_met" for key in required):
        blockers.append("priority_record_association_metrics_unvalidated_or_below_target")
    return blockers
