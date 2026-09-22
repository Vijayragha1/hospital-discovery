"""Independent synthetic original rectangles exercise private observer scoring."""
from copy import deepcopy
import hashlib
import json

import pytest

from association_evaluation import (AssociationObserver, CLINICAL, LINKED, UNIT, association_metrics,
                                    validate_association_manifest)


ORIGINAL = b"synthetic original document bytes for observer contract checks"
RECTANGLES = [[0, 0, .5, .5], [.5, 0, 1, .5], [0, .5, .5, 1], [.5, .5, 1, 1]]


def specimen(kind="image", repeated=False):
    texts = [("MRN", "SYN100", "diabetes"), ("MRN", "SYN100" if repeated else "SYN200", "hypertension"),
             ("Maintenance", "notice"), ("diabetes", "handout")]
    words, groups = [], []
    # Independently chosen source word coordinates. Gold contains original
    # rectangles only, never these generated region IDs or algorithm decisions.
    for block, (tokens, left, top) in enumerate(zip(texts, (.05, .55, .05, .55), (.1, .1, .6, .6)), 1):
        indices = []
        for index, token in enumerate(tokens):
            indices.append(len(words))
            words.append({"text": token, "left": left + index * .1, "right": left + index * .1 + .08,
                          "top": top, "bottom": top + .05, "block": block, "line": 1})
        groups.append(indices)
    unit_kind = "page" if kind == "pdf" else "frame"
    item = {"location": "original.pdf" if kind == "pdf" else "original.png", "records": {
        "mapping": "document_rectangles_v1", "document": {"sha256": hashlib.sha256(ORIGINAL).hexdigest(),
            "unit_kind": unit_kind, "coordinate_space": "rendered_unit_normalized_v1",
            "units": [{"ordinal": 1, "pixel_width": 1000, "pixel_height": 1000}]},
        "items": [{"locator": {"unit": 1, "rect": rectangle}, "clinical": clinical,
            "patient_reference": {"entity_type": "MRN", "value": value} if value else None}
            for rectangle, clinical, value in zip(RECTANGLES, (True, True, False, True),
                ("SYN100", "SYN100" if repeated else "SYN200", None, None))]}}
    layout = {"policy": "explicit_patient_fields_geometry_v1", "complete": True, "units": [{
        "kind": kind, "ordinal": 1, "pixel_width": 1000, "pixel_height": 1000,
        "coordinate_space": "rendered_unit_normalized_v1", "channels": [{"id": "ocr", "words": words}]}],
        "regions": [region(words, group, number, unit_kind=unit_kind) for number, group in enumerate(groups, 1)]}
    document = {"data": ORIGINAL, "suffix": ".pdf" if kind == "pdf" else ".png",
                "text": "\n".join(" ".join(tokens) for tokens in texts), "metadata": {}, "layout": layout}
    return item, document


def region(words, indices, number, unit_kind="frame", unit=1, candidate=True):
    text, spans = "", []
    for index in indices:
        if text:
            text += " "
        start = len(text)
        text += words[index]["text"]
        spans.append({"index": index, "start": start, "end": len(text)})
    return {"prefix": f"{unit_kind}:{unit}/channel:ocr/region:{number}", "unit": unit, "channel": "ocr",
            "text": text, "word_spans": spans, "association_candidate": candidate}


def clinical(region, value=None):
    if region["association_candidate"]:
        source_segment = region["prefix"] + "/record"
    else:
        source_segment = region["prefix"] + "/segment:1/block:1/row:1"
    return {"event": "clinical", "source_segment": source_segment, "segment": source_segment,
        "classification": "patient_linked_health" if value else "clinical_content", "reason": "synthetic_clinical",
        "match_count": 1, "anchors": [("MRN", value)] if value else []}


def score(item, document, events=None, status="full", final_mutation=None):
    token = lambda value: hashlib.sha256(("private-run-key\0" + value).encode()).hexdigest()
    observer = AssociationObserver(token)
    observer.begin_source({"samples": [item]})
    observer.observe({"event": "source", "location": item["location"], "document": document})
    if events is None:
        regions = document["layout"]["regions"]
        events = [clinical(regions[0], "SYN100"), clinical(regions[1], item["records"]["items"][1]["patient_reference"]["value"]),
                  clinical(regions[3])]
    findings = []
    for event in events:
        observer.observe({**event, "location": item["location"]})
        findings.append({"entity_type": "HEALTH_INFORMATION", **{key: event[key]
            for key in ("classification", "reason", "segment", "match_count")}})
    if final_mutation:
        findings = final_mutation(findings)
    actual = observer.commit({"location": item["location"], "status": status, "findings": findings})
    gold = observer.gold(item)
    observer.check_inventory(gold, actual)
    results = association_metrics([{"category": "ocr", "gold": gold, "observed": actual, "status": status}],
        {"ocr": [LINKED]}, .95, 1, observer.complete)
    return {row["label"]: row for row in results}, observer.reasons


@pytest.mark.parametrize("kind", ["pdf", "image"])
def test_independent_original_rectangles_score_linked_unlinked_and_negative_records(kind):
    item, document = specimen(kind)
    results, reasons = score(item, document)
    assert reasons == set()
    assert (results[CLINICAL]["tp"], results[CLINICAL]["fp"], results[CLINICAL]["fn"]) == (3, 0, 0)
    assert (results[LINKED]["tp"], results[LINKED]["fp"], results[LINKED]["fn"]) == (2, 0, 0)
    assert results[CLINICAL]["mapped_records"] == 4
    assert all(row["result"] == "unvalidated" for row in results.values())  # one synthetic object, no negatives pool
    report = json.dumps(results)
    assert not any(value in report for value in ("SYN100", "SYN200", "original.png", "rect", "left", "ocr/region"))


def test_swapped_patient_values_are_fp_and_fn_despite_correct_clinical_regions():
    item, document = specimen()
    regions = document["layout"]["regions"]
    results, reasons = score(item, document, [clinical(regions[0], "SYN200"), clinical(regions[1], "SYN100"), clinical(regions[3])])
    assert not reasons
    assert results[CLINICAL]["tp"] == 3
    assert (results[LINKED]["tp"], results[LINKED]["fp"], results[LINKED]["fn"]) == (0, 2, 2)


def test_equal_reference_values_in_distinct_original_rectangles_count_separately():
    item, document = specimen(repeated=True)
    results, reasons = score(item, document)
    assert not reasons and results[LINKED]["tp"] == 2
    assert results[CLINICAL]["positive_records"] == 3


def test_identical_values_and_coordinates_on_different_original_pages_remain_distinct():
    item, document = specimen("pdf", repeated=True)
    second = deepcopy(document["layout"]["units"][0])
    second["ordinal"] = 2
    document["layout"]["units"].append(second)
    document["text"] += "\f" + document["text"]
    item["records"]["document"]["units"].append({"ordinal": 2, "pixel_width": 1000, "pixel_height": 1000})
    for record in list(item["records"]["items"]):
        copied = deepcopy(record)
        copied["locator"]["unit"] = 2
        item["records"]["items"].append(copied)
    for row in list(document["layout"]["regions"]):
        copied = deepcopy(row)
        copied["unit"] = 2
        copied["prefix"] = copied["prefix"].replace("page:1/", "page:2/")
        document["layout"]["regions"].append(copied)
    events = [clinical(row, "SYN100" if index % 4 < 2 else None)
              for index, row in enumerate(document["layout"]["regions"]) if index % 4 != 2]
    results, reasons = score(item, document, events)
    assert not reasons and results[LINKED]["tp"] == 4 and results[CLINICAL]["tp"] == 6
    assert results[CLINICAL]["mapped_records"] == 8


def test_mixed_patient_prediction_is_never_assigned_to_either_gold_record_or_dropped():
    item, document = specimen()
    layout = document["layout"]
    mixed = region(layout["units"][0]["channels"][0]["words"], list(range(6)), 10)
    layout["regions"] = [mixed, *layout["regions"][2:]]
    results, reasons = score(item, document, [clinical(mixed, "SYN100"), clinical(layout["regions"][2])])
    assert "document_segment_crosses_or_misses_gold_records" in reasons
    assert "clinical_finding_record_unmapped" in reasons
    assert (results[CLINICAL]["tp"], results[CLINICAL]["fp"], results[CLINICAL]["fn"]) == (1, 1, 2)
    assert (results[LINKED]["tp"], results[LINKED]["fp"], results[LINKED]["fn"]) == (0, 1, 2)
    assert results[CLINICAL]["mapping_incomplete"]


def test_missing_original_record_stays_fn_even_with_no_ocr_words_or_algorithm_region():
    item, document = specimen()
    layout = document["layout"]
    words = layout["units"][0]["channels"][0]["words"]
    # The original gold rectangle remains while OCR misses every word there.
    del words[3:6]
    document["text"] = " ".join(word["text"] for word in words)
    layout["regions"] = [region(words, list(range(3)), 1), region(words, [3, 4], 2), region(words, [5, 6], 3)]
    results, reasons = score(item, document, [clinical(layout["regions"][0], "SYN100"), clinical(layout["regions"][2])])
    assert "original_record_inventory_not_fully_mapped" in reasons
    assert (results[LINKED]["tp"], results[LINKED]["fn"]) == (1, 1)
    assert (results[CLINICAL]["tp"], results[CLINICAL]["fn"]) == (2, 1)


def test_negative_and_unlinked_regions_can_produce_false_positive_associations():
    item, document = specimen()
    regions = document["layout"]["regions"]
    results, reasons = score(item, document, [clinical(regions[2], "SYN100"), clinical(regions[3], "SYN200")])
    assert not reasons
    assert (results[CLINICAL]["tp"], results[CLINICAL]["fp"], results[CLINICAL]["fn"]) == (1, 1, 2)
    assert results[LINKED]["fp"] == results[LINKED]["fn"] == 2


def test_residual_still_scores_clinical_presence_without_inventing_patient_linkage():
    item, document = specimen()
    for row in document["layout"]["regions"]:
        row["association_candidate"] = False
    results, reasons = score(item, document, [clinical(row) for index, row in enumerate(document["layout"]["regions"]) if index != 2])
    assert not reasons and results[CLINICAL]["tp"] == 3
    assert results[LINKED]["tp"] == 0 and results[LINKED]["fn"] == 2


def test_unmapped_global_supplement_is_counted_as_prediction_and_blocks_acceptance():
    item, document = specimen()
    document["layout"]["complete"] = False
    unmapped = {"prefix": "document:unmapped/channel:unmapped/region:1", "association_candidate": False}
    results, reasons = score(item, document, [clinical(unmapped)])
    assert "document_layout_observations_incomplete" in reasons and "clinical_finding_record_unmapped" in reasons
    assert (results[CLINICAL]["tp"], results[CLINICAL]["fp"], results[CLINICAL]["fn"]) == (0, 1, 3)
    assert results[LINKED]["fn"] == 2


def test_empty_ocr_observations_do_not_turn_annotated_original_records_into_success():
    item, document = specimen()
    document["layout"]["units"][0]["channels"] = []
    document["layout"]["regions"] = []
    document["text"] = ""
    results, reasons = score(item, document, [])
    assert "original_record_inventory_not_fully_mapped" in reasons
    assert results[CLINICAL]["mapped_records"] == 0 and results[CLINICAL]["fn"] == 3
    assert results[LINKED]["fn"] == 2


def test_correct_region_scores_do_not_upgrade_partial_original_pdf_coverage():
    results, reasons = score(*specimen("pdf"), status="partial")
    assert not reasons and results[LINKED]["tp"] == 2
    assert all(row["coverage_incomplete"] and row["result"] == "unvalidated" for row in results.values())


def test_layout_complete_flag_cannot_hide_extracted_text_outside_its_word_inventory():
    item, document = specimen()
    document["text"] += " UNMAPPED_EXTRACTED_CONTENT"
    results, reasons = score(item, document)
    assert "document_layout_text_conservation_failed" in reasons
    assert all(row["mapping_incomplete"] and row["result"] == "unvalidated" for row in results.values())


@pytest.mark.parametrize("mutation", ["bytes", "dimensions", "units", "policy", "coordinate_space", "missing_geometry",
                                     "text_outside_layout", "word_outside_gold", "word_crosses_boundary", "span_mismatch",
                                     "lost_word", "duplicate_word", "unaccounted_region_text"])
def test_invalid_or_incomplete_original_provenance_blocks_acceptance(mutation):
    item, document = specimen()
    layout, unit = document["layout"], document["layout"]["units"][0]
    events = [clinical(layout["regions"][0], "SYN100"), clinical(layout["regions"][1], "SYN200"), clinical(layout["regions"][3])]
    if mutation == "bytes": document["data"] += b"changed"
    elif mutation == "dimensions": unit["pixel_width"] += 1
    elif mutation == "units": layout["units"] = []
    elif mutation == "policy": layout["policy"] = "unrecognized_policy"
    elif mutation == "coordinate_space": unit["coordinate_space"] = "unknown_space"
    elif mutation == "missing_geometry": unit["channels"] = []
    elif mutation == "text_outside_layout": layout["complete"] = False
    elif mutation == "word_outside_gold":
        item["records"]["items"][0]["locator"]["rect"] = [0, 0, .01, .01]
    elif mutation == "word_crosses_boundary":
        unit["channels"][0]["words"][0].update(left=.49, right=.51)
    elif mutation == "span_mismatch": layout["regions"][0]["word_spans"][0]["end"] += 1
    elif mutation == "lost_word": layout["regions"].pop(2)
    elif mutation == "duplicate_word":
        copy = deepcopy(layout["regions"][0])
        copy["prefix"] = "frame:1/channel:ocr/region:99"
        layout["regions"].append(copy)
    elif mutation == "unaccounted_region_text": layout["regions"][0]["text"] += " UNMAPPED_TEXT"
    results, reasons = score(item, document, events)
    assert reasons and all(row["mapping_incomplete"] and row["result"] == "unvalidated" for row in results.values())


@pytest.mark.parametrize("status", ["failed", "inaccessible", "unsupported"])
def test_failed_final_object_discards_all_provisional_geometric_predictions(status):
    results, reasons = score(*specimen(), status=status)
    assert results[CLINICAL]["tp"] == results[CLINICAL]["fp"] == 0
    assert results[CLINICAL]["fn"] == 3 and results[LINKED]["fn"] == 2
    assert reasons


def test_final_finding_reconciliation_prevents_detector_only_success():
    results, reasons = score(*specimen(), final_mutation=lambda rows: [{**row, "match_count": 2} for row in rows])
    assert "final_clinical_findings_observations_mismatch" in reasons
    assert results[LINKED]["tp"] == 0 and results[LINKED]["fn"] == 2


def manifest(item):
    return {"schema_version": 3, "association_scoring": {"unit": UNIT, "normalization": "exact_nfc_v1", "annotations_complete": True},
            "sources": [{"kind": "filesystem", "samples": [item]}]}


def test_document_manifest_accepts_only_independent_original_rectangles():
    item, _ = specimen()
    assert validate_association_manifest(manifest(item))
    for mutation in ("algorithm_id", "overlap", "nan", "out_of_bounds", "unknown_unit", "hash", "dimension"):
        changed = deepcopy(item)
        if mutation == "algorithm_id": changed["records"]["items"][0]["locator"] = {"region": "frame:1/channel:ocr/region:1"}
        elif mutation == "overlap": changed["records"]["items"][1]["locator"]["rect"] = [.25, 0, 1, .5]
        elif mutation == "nan": changed["records"]["items"][0]["locator"]["rect"][0] = float("nan")
        elif mutation == "out_of_bounds": changed["records"]["items"][0]["locator"]["rect"][0] = -.1
        elif mutation == "unknown_unit": changed["records"]["items"][0]["locator"]["unit"] = 2
        elif mutation == "hash": changed["records"]["document"]["sha256"] = "not_an_original_hash"
        elif mutation == "dimension": changed["records"]["document"]["units"][0]["pixel_width"] = True
        with pytest.raises(ValueError):
            validate_association_manifest(manifest(changed))
