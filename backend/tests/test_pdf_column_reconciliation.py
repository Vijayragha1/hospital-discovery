"""Independent same-page observation matching under different line groupings.

These fixtures prescribe source token positions and expected multiplicity. They
do not derive expected matches from reconciliation or claim hospital accuracy.
"""
from collections import Counter
from copy import deepcopy
import json

import pytest

from app.document_channels import canonical_document_channels
from app.extraction import ExtractionResult
from app.ocr_accounting import document_units_from_report, validate_report
from app.pdf_reconciliation import reconcile_page


def positioned(text, x, y, *, block=1, line=1):
    words = []
    for token in text.split():
        width = len(token) * .006
        words.append(dict(text=token, left=x, top=y, right=x + width, bottom=y + .022,
                          block=block, line=line))
        x += width + .010
    return words


def tokens(words):
    return [word["text"] for word in words]


def page(native, ocr):
    return {"native_words": deepcopy(native), "ocr_words": deepcopy(ocr),
            "native_text": " ".join(tokens(native)), "text": " ".join(tokens(ocr)),
            "native_status": "completed", "ocr_status": "completed", "render_status": "completed",
            "native_text_truncated": False, "truncated": False,
            "geometry_verified": True, "geometry_reason": "verified",
            "pixel_width": 1000, "pixel_height": 1000}


def columns(left=("MRN: LEFT100",), right=("MRN: RIGHT200",)):
    assert len(left) == len(right)
    left_rows = [positioned(text, .08, .10 + row * .08, block=1, line=row + 1)
                 for row, text in enumerate(left)]
    right_rows = [positioned(text, .60, .10 + row * .08, block=2, line=row + 1)
                  for row, text in enumerate(right)]
    # Native reading order follows columns; OCR reading order follows rows.
    native = [word for row in left_rows + right_rows for word in row]
    ocr = []
    for index, (first, second) in enumerate(zip(left_rows, right_rows), 1):
        for word in deepcopy(first + second):
            word.update(block=9, line=index)
            ocr.append(word)
    return native, ocr


def extraction(unit):
    payload = {"protocol": "parser-accounting/v1", "kind": "pdf", "original_format": "PDF",
               "original_unit_count": 1, "units_omitted": 0, "page_accounting_complete": True,
               "limited": False, "reason_codes": [], "legibility_verified": False,
               "nonvisual_content_present": None,
               "text_characters": len(unit["native_text"]) + len(unit["text"]),
               "units": [{"ordinal": 1, **deepcopy(unit)}]}
    text, metadata = validate_report(payload, "pdf", 1_000_000)
    return ExtractionResult(text=text, status="partial", metadata=metadata,
                            document_units=document_units_from_report(payload, "pdf", 1_000_000))


def channels(unit):
    extracted = extraction(unit)
    result = canonical_document_channels(extracted)
    assert not result.fallback
    observed = []
    previous_end = 0
    for channel in result.channels:
        assert channel["start"] >= previous_end
        assert extracted.text[channel["start"]:channel["end"]] == channel["text"]
        assert channel["text"].split() == tokens(channel["words"])
        previous_end = channel["end"]
        observed.extend(channel["text"].split())
    observed.extend(result.residual_text.split())
    assert observed == extracted.text.split()
    return result


def assert_component_retained(native, ocr):
    original = page(native, ocr)
    text, summary = reconcile_page(original)
    assert not summary["reconciled"]
    assert Counter(text.split()) == Counter(tokens(native) + tokens(ocr))
    result = channels(original)
    assert all(not channel["coordinate_eligible"] for channel in result.channels)
    assert Counter(token for channel in result.channels for token in channel["text"].split()) == Counter(text.split())


def test_two_native_columns_grouped_into_one_ocr_line_are_one_observation_each():
    native, ocr = columns()
    original = page(native, ocr)
    before = deepcopy(original)
    text, summary = reconcile_page(original)
    assert summary["reconciled"]
    assert text.split() == tokens(native)
    assert Counter(text.split()) == {"MRN:": 2, "LEFT100": 1, "RIGHT200": 1}
    result = channels(original)
    assert [channel["channel"] for channel in result.channels] == ["native"]
    assert result.channels[0]["coordinate_eligible"]
    assert tokens(result.channels[0]["words"]) == tokens(native)
    assert original == before


def test_column_major_native_and_row_major_ocr_preserve_all_four_native_lines():
    native, ocr = columns(("MRN: LEFT100", "Diagnosis: diabetes"),
                          ("MRN: RIGHT200", "Diagnosis: hypertension"))
    text, summary = reconcile_page(page(native, ocr))
    assert summary["reconciled"] and text.split() == tokens(native)
    result = channels(page(native, ocr))
    assert len(result.channels) == 1 and result.channels[0]["coordinate_eligible"]
    assert {(word["block"], word["line"]) for word in result.channels[0]["words"]} == {
        (1, 1), (1, 2), (2, 1), (2, 2)}


def test_inverse_grouping_one_native_line_two_ocr_lines_is_also_lossless():
    separate, merged = columns()
    text, summary = reconcile_page(page(merged, separate))
    assert summary["reconciled"] and text.split() == tokens(merged)
    result = channels(page(merged, separate))
    assert len(result.channels) == 1 and result.channels[0]["channel"] == "native"


def test_equal_values_in_distinct_columns_are_not_globally_deduplicated():
    native, ocr = columns(("MRN: SAME100",), ("MRN: SAME100",))
    text, summary = reconcile_page(page(native, ocr))
    assert summary["reconciled"]
    assert text.split().count("SAME100") == 2
    result = channels(page(native, ocr))
    occurrences = [w for w in result.channels[0]["words"] if w["text"] == "SAME100"]
    assert len(occurrences) == 2 and occurrences[0]["left"] != occurrences[1]["left"]


def test_identical_repeated_tokens_inside_one_native_line_keep_multiplicity():
    native, ocr = columns(("SAME SAME SAME",), ("OTHER OTHER",))
    text, summary = reconcile_page(page(native, ocr))
    assert summary["reconciled"]
    assert Counter(text.split()) == {"SAME": 3, "OTHER": 2}
    result = channels(page(native, ocr))
    assert len(result.channels[0]["words"]) == 5


def test_unrelated_same_value_at_another_position_survives_as_ocr_observation():
    native, ocr = columns()
    ocr += positioned("MRN: LEFT100", .08, .60, block=10, line=1)
    text, summary = reconcile_page(page(native, ocr))
    assert summary["reconciled"]
    assert text.split().count("LEFT100") == 2 and text.split().count("RIGHT200") == 1
    result = channels(page(native, ocr))
    assert [c["channel"] for c in result.channels] == ["native", "ocr"]
    assert all(c["coordinate_eligible"] for c in result.channels)


def test_same_tokens_at_wrong_positions_are_not_equivalent_observations():
    native, ocr = columns(("MRN: LEFT100",), ("MRN: RIGHT200",))
    # Swap only the values, keeping the respective boxes and channel words/text
    # internally consistent. A global token multiset cannot prove correspondence.
    ocr[1]["text"], ocr[3]["text"] = ocr[3]["text"], ocr[1]["text"]
    assert_component_retained(native, ocr)


@pytest.mark.parametrize("missing", ["native", "ocr"])
def test_missing_word_inside_the_overlapping_component_prevents_suppression(missing):
    native, ocr = columns(("MRN: LEFT100 NOTE",), ("MRN: RIGHT200",))
    if missing == "native":
        del native[2]
    else:
        del ocr[2]
    assert_component_retained(native, ocr)


def test_ocr_only_column_in_same_merged_line_is_retained_with_the_overlap():
    native, ocr = columns()
    native = native[:2]
    assert_component_retained(native, ocr)


def test_one_changed_token_preserves_every_line_in_its_overlap_component():
    native, ocr = columns()
    ocr[-1]["text"] = "WRONG300"
    assert_component_retained(native, ocr)


@pytest.mark.parametrize("duplicated", ["native", "ocr"])
def test_duplicate_overprint_geometry_cannot_be_matched_one_to_many(duplicated):
    native, ocr = columns()
    extra = deepcopy((native if duplicated == "native" else ocr)[:2])
    for word in extra:
        word.update(block=20, line=1)
    if duplicated == "native":
        native += extra
    else:
        ocr += extra
    assert_component_retained(native, ocr)


def test_competing_different_text_blocks_suppression_of_equal_component_words():
    native, ocr = columns()
    conflict = deepcopy(ocr[:2])
    conflict[-1]["text"] = "OTHER900"
    for word in conflict:
        word.update(block=20, line=1)
    ocr += conflict
    assert_component_retained(native, ocr)


@pytest.mark.parametrize("split", ["native", "ocr"])
def test_token_merge_split_is_not_repaired_by_concatenation(split):
    whole = positioned("ABCD", .08, .10)
    pieces = [dict(text="AB", left=.08, right=.092, top=.10, bottom=.122, block=1, line=1),
              dict(text="CD", left=.092, right=.104, top=.10, bottom=.122, block=1, line=1)]
    native, ocr = (pieces, whole) if split == "native" else (whole, pieces)
    assert_component_retained(native, ocr)


def test_tiny_same_text_token_in_a_huge_box_does_not_prove_observation_identity():
    native, ocr = columns()
    native[1].update(left=.10, right=.55, top=.08, bottom=.14)
    assert_component_retained(native, ocr)


def test_suppressed_merged_ocr_line_is_a_hard_barrier_between_surviving_fragments():
    native, duplicate = columns(("LEFT_SEPARATOR",), ("RIGHT_SEPARATOR",))
    for word in native + duplicate:
        word["top"] += .20
        word["bottom"] += .20
    before = positioned("MRN: ORPHAN100", .08, .10, block=9, line=1)
    for word in duplicate:
        word.update(block=9, line=2)
    after = positioned("Diagnosis: diabetes", .08, .50, block=9, line=3)
    original = page(native, before + duplicate + after)
    text, summary = reconcile_page(original)
    assert summary["reconciled"]
    assert Counter(text.split()) == Counter(tokens(native + before + after))
    result = channels(original)
    assert [c["channel"] for c in result.channels] == ["native", "ocr", "ocr-2"]
    assert result.channels[1]["text"] == "MRN: ORPHAN100"
    assert result.channels[2]["text"] == "Diagnosis: diabetes"
    assert all(not ("ORPHAN100" in c["text"] and "diabetes" in c["text"]) for c in result.channels)


def test_several_fully_matched_ocr_rows_do_not_create_empty_residual_channels():
    native, ocr = columns(("LEFT_FIRST", "LEFT_SECOND"), ("RIGHT_FIRST", "RIGHT_SECOND"))
    ocr += positioned("UNMATCHED", .08, .60, block=10, line=1)
    result = channels(page(native, ocr))
    assert [c["channel"] for c in result.channels] == ["native", "ocr"]
    assert result.channels[1]["text"] == "UNMATCHED"
    assert all(c["text"] for c in result.channels)


@pytest.mark.parametrize("change", [
    {"geometry_verified": False}, {"native_status": "limited"}, {"ocr_status": "limited"},
    {"render_status": "failed"}, {"native_text_truncated": True}, {"truncated": True},
])
def test_unknown_geometry_or_partial_processing_cannot_claim_reconciliation(change):
    native, ocr = columns()
    original = {**page(native, ocr), **change}
    text, summary = reconcile_page(original)
    assert not summary["reconciled"]
    assert {"LEFT100", "RIGHT200"} <= set(text.split())


def test_small_measured_box_jitter_keeps_exact_token_correspondence():
    native, ocr = columns()
    for word in ocr:
        for key in ("left", "right", "top", "bottom"):
            word[key] += .001
    text, summary = reconcile_page(page(native, ocr))
    assert summary["reconciled"] and text.split() == tokens(native)


def test_nfc_equivalent_spellings_can_match_without_changing_retained_native_text():
    native, ocr = columns(("Patient: José",), ("MRN: RIGHT200",))
    ocr[1]["text"] = "Jose\u0301"
    text, summary = reconcile_page(page(native, ocr))
    assert summary["reconciled"] and "José" in text and "Jose\u0301" not in text


def test_summary_contains_no_source_values_words_or_coordinates():
    native, ocr = columns()
    _, summary = reconcile_page(page(native, ocr))
    serialized = json.dumps(summary)
    assert "LEFT100" not in serialized and "RIGHT200" not in serialized
    assert all(not isinstance(value, (list, dict)) for value in summary.values())
