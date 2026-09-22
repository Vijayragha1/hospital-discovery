"""Independent synthetic geometry; no claim of hospital OCR/PHI accuracy."""
from collections import Counter
from copy import deepcopy
import random

import pytest

from app.document_layout import POLICY, segment_words


def line(text, x=.08, y=.1, block=1, row=1, height=.02):
    result = []
    for token in text.split():
        width = max(.009, len(token) * .005)
        result.append({"text": token, "left": x, "top": y, "right": x + width,
                       "bottom": y + height, "block": block, "line": row})
        x += width + .008
    return result


def form(identifier, diagnosis, x=.08, y=.1, block=1):
    return line("MRN: " + identifier, x, y, block, 1) + line(
        "Diagnosis: " + diagnosis, x, y + .035, block + 1, 2)


def candidates(result):
    return [region for region in result["regions"] if region["association_candidate"]]


def assert_partition(words, result):
    assert result["policy"] == POLICY
    assigned = [index for region in result["regions"] for index in region["word_indices"]]
    assert Counter(assigned) == Counter(range(len(words)))
    for region in result["regions"]:
        assert region["kind"] == ("record" if region["association_candidate"] else "residual")
        assert [span["index"] for span in region["word_spans"]] == region["word_indices"]
        for span in region["word_spans"]:
            assert region["text"][span["start"]:span["end"]] == words[span["index"]]["text"]
        assert region["text"].split() == [words[index]["text"] for index in region["word_indices"]]
    assert result["word_count"] == len(words)


def test_compact_form_crosses_ocr_paragraph_blocks_but_preserves_lines():
    words = form("SYN100", "diabetes")
    result = segment_words(words)
    assert [r["text"] for r in candidates(result)] == ["MRN: SYN100\nDiagnosis: diabetes"]
    assert result["residual_regions"] == 0
    assert_partition(words, result)


def test_vertically_stacked_forms_and_repeated_identifier_remain_distinct():
    words = form("SYN100", "diabetes") + form("SYN100", "hypertension", y=.22, block=3)
    result = segment_words(words)
    assert len(candidates(result)) == 2
    assert all(not ("diabetes" in r["text"] and "hypertension" in r["text"]) for r in result["regions"])
    assert_partition(words, result)


def test_stable_gutter_two_columns_with_independent_patient_forms():
    words = form("LEFT100", "diabetes") + form("RIGHT200", "hypertension", x=.60, block=4)
    result = segment_words(words)
    assert result["lane_count"] == 2 and len(candidates(result)) == 2
    assert {r["text"] for r in candidates(result)} == {
        "MRN: LEFT100\nDiagnosis: diabetes", "MRN: RIGHT200\nDiagnosis: hypertension"}
    assert_partition(words, result)


def test_unlabelled_neighbouring_column_never_borrows_identifier():
    words = form("LEFT100", "diabetes") + line("Record B", x=.60, block=4) + line(
        "Diagnosis: hypertension", x=.60, y=.135, block=5)
    result = segment_words(words)
    assert len(candidates(result)) == 1
    assert "hypertension" not in candidates(result)[0]["text"]
    assert any("hypertension" in r["text"] and not r["association_candidate"] for r in result["regions"])
    assert_partition(words, result)


def test_single_horizontal_gap_cannot_make_a_patient_record():
    words = line("MRN: LEFT100") + line("Diagnosis: diabetes", x=.6)
    result = segment_words(words)
    assert not candidates(result)
    assert {r["reason"] for r in result["regions"]} == {"unresolved_horizontal_layout"}
    assert_partition(words, result)


def test_clinical_text_beside_but_below_identifier_is_not_nearest_anchor_linked():
    words = line("MRN: LEFT100") + line("Diagnosis: diabetes", x=.6, y=.135)
    result = segment_words(words)
    assert all("diabetes" not in r["text"] for r in candidates(result))
    assert_partition(words, result)


@pytest.mark.parametrize("value", ["", "???", "Unreadable", "Unknown"])
def test_new_unreadable_patient_name_header_ends_prior_record(value):
    words = line("MRN: OLD100") + line("Patient Name = " + value, y=.135, row=2) + line(
        "Diagnosis: diabetes", y=.17, row=3)
    result = segment_words(words)
    assert all("diabetes" not in r["text"] for r in candidates(result))
    assert any(r["reason"] == "unreadable_patient_header" and "diabetes" in r["text"] for r in result["regions"])
    assert_partition(words, result)


def test_new_readable_name_also_ends_prior_identifier_region():
    words = line("MRN: OLD100") + line("Patient Name = Demo Other", y=.135) + line(
        "Diagnosis: diabetes", y=.17)
    result = segment_words(words)
    assert len(candidates(result)) == 2
    assert all(not ("OLD100" in r["text"] and "diabetes" in r["text"]) for r in result["regions"])
    assert_partition(words, result)


def test_adjacent_distinct_demographic_fields_remain_detector_ambiguity_responsibility():
    from app.detection import Detector
    words = line("Patient Name: Demo Alpha") + line("MRN: SYN100", y=.135) + line(
        "UHID: OTHER200", y=.17) + line("Diagnosis: diabetes", y=.205)
    result = segment_words(words)
    assert len(candidates(result)) == 1
    # The document entry point inspects the complete candidate record, so text
    # segmentation cannot hide a conflicting demographic identifier.
    findings = Detector("rules").analyze_layout_region(candidates(result)[0]["text"],
        prefix="frame:1/channel:ocr/region:1", association_candidate=True)
    clinical = [finding for finding in findings if finding["entity_type"] == "HEALTH_INFORMATION"]
    assert clinical and all(finding["classification"] == "clinical_content" for finding in clinical)
    assert_partition(words, result)


@pytest.mark.parametrize("header", ["Doctor MRN: DOC100", "Relative MRN: REL100", "The patient MRN: SYN100", "Mother ABHA: 12345678901234"])
def test_role_and_narrative_identifiers_are_not_patient_fields(header):
    words = line(header) + line("Diagnosis: diabetes", y=.135)
    result = segment_words(words)
    assert not candidates(result)
    assert_partition(words, result)


def test_narrative_reference_inside_form_ends_propagation():
    words = line("MRN: SYN100") + line("Relative MRN: REL200", y=.135) + line(
        "Diagnosis: diabetes", y=.17)
    result = segment_words(words)
    assert all("diabetes" not in r["text"] for r in candidates(result))
    assert_partition(words, result)


def test_bare_abha_address_is_pii_not_an_automatic_patient_header():
    words = line("example@abdm") + line("Diagnosis: diabetes", y=.135)
    result = segment_words(words)
    assert not candidates(result)
    assert_partition(words, result)


def test_explicit_abha_address_field_can_start_a_record():
    words = line("ABHA Address: example@abdm") + line("Diagnosis: diabetes", y=.135)
    result = segment_words(words)
    assert len(candidates(result)) == 1
    assert_partition(words, result)


def test_unsplit_later_patient_name_header_cannot_reuse_earlier_mrn():
    words = line("MRN: OLD100 Patient Name: Demo Other") + line("Diagnosis: diabetes", y=.135)
    result = segment_words(words)
    assert not candidates(result)
    assert any(r["reason"] == "unresolved_patient_headers" for r in result["regions"])
    assert_partition(words, result)


def test_unlabelled_new_record_header_stops_previous_identity():
    words = line("MRN: OLD100") + line("Record B", y=.135) + line("Diagnosis: diabetes", y=.17)
    result = segment_words(words)
    assert all("diabetes" not in r["text"] for r in candidates(result))
    assert_partition(words, result)


def test_research_section_and_remote_footer_are_not_inherited():
    words = form("SYN100", "diabetes") + line("Research about hypertension", y=.17) + line(
        "Medication study", y=.205) + line("Diagnosis: carcinoma", y=.8)
    result = segment_words(words)
    assert [r["text"] for r in candidates(result)] == ["MRN: SYN100\nDiagnosis: diabetes"]
    assert_partition(words, result)


def test_headered_table_and_missing_row_id_are_explicitly_residual():
    words = line("MRN") + line("Diagnosis", x=.6) + line("SYN100", y=.135) + line(
        "diabetes", x=.6, y=.135) + line("hypertension", x=.6, y=.17)
    result = segment_words(words)
    assert not candidates(result) and result["table_layout_detected"]
    assert {r["reason"] for r in result["regions"]} == {"unverified_table_layout"}
    assert_partition(words, result)


def test_crossing_gutter_text_makes_layout_residual():
    words = form("LEFT100", "diabetes") + form("RIGHT200", "hypertension", x=.60, block=4)
    crossing = line("CROSSING", x=.3, y=.119)
    crossing[0]["right"] = .7
    words += crossing
    result = segment_words(words)
    assert not candidates(result)
    assert {r["reason"] for r in result["regions"]} <= {"crossing_column_gutter", "overlapping_words"}
    assert_partition(words, result)


def test_overlapping_words_are_never_promoted_and_not_deduplicated():
    words = form("SYN100", "diabetes")
    words.append(deepcopy(words[1]))
    result = segment_words(words)
    assert not candidates(result) and result["overlapping_words"] == 2
    assert_partition(words, result)


def test_repeat_values_in_distinct_positions_survive_and_evidence_stays_in_own_record():
    from app.detection import Detector
    words = form("LEFT100", "diabetes") + form("RIGHT200", "diabetes", x=.60, block=4)
    result = segment_words(words)
    for index, region in enumerate(candidates(result), 1):
        findings = Detector("rules").analyze_layout_region(region["text"], capture_evidence=True,
            prefix=f"frame:1/channel:ocr/region:{index}", association_candidate=True)
        assert any(f["classification"] == "patient_linked_health" for f in findings)
        assert all(not ("LEFT100" in example["excerpt"] and "RIGHT200" in example["excerpt"])
                   for finding in findings for example in finding["evidence"])
    assert sum(r["text"].count("diabetes") for r in result["regions"]) == 2
    assert_partition(words, result)


@pytest.mark.parametrize("scale,dx,dy", [(1, 0, 0), (.6, .15, .2), (.3, .45, .5)])
def test_translation_scale_and_input_order_do_not_change_record_partition(scale, dx, dy):
    words = form("LEFT100", "diabetes") + form("RIGHT200", "hypertension", x=.60, block=4)
    expected = {r["text"] for r in candidates(segment_words(words))}
    for word in words:
        for key in ("left", "right"):
            word[key] = dx + word[key] * scale
        for key in ("top", "bottom"):
            word[key] = dy + word[key] * scale
    for seed in range(10):
        shuffled = deepcopy(words)
        random.Random(seed).shuffle(shuffled)
        result = segment_words(shuffled)
        assert {r["text"] for r in candidates(result)} == expected
        assert_partition(shuffled, result)


def test_empty_channel_is_valid_and_has_no_regions():
    result = segment_words([])
    assert result["regions"] == [] and result["word_count"] == 0
    assert result["candidate_regions"] == result["residual_regions"] == 0


@pytest.mark.parametrize("change", [
    {"left": float("nan")}, {"right": 1.1}, {"top": True}, {"bottom": .01},
    {"line": 0}, {"block": True}, {"text": "PRIVATE VALUE"},
])
def test_invalid_input_has_only_fixed_errors(change):
    word = {**line("PRIVATE")[0], **change}
    with pytest.raises(ValueError) as caught:
        segment_words([word])
    assert "PRIVATE" not in str(caught.value) and str(caught.value).startswith("document_layout_")


def test_word_and_work_limits_are_bounded_and_fail_closed(monkeypatch):
    import app.document_layout as layout
    with pytest.raises(ValueError, match="document_layout_word_limit"):
        segment_words(line("WORD") * 10001)
    words = form("SYN100", "diabetes")
    monkeypatch.setattr(layout, "MAX_GRID_ENTRIES", 1)
    result = segment_words(words)
    assert result["limit_reached"] and not candidates(result)
    assert {r["reason"] for r in result["regions"]} == {"layout_limit"}
    assert_partition(words, result)


def layout_findings(words):
    """Exercise final classification, rather than only the candidate flag."""
    from app.detection import Detector
    result = segment_words(words)
    assert_partition(words, result)
    detector = Detector("rules")
    findings = []
    for index, region in enumerate(result["regions"], 1):
        findings.extend(detector.analyze_layout_region(region["text"],
            prefix=f"frame:1/channel:ocr/region:{index}",
            association_candidate=region["association_candidate"], capture_evidence=True))
    return result, findings


def assert_clinical_retained_without_link(words):
    result, findings = layout_findings(words)
    clinical = [finding for finding in findings if finding["entity_type"] == "HEALTH_INFORMATION"]
    assert clinical, "Residual clinical observations must not disappear."
    assert all(finding["classification"] == "clinical_content" for finding in clinical)
    return result, findings


@pytest.mark.parametrize("right_column", [.18, .20, .22])
def test_adversarial_narrow_neighbour_column_does_not_borrow_left_patient(right_column):
    # A separate Record B heading sits beside the first record's ID; its clinical
    # line is below that heading. Narrow gutters cannot turn it into Record A.
    words = line("MRN: LEFT100") + line("Record B", x=right_column, block=2) + line(
        "Diagnosis: diabetes", x=right_column, y=.135, block=3)
    assert_clinical_retained_without_link(words)


@pytest.mark.parametrize("uncertain_header", ["Patient Narne: ???", "Patient N ame: ???"])
def test_adversarial_uncertain_patient_field_ends_prior_identity(uncertain_header):
    # Recognition may fail on the field label itself, not only on its value.
    words = line("MRN: OLD100") + line(uncertain_header, y=.135) + line("Diagnosis: diabetes", y=.17)
    _, findings = assert_clinical_retained_without_link(words)
    assert any(f["entity_type"] == "MRN" for f in findings)


@pytest.mark.parametrize("role_reference", [
    "UHID: OLD100 (previous patient)", "MRN: DOC100 (doctor)", "MRN: REL100 (mother)",
])
def test_adversarial_postposed_role_disqualifies_patient_identity(role_reference):
    words = line(role_reference) + line("Diagnosis: diabetes", y=.135)
    _, findings = assert_clinical_retained_without_link(words)
    assert any(f["entity_type"] in {"MRN", "UHID"} for f in findings)


@pytest.mark.parametrize("narrative", ["Previous UHID: OLD100", "Doctor MRN: DOC100", "Relative MRN: REL100"])
def test_adversarial_narrative_reference_after_real_patient_does_not_propagate(narrative):
    words = line("MRN: CURRENT200") + line(narrative, y=.135) + line("Diagnosis: diabetes", y=.17)
    assert_clinical_retained_without_link(words)


@pytest.mark.parametrize("missing_header", ["MRN:", "LEFT100", "???"])
def test_adversarial_partial_ocr_without_complete_patient_field_remains_residual(missing_header):
    words = line(missing_header) + line("Diagnosis: diabetes", y=.135)
    assert_clinical_retained_without_link(words)


@pytest.mark.parametrize("right_column", [.40, .60, .80])
def test_adversarial_small_geometry_jitter_and_wide_gutters_keep_useful_positives(right_column):
    words = form("LEFT100", "diabetes", x=.02) + form("RIGHT200", "hypertension", x=right_column, block=5)
    for seed in range(5):
        altered = deepcopy(words)
        rng = random.Random(seed)
        for word in altered:
            jitter = rng.uniform(-.001, .001)
            word["top"] += jitter
            word["bottom"] += jitter
        rng.shuffle(altered)
        result, findings = layout_findings(altered)
        clinical = [f for f in findings if f["entity_type"] == "HEALTH_INFORMATION"]
        assert len(clinical) == 2 and all(f["classification"] == "patient_linked_health" for f in clinical)
        assert len(candidates(result)) == 2
        assert all(not ("LEFT100" in e["excerpt"] and "RIGHT200" in e["excerpt"])
                   for f in findings for e in f["evidence"])


def test_adversarial_three_row_table_missing_middle_identity_retains_every_row_unlinked():
    words = line("Patient ID") + line("Diagnosis", x=.6)
    words += line("ROW100", y=.135) + line("diabetes", x=.6, y=.135)
    words += line("hypertension", x=.6, y=.17)
    words += line("ROW300", y=.205) + line("carcinoma", x=.6, y=.205)
    result, findings = assert_clinical_retained_without_link(words)
    assert not candidates(result)
    retained = " ".join(region["text"] for region in result["regions"])
    assert all(token in retained for token in ("ROW100", "ROW300", "diabetes", "hypertension", "carcinoma"))


def test_adversarial_later_channel_without_header_cannot_inherit_prior_patient():
    layout_findings(form("PRIOR100", "hypertension"))
    assert_clinical_retained_without_link(line("Diagnosis: diabetes"))


def test_adversarial_name_header_cannot_widen_into_neighbouring_record():
    import re
    from types import SimpleNamespace
    from app.detection import Detector
    words = line("Patient Name: Demo Alpha") + line("Record B", x=.25, block=2) + line(
        "Diagnosis: diabetes", x=.25, y=.135, block=3)
    result = segment_words(words)
    assert_partition(words, result)
    detector = Detector("rules")
    # This is a boundary test, not a name-model accuracy test: provide only the
    # actual first record's known name span to isolate the association decision.
    detector._analyzer = SimpleNamespace(analyze=lambda **kwargs: [
        SimpleNamespace(entity_type="PERSON", start=match.start(), end=match.end(), score=.99)
        for match in re.finditer(r"Demo Alpha", kwargs["text"])])
    clinical = []
    for index, region in enumerate(result["regions"], 1):
        rows = detector.analyze_layout_region(region["text"],
            prefix=f"frame:1/channel:ocr/region:{index}", association_candidate=region["association_candidate"])
        clinical.extend(finding for finding in rows if finding["entity_type"] == "HEALTH_INFORMATION")
    assert clinical and all(finding["classification"] == "clinical_content" for finding in clinical)
