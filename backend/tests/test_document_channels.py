"""Conservation and hard barriers for transient automatic-layout inputs."""
import copy
import json

import pytest

from app.document_channels import canonical_document_channels
from app.extraction import ExtractionResult, _bounded, extract_bytes
from app.ocr_accounting import document_units_from_report, validate_report
from test_document_units import geometry_report
from test_ocr_accounting import install_endpoint, report
from test_pdf_reconciliation import words


def extracted_from_report(payload):
    kind = payload['kind']
    text, metadata = validate_report(payload, kind, 1_000_000)
    metadata['patient_linkage_context_verified'] = False
    return ExtractionResult(text=text, metadata=metadata,
                            document_units=document_units_from_report(payload, kind, 1_000_000))


def pdf(native, ocr=None):
    if ocr is None:
        ocr = copy.deepcopy(native)
    native_text = ' '.join(word['text'] for word in native)
    ocr_text = ' '.join(word['text'] for word in ocr)
    payload = report('pdf', (ocr_text,))
    payload['units'][0].update(native_text=native_text, native_words=native, native_status='completed',
        native_text_truncated=False, ocr_words=ocr, geometry_verified=True, geometry_reason='verified',
        pixel_width=1000, pixel_height=800)
    payload['text_characters'] = len(native_text) + len(ocr_text)
    return extracted_from_report(payload)


def assert_conserved(extracted, result):
    if result.fallback:
        assert not result.channels and result.residual_text == extracted.text
        return
    spans = [(channel['start'], channel['end']) for channel in result.channels]
    assert spans == sorted(spans)
    for channel in result.channels:
        assert extracted.text[channel['start']:channel['end']] == channel['text']
        if channel['coordinate_eligible']:
            assert channel['text'].split() == [word['text'] for word in channel['words']]
    reconstructed_tokens = [token for channel in result.channels for token in channel['text'].split()]
    reconstructed_tokens.extend(result.residual_text.split())
    assert reconstructed_tokens == extracted.text.split()


def test_raster_keeps_literal_whitespace_all_blocks_and_original_frames():
    payload = geometry_report(texts=('MRN: SECRET100 diabetes', 'MRN: SECRET100 diabetes'))
    for item in payload['units']:
        item['text'] = '  MRN:\tSECRET100\fdiabetes\n'
        item['ocr_words'][-1].update(block=2, line=1, top=.6, bottom=.65)
    payload['text_characters'] = sum(len(item['text']) for item in payload['units'])
    extracted = extracted_from_report(payload)
    result = canonical_document_channels(extracted)
    assert not result.fallback and result.residual_text == ''
    assert [(c['kind'], c['ordinal'], c['channel']) for c in result.channels] == [
        ('image', 1, 'ocr'), ('image', 2, 'ocr')]
    assert result.channels[0]['text'] == '  MRN:\tSECRET100\ndiabetes\n'
    assert [word['block'] for word in result.channels[0]['words']] == [1, 1, 2]
    assert all(c['coordinate_eligible'] for c in result.channels)
    assert_conserved(extracted, result)


def test_pdf_equal_native_ocr_lines_have_one_canonical_observation():
    extracted = pdf(words('MRN: SECRET100 diabetes'))
    result = canonical_document_channels(extracted)
    assert [c['channel'] for c in result.channels] == ['native']
    assert result.channels[0]['text'].count('SECRET100') == 1
    assert result.channels[0]['coordinate_eligible']
    assert_conserved(extracted, result)


def test_repeated_values_at_different_positions_and_on_other_pages_survive():
    native = words('MRN: SECRET100', .1) + words('MRN: SECRET100', .5, block=2)
    extracted = pdf(native)
    first = copy.deepcopy(extracted.document_units[0])
    second = copy.deepcopy(first)
    second['ordinal'] = 2
    extracted.document_units = [first, second]
    extracted.text += '\f' + extracted.text
    result = canonical_document_channels(extracted)
    assert [c['ordinal'] for c in result.channels] == [1, 2]
    assert all(c['text'].count('SECRET100') == 2 for c in result.channels)
    assert all({w['block'] for w in c['words']} == {1, 2} for c in result.channels)
    assert_conserved(extracted, result)


def test_ocr_only_same_value_remains_separate_from_native_channel():
    native = words('MRN: SECRET100', .1)
    extracted = pdf(native, copy.deepcopy(native) + words('MRN: SECRET100', .6, block=2))
    result = canonical_document_channels(extracted)
    assert [c['channel'] for c in result.channels] == ['native', 'ocr']
    assert all(c['coordinate_eligible'] for c in result.channels)
    assert sum(c['text'].count('SECRET100') for c in result.channels) == 2
    assert_conserved(extracted, result)


def test_ocr_suppression_is_hard_barrier_but_regular_blocks_are_retained():
    native = words('separator', .3)
    ocr = (words('MRN: SECRET100', .1, line=1) + words('separator', .3, line=2)
           + words('diabetes', .5, line=3) + words('phone 1234567890', .7, block=2))
    extracted = pdf(native, ocr)
    result = canonical_document_channels(extracted)
    assert [c['channel'] for c in result.channels] == ['native', 'ocr', 'ocr-2']
    assert result.channels[1]['text'] == 'MRN: SECRET100'
    assert result.channels[2]['text'] == 'diabetes\n\nphone 1234567890'
    assert {w['block'] for w in result.channels[2]['words']} == {1, 2}
    assert result.channels[2]['fragment'] == 2
    assert_conserved(extracted, result)


def test_multiple_consecutive_suppressed_lines_do_not_create_empty_fragments():
    native = words('first', .1) + words('second', .3, line=2) + words('last', .7, line=3)
    ocr = (copy.deepcopy(native[:2]) + words('residual', .5, line=4)
           + copy.deepcopy(native[2:]))
    extracted = pdf(native, ocr)
    result = canonical_document_channels(extracted)
    assert [c['channel'] for c in result.channels] == ['native', 'ocr']
    assert result.channels[1]['text'] == 'residual'
    assert_conserved(extracted, result)


@pytest.mark.parametrize('case', ['different', 'competing'])
def test_conflicting_overlaps_keep_all_channels_but_disable_coordinates(case):
    native = words('MRN: SECRET100', .1)
    if case == 'different':
        ocr = words('MRN: SECRET200', .1)
    else:
        ocr = copy.deepcopy(native) + words('MRN: SECRET200', .105, block=2)
    extracted = pdf(native, ocr)
    result = canonical_document_channels(extracted)
    assert not result.fallback and len(result.channels) == 2
    assert all(not c['coordinate_eligible'] and c['reason'] == 'native_ocr_overlap_unresolved'
               for c in result.channels)
    assert_conserved(extracted, result)


def test_unknown_geometry_keeps_native_and_ocr_text_separate_unverified():
    extracted = pdf(words('MRN: SECRET100'), words('diabetes', .5))
    unit = extracted.document_units[0]
    unit.update(geometry_verified=False, geometry_reason='mapping_unverified',
                coordinate_eligible=False, coordinate_reason='mapping_unverified')
    # Unknown-map reconciliation preserves original source channel whitespace.
    unit['native_text'] = ' MRN:\tSECRET100 '
    unit['text'] = '\ndiabetes\n'
    extracted.text = unit['native_text'] + '\n\n' + unit['text']
    result = canonical_document_channels(extracted)
    assert not result.fallback
    assert [c['channel'] for c in result.channels] == ['native', 'ocr']
    assert all(not c['coordinate_eligible'] and c['words'] == [] for c in result.channels)
    assert_conserved(extracted, result)


def test_spatial_limit_falls_back_to_unverified_native_and_ocr_observations(monkeypatch):
    from app import pdf_reconciliation
    extracted = pdf(words('MRN: SECRET100'))
    monkeypatch.setattr(pdf_reconciliation, 'MAX_GRID_ENTRIES', 0)
    original = extracted.document_units[0]
    extracted.text = original['native_text'] + '\n\n' + original['text']
    result = canonical_document_channels(extracted)
    assert not result.fallback and len(result.channels) == 2
    assert all(not c['coordinate_eligible'] and c['reason'] == 'reconciliation_limit' for c in result.channels)
    assert_conserved(extracted, result)


def test_tika_supplement_is_untouched_unmapped_even_when_values_repeat(monkeypatch):
    monkeypatch.setenv('TIKA_URL', 'http://127.0.0.1:9998')
    install_endpoint(monkeypatch, geometry_report('pdf'), tika_payload=[{
        'X-TIKA:content': '<div class="page"><p>SECRET100 TIKA_ONLY_VALUE</p></div>'}])
    extracted = extract_bytes(b'%PDF-synthetic', '.pdf')
    result = canonical_document_channels(extracted)
    assert not result.fallback and result.reason == 'unmapped_supplement'
    assert 'SECRET100' in result.residual_text and 'TIKA_ONLY_VALUE' in result.residual_text
    assert 'TIKA_ONLY_VALUE' not in json.dumps(result.channels)
    assert all(c['coordinate_eligible'] for c in result.channels)
    assert_conserved(extracted, result)


@pytest.mark.parametrize('where', ['prefix', 'middle', 'missing_separator', 'lost_page'])
def test_alignment_mismatch_returns_whole_actual_text_without_coordinate_guesses(where):
    extracted = pdf(words('MRN: SECRET100'))
    if where == 'prefix':
        extracted.text = 'EXTRA ' + extracted.text
    elif where == 'middle':
        extracted.text = extracted.text.replace('SECRET100', 'SECRET200')
    elif where == 'missing_separator':
        extracted.text += ' TIKA_ONLY'
    else:
        second = copy.deepcopy(extracted.document_units[0])
        second['ordinal'] = 2
        extracted.document_units.append(second)
    result = canonical_document_channels(extracted)
    assert result.fallback and result.reason == 'document_text_alignment_unverified'
    assert_conserved(extracted, result)


@pytest.mark.parametrize('where', ['metadata', 'nested_metadata', 'unit', 'actual_truncation'])
def test_global_truncation_always_uses_whole_actual_text_unverified(where):
    extracted = extracted_from_report(geometry_report())
    if where == 'metadata':
        extracted.metadata['text_truncated'] = True
    elif where == 'nested_metadata':
        extracted.metadata['page_ocr'] = {'text_truncated': True}
    elif where == 'unit':
        extracted.document_units[0].update(coordinate_eligible=False, coordinate_reason='document_text_truncated')
    else:
        _bounded(extracted.text, 8, extracted)
    result = canonical_document_channels(extracted)
    assert result.fallback and result.reason == 'document_text_truncated'
    assert_conserved(extracted, result)


@pytest.mark.parametrize('change', [
    {'ordinal': True}, {'ordinal': 2}, {'kind': 'other'}, {'coordinate_space': 'raw_pixels'},
    {'pixel_width': None}, {'ocr_words': []}, {'coordinate_eligible': 'true'},
    {'coordinate_reason': 'SECRET_REASON'}, {'ocr_status': 'failed'},
])
def test_mutated_or_inconsistent_claims_fail_closed_without_value_diagnostics(change):
    extracted = extracted_from_report(geometry_report())
    extracted.document_units[0].update(change)
    result = canonical_document_channels(extracted)
    assert result.fallback and result.reason == 'document_channels_invalid'
    assert 'SECRET' not in repr(result)
    assert_conserved(extracted, result)


def test_whole_document_geometry_limit_is_checked_again(monkeypatch):
    from app import ocr_accounting
    extracted = extracted_from_report(geometry_report(texts=('MRN: SECRET100', 'MRN: SECRET200')))
    monkeypatch.setattr(ocr_accounting, 'MAX_DOCUMENT_WORDS', 3)
    result = canonical_document_channels(extracted)
    assert result.fallback and result.reason == 'document_channels_invalid'
    assert_conserved(extracted, result)


def test_missing_legacy_geometry_retains_unverified_raster_text():
    extracted = extracted_from_report(report(texts=('MRN: SECRET100 diabetes',)))
    result = canonical_document_channels(extracted)
    assert not result.fallback and result.channels[0]['words'] == []
    assert not result.channels[0]['coordinate_eligible']
    assert_conserved(extracted, result)


def test_incomplete_original_inventory_never_regains_coordinate_eligibility():
    payload = geometry_report()
    payload.update(original_unit_count=2, units_omitted=1, page_accounting_complete=False,
                   limited=True, reason_codes=['page_limit'])
    extracted = extracted_from_report(payload)
    result = canonical_document_channels(extracted)
    assert not result.fallback and not result.channels[0]['coordinate_eligible']
    assert result.channels[0]['reason'] == 'document_inventory_incomplete'
    assert_conserved(extracted, result)


def test_no_document_units_returns_actual_text_as_unverified_residual():
    extracted = ExtractionResult(text='SECRET100 TIKA_ONLY')
    result = canonical_document_channels(extracted)
    assert result.fallback and result.reason == 'document_units_unavailable'
    assert_conserved(extracted, result)


def test_raster_does_not_invent_a_supplement_for_unexpected_extra_text():
    extracted = extracted_from_report(geometry_report())
    extracted.text += '\fUNEXPECTED_TEXT'
    result = canonical_document_channels(extracted)
    assert result.fallback and result.reason == 'document_text_alignment_unverified'
    assert_conserved(extracted, result)


def test_raster_nfc_equivalence_does_not_change_original_character_spans():
    payload = geometry_report(texts=('Patient: Jose\u0301',))
    payload['units'][0]['ocr_words'][1]['text'] = 'Jos\u00e9'
    extracted = extracted_from_report(payload)
    result = canonical_document_channels(extracted)
    assert result.fallback and result.reason == 'document_text_alignment_unverified'
    assert result.residual_text == 'Patient: Jose\u0301'
    assert_conserved(extracted, result)


def test_blank_units_preserve_later_original_ordinal_and_blank_pdf_can_have_supplement():
    extracted = extracted_from_report(geometry_report(texts=('', 'MRN: SECRET100')))
    result = canonical_document_channels(extracted)
    assert [c['ordinal'] for c in result.channels] == [2]
    assert result.channels[0]['start'] == 1
    assert_conserved(extracted, result)
    extracted = pdf([])
    extracted.text = 'UNMAPPED_SUPPLEMENT'
    result = canonical_document_channels(extracted)
    assert not result.fallback and not result.channels
    assert result.residual_text == extracted.text
    assert_conserved(extracted, result)


def test_raw_values_and_coordinates_stay_transient_and_inputs_are_not_mutated():
    extracted = pdf(words('MRN: SECRET100 diabetes'))
    original = copy.deepcopy(extracted)
    result = canonical_document_channels(extracted)
    assert extracted == original
    assert not extracted.metadata['patient_linkage_context_verified']
    assert 'SECRET100' not in repr(result) and 'left' not in repr(result)
    assert 'SECRET100' not in repr(extracted) and 'words' not in repr(extracted)
    assert 'SECRET100' not in json.dumps(extracted.metadata)
    result.channels[0]['words'][0]['text'] = 'changed'
    assert extracted.document_units[0]['native_words'][0]['text'] == 'MRN:'
