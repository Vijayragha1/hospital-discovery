"""Transient geometry is bounded, independent of linkage, and never retained."""
import copy
import json

import pytest

from app import ocr_accounting
from app.detection import Detector
from app.extraction import ExtractionResult, _bounded, extract_bytes
from app.ocr_accounting import document_units_from_report, validate_report
from app.scanning import _file_result
from test_ocr_accounting import install_endpoint, report


def geometry_report(kind='image', texts=('MRN: SECRET100 diabetes',)):
    payload = report(kind, texts)
    for unit in payload['units']:
        tokens = unit['text'].split()
        words = [dict(text=token, left=.05 + i * .2, top=.1, right=.15 + i * .2,
                      bottom=.15, block=1, line=1) for i, token in enumerate(tokens)]
        unit.update(pixel_width=1000, pixel_height=800, ocr_words=words,
                    geometry_verified=True, geometry_reason='verified')
        if kind == 'pdf':
            unit.update(native_status='completed', native_text=unit['text'],
                        native_text_truncated=False, native_words=copy.deepcopy(words))
    if kind == 'pdf':
        payload['text_characters'] *= 2
    return payload


def test_valid_original_units_keep_repeated_values_and_explicit_coordinate_space():
    payload = geometry_report(texts=('MRN: SECRET100', 'MRN: SECRET100'))
    text, metadata = validate_report(payload, 'image', 1000)
    units = document_units_from_report(payload, 'image', 1000)
    assert len((text, metadata)) == 2  # Existing accounting return contract.
    assert [unit['ordinal'] for unit in units] == [1, 2]
    assert all(unit['coordinate_space'] == 'rendered_unit_normalized_v1' for unit in units)
    assert all(unit['coordinate_eligible'] and unit['geometry_verified'] for unit in units)
    assert all((unit['pixel_width'], unit['pixel_height']) == (1000, 800) for unit in units)
    assert all(unit['ocr_words'][1]['text'] == 'SECRET100' for unit in units)
    assert 'SECRET100' not in json.dumps(metadata)
    assert not any(key in json.dumps(metadata) for key in ('ocr_words', 'left', 'right', 'pixel_width'))
    units[0]['ocr_words'][0]['text'] = 'changed'
    assert payload['units'][0]['ocr_words'][0]['text'] == 'MRN:'


def test_legacy_geometry_is_compatible_but_cannot_be_used_for_coordinates():
    payload = report(texts=('MRN: SECRET100',))
    _, metadata = validate_report(payload, 'image', 1000)
    units = document_units_from_report(payload, 'image', 1000)
    assert metadata['page_accounting_complete']
    assert not units[0]['geometry_verified'] and not units[0]['coordinate_eligible']
    assert units[0]['geometry_reason'] == 'geometry_unavailable'
    assert units[0]['ocr_words'] == [] and units[0]['pixel_width'] is None


@pytest.mark.parametrize('change', [
    {'pixel_width': None}, {'pixel_width': True}, {'pixel_width': 0}, {'pixel_height': 1.5},
    {'pixel_width': 10000, 'pixel_height': 10000}, {'geometry_verified': 'true'},
    {'geometry_reason': 'PRIVATE_REASON'}, {'geometry_reason': []},
    {'geometry_verified': False}, {'ocr_words': None},
])
def test_malformed_claimed_geometry_is_rejected(change):
    payload = geometry_report()
    payload['units'][0].update(change)
    with pytest.raises(ValueError):
        validate_report(payload, 'image', 1000)


@pytest.mark.parametrize('change', [
    {'left': float('nan')}, {'bottom': float('inf')}, {'right': 2}, {'left': True},
    {'right': .01}, {'line': True}, {'block': 0}, {'text': 'MRN: diabetes'},
    {'text': 'different'},
])
def test_word_geometry_and_complete_token_inventory_are_checked(change):
    payload = geometry_report()
    payload['units'][0]['ocr_words'][0].update(change)
    with pytest.raises(ValueError):
        document_units_from_report(payload, 'image', 1000)


def test_noncontiguous_line_identity_is_rejected():
    payload = geometry_report()
    payload['units'][0]['ocr_words'][1]['line'] = 2
    with pytest.raises(ValueError, match='noncontiguous_pdf_line'):
        document_units_from_report(payload, 'image', 1000)


def test_verified_geometry_requires_completed_untruncated_channels():
    payload = geometry_report()
    payload['units'][0].update(ocr_status='limited', truncated=True)
    payload.update(page_accounting_complete=False, limited=True, reason_codes=['text_limit'])
    with pytest.raises(ValueError, match='incomplete_document_geometry_channel'):
        validate_report(payload, 'image', 1000)


def test_blank_successful_channel_can_have_verified_empty_geometry():
    units = document_units_from_report(geometry_report(texts=('',)), 'image', 1000)
    assert units[0]['coordinate_eligible'] and units[0]['ocr_words'] == []


def test_explicitly_unverified_mapping_preserves_only_valid_sanitized_words():
    payload = geometry_report()
    payload['units'][0].update(geometry_verified=False, geometry_reason='mapping_unverified')
    payload['units'][0]['ocr_words'][0]['private_extra'] = 'not retained'
    units = document_units_from_report(payload, 'image', 1000)
    assert units[0]['ocr_words'] and not units[0]['coordinate_eligible']
    assert 'private_extra' not in units[0]['ocr_words'][0]
    payload['units'][0]['ocr_words'][0]['left'] = float('nan')
    with pytest.raises(ValueError):
        document_units_from_report(payload, 'image', 1000)


def test_geometry_failure_can_retain_text_without_trusting_missing_words():
    payload = geometry_report()
    payload['units'][0].update(geometry_verified=False, geometry_reason='geometry_invalid', ocr_words=[])
    units = document_units_from_report(payload, 'image', 1000)
    assert units[0]['text'] and not units[0]['coordinate_eligible']


def test_incomplete_whole_inventory_disables_otherwise_valid_unit_coordinates():
    payload = geometry_report()
    payload.update(original_unit_count=2, units_omitted=1, page_accounting_complete=False,
                   limited=True, reason_codes=['page_limit'])
    units = document_units_from_report(payload, 'image', 1000)
    assert units[0]['geometry_verified'] and not units[0]['coordinate_eligible']
    assert units[0]['coordinate_reason'] == 'document_inventory_incomplete'


@pytest.mark.parametrize('kind', ['image', 'pdf'])
def test_word_and_character_caps_cover_the_whole_document_and_both_channels(monkeypatch, kind):
    payload = geometry_report(kind, texts=('MRN: SECRET100', 'MRN: SECRET200'))
    expected_words = 4 * (2 if kind == 'pdf' else 1)
    monkeypatch.setattr(ocr_accounting, 'MAX_DOCUMENT_WORDS', expected_words - 1)
    with pytest.raises(ValueError, match='document_geometry_limit'):
        document_units_from_report(payload, kind, 1000)
    monkeypatch.setattr(ocr_accounting, 'MAX_DOCUMENT_WORDS', 10000)
    expected_chars = sum(len(word['text']) for unit in payload['units'] for word in unit['ocr_words'])
    expected_chars *= 2 if kind == 'pdf' else 1
    monkeypatch.setattr(ocr_accounting, 'MAX_DOCUMENT_WORD_CHARACTERS', expected_chars - 1)
    with pytest.raises(ValueError, match='document_geometry_limit'):
        document_units_from_report(payload, kind, 1000)


def test_extraction_repr_and_scanner_output_never_include_transient_payload(monkeypatch, tmp_path):
    install_endpoint(monkeypatch, geometry_report())
    extracted = extract_bytes(b'synthetic', '.png')
    assert extracted.document_units[0]['coordinate_eligible']
    assert extracted.metadata['patient_linkage_context_verified'] is False
    assert 'SECRET100' not in repr(extracted)
    assert 'ocr_words' not in repr(extracted)
    path = tmp_path / 'fixture.png'
    path.write_bytes(b'synthetic')
    result = _file_result(path.name, path.read_bytes(), path.stat(), path.stat(),
                          {'capture_evidence': False}, Detector('rules'))
    serialized = json.dumps(result)
    assert 'SECRET100' not in serialized and 'ocr_words' not in serialized
    assert 'coordinate_space' not in serialized
    assert any(item['classification'] == 'patient_linked_health' for item in result['findings'])
    assert result['metadata']['document_layout']['candidate_records'] == 1
    assert result['metadata']['document_layout']['patient_association_accuracy_validated'] is False


def test_pdf_supplement_keeps_original_units_without_assigning_its_text_coordinates(monkeypatch):
    monkeypatch.setenv('TIKA_URL', 'http://127.0.0.1:9998')
    install_endpoint(monkeypatch, geometry_report('pdf'), tika_payload=[{
        'X-TIKA:content': '<div class="page"><p>UNMAPPED_SECRET</p></div>'}])
    extracted = extract_bytes(b'%PDF-synthetic', '.pdf')
    assert 'UNMAPPED_SECRET' in extracted.text
    assert extracted.document_units[0]['native_text'] == 'MRN: SECRET100 diabetes'
    assert 'UNMAPPED_SECRET' not in json.dumps(extracted.document_units)
    assert extracted.document_units[0]['coordinate_eligible']
    assert extracted.metadata['patient_linkage_context_verified'] is False
    assert 'SECRET' not in json.dumps(extracted.metadata) and 'SECRET' not in repr(extracted)


def test_global_output_truncation_disables_all_coordinate_eligibility():
    units = document_units_from_report(geometry_report(), 'image', 1000)
    result = _bounded('MRN: SECRET100 diabetes', 5, ExtractionResult(document_units=units))
    assert result.status == 'partial' and result.metadata['text_truncated']
    assert result.document_units[0]['geometry_verified']
    assert not result.document_units[0]['coordinate_eligible']
    assert result.document_units[0]['coordinate_reason'] == 'document_text_truncated'


def test_public_helper_accounts_for_unit_separators_in_output_budget():
    payload = geometry_report(texts=('MRN: SECRET100', 'MRN: SECRET200'))
    units = document_units_from_report(payload, 'image', payload['text_characters'])
    assert all(unit['geometry_verified'] for unit in units)
    assert all(not unit['coordinate_eligible'] and unit['coordinate_reason'] == 'document_text_truncated'
               for unit in units)


def test_pdf_combined_tika_output_limit_disables_original_unit_eligibility(monkeypatch):
    monkeypatch.setenv('TIKA_URL', 'http://127.0.0.1:9998')
    install_endpoint(monkeypatch, geometry_report('pdf'), tika_payload=[{
        'X-TIKA:content': '<div class="page"><p>' + 'Unmapped ' * 30 + '</p></div>'}])
    result = extract_bytes(b'%PDF-synthetic', '.pdf', {'max_text_chars': 60})
    assert result.metadata['text_truncated'] and len(result.text) == 60
    assert result.document_units and not any(unit['coordinate_eligible'] for unit in result.document_units)


def test_invalid_geometry_endpoint_response_does_not_leak_parser_values(monkeypatch):
    payload = geometry_report()
    payload['units'][0]['geometry_reason'] = 'PRIVATE_SECRET100'
    install_endpoint(monkeypatch, payload)
    result = extract_bytes(b'synthetic', '.png')
    assert result.status == 'failed' and result.document_units is None
    assert result.reason == 'page_ocr_unavailable_or_invalid_response'
    assert 'SECRET100' not in repr(result)
