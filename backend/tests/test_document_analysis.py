"""Original-unit pipeline safety: conservation, association and evidence scope."""
import copy
import json
from collections import Counter
from types import SimpleNamespace

import pytest

from app.detection import Detector
from app.document_analysis import analyze_document
from app.extraction import ExtractionResult
from test_document_channels import extracted_from_report, pdf
from test_document_layout import form, line
from test_ocr_accounting import report


def raster(*frames):
    payload = report('image', tuple(' '.join(word['text'] for word in frame) for frame in frames))
    for unit, frame in zip(payload['units'], frames):
        unit.update(ocr_words=copy.deepcopy(frame), pixel_width=1000, pixel_height=800,
                    geometry_verified=True, geometry_reason='verified')
    return extracted_from_report(payload)


def analyze(extracted, *, evidence=False):
    observations, events = [], []
    detector = Detector('rules', _observation_sink=observations.append, _association_sink=events.append)
    findings = analyze_document('synthetic/source.png', b'synthetic-original-bytes', '.PNG', extracted,
                                {'capture_evidence': evidence}, detector)
    assert detector._layout_scope is None
    assert detector._observation_scope is None
    assert detector._association_scope is None
    return findings, observations, events


def clinical(findings):
    return [finding for finding in findings if finding['entity_type'] == 'HEALTH_INFORMATION']


def entity_counts(findings):
    counts = Counter()
    for finding in findings:
        counts[finding['entity_type']] += finding['match_count']
    return counts


def assert_unlinked(findings):
    assert clinical(findings)
    assert all(finding['classification'] == 'clinical_content' for finding in clinical(findings))


def test_two_columns_observers_evidence_and_public_findings_share_exact_region_prefixes():
    extracted = raster(form('LEFT100', 'diabetes') + form('RIGHT200', 'hypertension', x=.60, block=4))
    findings, observations, events = analyze(extracted, evidence=True)
    assert len(clinical(findings)) == 2
    assert all(finding['classification'] == 'patient_linked_health' for finding in clinical(findings))
    source_event, *clinical_events = events
    assert source_event['event'] == 'source' and source_event['document']['suffix'] == '.png'
    layout = source_event['document']['layout']
    assert layout['complete']
    region_by_prefix = {region['prefix']: region for region in layout['regions']}
    assert len(region_by_prefix) == 2
    clinical_by_segment = {event['segment']: event for event in clinical_events}
    for finding in findings:
        assert finding['segment'].endswith('/record')
        region = region_by_prefix[finding['segment'].removesuffix('/record')]
        for evidence in finding['evidence']:
            assert evidence['segment'] == finding['segment']
            assert evidence['value'] == region['text'][evidence['start']:evidence['end']]
            assert not ('LEFT100' in evidence['excerpt'] and 'RIGHT200' in evidence['excerpt'])
        if finding['entity_type'] == 'HEALTH_INFORMATION':
            event = clinical_by_segment[finding['segment']]
            expected = 'LEFT100' if 'diabetes' in region['text'] else 'RIGHT200'
            assert event['anchors'] == [('MRN', expected)]
    for observation in observations:
        assert observation['source_span_valid']
        assert observation['segment'] == observation['source_segment']
        region = region_by_prefix[observation['segment'].removesuffix('/record')]
        assert observation['value'] == region['text'][observation['start']:observation['end']]
    assert not extracted.metadata['patient_linkage_context_verified']
    assert extracted.metadata['document_layout']['candidate_records'] == 2
    assert not extracted.metadata['document_layout']['patient_association_accuracy_validated']


def test_frames_and_repeated_values_do_not_merge_or_deduplicate():
    extracted = raster(form('REPEAT100', 'diabetes'), form('REPEAT100', 'diabetes'))
    findings, observations, events = analyze(extracted)
    assert entity_counts(findings) == {'MRN': 2, 'HEALTH_INFORMATION': 4}
    assert len(observations) == 2 and [event['value'] for event in observations] == ['REPEAT100', 'REPEAT100']
    assert {finding['segment'].split('/')[0] for finding in findings} == {'frame:1', 'frame:2'}
    assert len([event for event in events if event['event'] == 'clinical']) == 2


def test_pdf_equal_native_ocr_observations_are_detected_only_once():
    extracted = pdf(form('NATIVE100', 'diabetes'))
    findings, observations, events = analyze(extracted)
    assert entity_counts(findings) == {'MRN': 1, 'HEALTH_INFORMATION': 2}
    assert len(observations) == 1 and observations[0]['value'] == 'NATIVE100'
    assert all('/channel:native/' in finding['segment'] for finding in findings)
    assert clinical(findings)[0]['classification'] == 'patient_linked_health'
    assert [channel['id'] for channel in events[0]['document']['layout']['units'][0]['channels']] == ['native']


def test_native_identifier_and_ocr_only_clinical_content_cannot_be_joined():
    extracted = pdf(line('MRN: NATIVE100'), line('Diagnosis: diabetes', y=.135, block=2))
    findings, observations, events = analyze(extracted)
    assert_unlinked(findings)
    assert entity_counts(findings) == {'MRN': 1, 'HEALTH_INFORMATION': 2}
    assert all('/channel:ocr/' in item['segment'] for item in clinical(findings))
    assert events[-1]['anchors'] == []


def test_suppressed_ocr_line_barrier_prevents_borrowing_prior_ocr_identifier():
    separator = line('Separator', y=.135, row=2)
    ocr = line('MRN: OCR100', row=1) + copy.deepcopy(separator) + line('Diagnosis: diabetes', y=.17, row=3)
    extracted = pdf(separator, ocr)
    findings, observations, events = analyze(extracted, evidence=True)
    assert_unlinked(findings)
    assert entity_counts(findings) == {'MRN': 1, 'HEALTH_INFORMATION': 2}
    assert '/channel:ocr-2/' in clinical(findings)[0]['segment']
    assert observations[0]['segment'].startswith('page:1/channel:ocr/')
    assert all('OCR100' not in example['excerpt'] for item in clinical(findings) for example in item['evidence'])


def test_native_ocr_conflicts_are_retained_but_cannot_create_links():
    extracted = pdf(form('NATIVE100', 'diabetes'), form('OCR200', 'hypertension'))
    findings, observations, events = analyze(extracted)
    assert_unlinked(findings)
    assert entity_counts(findings) == {'MRN': 2, 'HEALTH_INFORMATION': 4}
    assert {observation['value'] for observation in observations} == {'NATIVE100', 'OCR200'}
    assert all(not region['association_candidate'] for region in events[0]['document']['layout']['regions'])
    assert not events[0]['document']['layout']['complete']


def test_unmapped_tika_text_is_detected_once_without_borrowing_mapped_identity():
    extracted = pdf(form('NATIVE100', 'diabetes'))
    extracted.text += '\fMRN: TIKA200\nDiagnosis: hypertension\nContact: extra@example.test'
    findings, observations, events = analyze(extracted, evidence=True)
    assert entity_counts(findings) == {'MRN': 2, 'HEALTH_INFORMATION': 4, 'EMAIL_ADDRESS': 1}
    health = clinical(findings)
    assert len(health) == 2
    linked = next(item for item in health if item['classification'] == 'patient_linked_health')
    unlinked = next(item for item in health if item['classification'] == 'clinical_content')
    assert '/channel:native/' in linked['segment']
    assert unlinked['segment'].startswith('document:unmapped/channel:unmapped/region:1/')
    assert all('TIKA200' not in example['excerpt'] for item in findings if '/channel:native/' in item['segment']
               for example in item['evidence'])
    assert not events[0]['document']['layout']['complete']
    assert extracted.metadata['document_layout']['unverified_regions'] == 1
    assert events[-1]['anchors'] == []


@pytest.mark.parametrize('mode', ['local_mapping_unknown', 'inventory_incomplete', 'legacy_no_words'])
def test_ineligible_geometry_keeps_identifiers_and_health_but_never_links(mode):
    extracted = raster(form('PRIVATE100', 'diabetes'))
    unit = extracted.document_units[0]
    if mode == 'inventory_incomplete':
        unit.update(coordinate_eligible=False, coordinate_reason='document_inventory_incomplete')
    else:
        reason = 'geometry_unavailable' if mode == 'legacy_no_words' else 'mapping_unverified'
        unit.update(coordinate_eligible=False, coordinate_reason=reason,
                    geometry_verified=False, geometry_reason=reason)
        if mode == 'legacy_no_words':
            unit['ocr_words'] = []
    findings, observations, events = analyze(extracted)
    assert_unlinked(findings)
    assert entity_counts(findings) == {'MRN': 1, 'HEALTH_INFORMATION': 2}
    assert len(observations) == 1 and observations[0]['value'] == 'PRIVATE100'
    assert not extracted.metadata['document_layout']['original_word_mapping_complete']


@pytest.mark.parametrize('mode', ['duplicate_region', 'dropped_region', 'wrong_span', 'changed_word', 'duplicate_word'])
def test_bad_layout_plan_falls_back_to_whole_actual_text_without_drops_or_double_counts(monkeypatch, mode):
    import app.document_layout as module
    extracted = raster(form('LEFT100', 'diabetes') + form('RIGHT200', 'hypertension', x=.6, block=4))
    original = module.segment_words

    def bad_plan(words):
        proposed = copy.deepcopy(original(words))
        region = proposed['regions'][0]
        if mode == 'duplicate_region':
            proposed['regions'].append(copy.deepcopy(region))
        elif mode == 'dropped_region':
            proposed['regions'].pop()
        elif mode == 'wrong_span':
            region['word_spans'][0]['start'] += 1
        elif mode == 'changed_word':
            region['text'] = region['text'].replace('LEFT100', 'OTHER99')
        else:
            region['word_spans'][1]['index'] = region['word_spans'][0]['index']
            region['word_indices'][1] = region['word_indices'][0]
        return proposed

    monkeypatch.setattr(module, 'segment_words', bad_plan)
    findings, observations, events = analyze(extracted)
    assert_unlinked(findings)
    assert entity_counts(findings) == {'MRN': 2, 'HEALTH_INFORMATION': 4}
    assert Counter(item['value'] for item in observations) == {'LEFT100': 1, 'RIGHT200': 1}
    assert 'layout' not in events[0]['document']
    assert extracted.metadata['document_layout']['reason'] == 'document_layout_unavailable'


@pytest.mark.parametrize('mode', ['text_mismatch', 'truncation', 'invalid_box'])
def test_invalid_channel_alignment_preserves_only_actual_returned_text_unlinked(mode):
    extracted = raster(form('PRIVATE100', 'diabetes'))
    if mode == 'text_mismatch':
        extracted.text = extracted.text.replace('PRIVATE100', 'ACTUAL200')
    elif mode == 'truncation':
        extracted.metadata['text_truncated'] = True
    else:
        extracted.document_units[0]['ocr_words'][0]['left'] = float('nan')
    findings, observations, events = analyze(extracted)
    assert_unlinked(findings)
    assert entity_counts(findings) == {'MRN': 1, 'HEALTH_INFORMATION': 2}
    assert observations[0]['value'] == ('ACTUAL200' if mode == 'text_mismatch' else 'PRIVATE100')
    assert extracted.metadata['document_layout']['candidate_records'] == 0


def test_different_labelled_identifiers_on_adjacent_lines_are_ambiguous():
    extracted = raster(line('MRN: FIRST100') + line('UHID: SECOND200', y=.135, row=2)
                       + line('Diagnosis: diabetes', y=.17, row=3))
    findings, observations, events = analyze(extracted)
    assert_unlinked(findings)
    assert clinical(findings)[0]['reason'] == 'clinical_content_with_ambiguous_patient_references'
    assert {item['value'] for item in observations} == {'FIRST100', 'SECOND200'}
    assert events[-1]['anchors'] == []


@pytest.mark.parametrize('fields', [
    'MRN: FIRST100 UHID: SECOND200',
    'MRN: FIRST100 MRN: SECOND200',
    'Patient ID: FIRST100 ABHA: 12-3456-7890-1234',
    'MRN: FIRST100 Medical Record No: SECOND200',
])
def test_conflicting_explicit_fields_on_one_unsplit_spatial_line_cannot_link(fields):
    extracted = raster(line(fields + ' Diagnosis: diabetes'))
    findings, observations, events = analyze(extracted)
    assert_unlinked(findings)
    assert len(observations) >= 2
    assert events[-1]['anchors'] == []


def test_unlabelled_neighbour_and_later_unreadable_header_do_not_borrow_previous_patient():
    extracted = raster(form('LEFT100', 'diabetes') + line('Record B', x=.6, block=4)
                       + line('Diagnosis: hypertension', x=.6, y=.135, block=5))
    findings, observations, events = analyze(extracted, evidence=True)
    assert sum(item['classification'] == 'patient_linked_health' for item in clinical(findings)) == 1
    hypertension = next(item for item in clinical(findings)
                        if any(example['value'] == 'hypertension' for example in item['evidence']))
    assert hypertension['classification'] == 'clinical_content'
    extracted = raster(line('MRN: FIRST100') + line('Patient Name = Unknown', y=.135, row=2)
                       + line('Diagnosis: diabetes', y=.17, row=3))
    findings, _, _ = analyze(extracted)
    assert_unlinked(findings)


@pytest.mark.parametrize('connector', ['file', 'object_store'])
def test_connector_result_never_persists_private_layout_values_boxes_or_observers(monkeypatch, connector):
    extracted = raster(form('PRIVATE100', 'diabetes'))
    if connector == 'file':
        import app.scanning as scanning
        monkeypatch.setattr(scanning, 'extract_bytes', lambda *args, **kwargs: extracted)
        stat = SimpleNamespace(st_size=10, st_mtime_ns=2, st_ino=3)
        result = scanning._file_result('synthetic.png', b'original', stat, stat, {}, Detector('rules'))
    else:
        import app.extraction as extraction
        from app.cloud_connectors import _extract
        monkeypatch.setattr(extraction, 'extract_bytes', lambda *args, **kwargs: extracted)
        result = _extract('synthetic.png', b'original', 10, 'synthetic-etag', {}, Detector('rules'))
    assert any(item['classification'] == 'patient_linked_health' for item in result['findings'])
    serialized = json.dumps(result)
    assert all(secret not in serialized for secret in ('PRIVATE100', 'diabetes', 'ocr_words',
                                                      'word_spans', 'coordinate_space', 'pixel_width',
                                                      '"left"', '"right"', '"anchors"', '"layout"'))
    assert all('evidence' not in item for item in result['findings'])


def test_observer_scopes_and_layout_scope_restore_after_detector_failure():
    observations, events = [], []
    detector = Detector('rules', _observation_sink=observations.append, _association_sink=events.append)
    detector._analyzer = SimpleNamespace(analyze=lambda **kwargs: (_ for _ in ()).throw(RuntimeError('PRIVATE_FAILURE')))
    previous_observation = ('previous', None, 0)
    previous_association = {'location': 'previous', 'references': (), 'finding_segment': None}
    previous_layout = {'prefix': 'frame:99', 'candidate': False}
    detector._observation_scope = previous_observation
    detector._association_scope = previous_association
    detector._layout_scope = previous_layout
    with pytest.raises(RuntimeError, match='local_ner_analysis_failed') as caught:
        analyze_document('synthetic.png', b'original', '.png', raster(form('PRIVATE100', 'diabetes')), {}, detector)
    assert 'PRIVATE' not in str(caught.value)
    assert detector._observation_scope is previous_observation
    assert detector._association_scope is previous_association
    assert detector._layout_scope is previous_layout


def test_no_geometry_keeps_normal_text_compatibility_and_explicit_unverified_context():
    regular = ExtractionResult(text='MRN: NORMAL100; diagnosis: diabetes')
    findings, _, _ = analyze(regular)
    assert clinical(findings)[0]['classification'] == 'patient_linked_health'
    unverified = ExtractionResult(text=regular.text, metadata={'patient_linkage_context_verified': False})
    findings, _, _ = analyze(unverified)
    assert_unlinked(findings)
