import json
import pytest
from app.detection import Detector
from app.extraction import extract_bytes
from app.ocr_accounting import validate_report


def report(kind='image', texts=('MRN: A12345', 'Research about diabetes')):
    return {'protocol': 'parser-accounting/v1', 'kind': kind, 'original_format': 'TIFF' if kind == 'image' else 'PDF',
        'original_unit_count': len(texts), 'units_omitted': 0, 'page_accounting_complete': True,
        'limited': False, 'reason_codes': [], 'legibility_verified': False,
        'nonvisual_content_present': False if kind == 'image' else None,
        'text_characters': sum(map(len, texts)),
        'units': [{'ordinal': i, 'render_status': 'completed', 'ocr_status': 'completed',
                   'text': text, 'truncated': False} for i, text in enumerate(texts, 1)]}


def install_endpoint(monkeypatch, payload, status=200, tika_payload=None):
    monkeypatch.setenv('PAGE_OCR_URL', 'http://127.0.0.1:9997')
    observed = []
    class Response:
        status_code = status
        def __init__(self, value): self.value = value
        def __enter__(self): return self
        def __exit__(self, *_): pass
        def iter_content(self, _): yield json.dumps(self.value).encode()
    class Session:
        trust_env = True
        def __enter__(self): return self
        def __exit__(self, *_): pass
        def put(self, url, **kwargs):
            observed.append((url, kwargs, self.trust_env))
            return Response(tika_payload if url.endswith('/rmeta') else payload)
    monkeypatch.setattr('requests.Session', Session)
    return observed


def test_every_original_frame_reaches_detector_and_metadata_has_no_values(monkeypatch):
    calls = install_endpoint(monkeypatch, report())
    extracted = extract_bytes(b'synthetic image', '.tif')
    assert extracted.status == 'full' and extracted.examined == 2 and extracted.unit == 'frames'
    assert extracted.metadata['page_accounting_complete']
    assert extracted.metadata['segment_numbers_are_original_unit_ordinals']
    assert 'A12345' not in json.dumps(extracted.metadata)
    findings = Detector('rules').analyze(extracted.text, capture_evidence=True)
    assert any(item['entity_type'] == 'MRN' for item in findings)
    assert all(item['classification'] == 'clinical_content' for item in findings if item['entity_type'] == 'HEALTH_INFORMATION')
    assert all(not ('A12345' in example['excerpt'] and 'diabetes' in example['excerpt'])
               for item in findings for example in item['evidence'])
    assert len(calls) == 1 and calls[0][0].endswith('/v1/image')
    assert calls[0][1]['allow_redirects'] is False and calls[0][2] is False


def test_frame_failure_retains_gap_and_surviving_frame_values(monkeypatch):
    data = report()
    data['units'][1].update(render_status='failed', ocr_status='not_attempted', text='')
    data.update(page_accounting_complete=False, text_characters=len(data['units'][0]['text']), reason_codes=['pixel_limit'], limited=True)
    install_endpoint(monkeypatch, data)
    extracted = extract_bytes(b'synthetic', '.tiff')
    assert extracted.status == 'partial' and extracted.examined == 1
    assert extracted.metadata['units'][1]['render_status'] == 'failed'
    assert 'A12345' in extracted.text


def test_missing_frames_and_text_limit_cannot_be_complete(monkeypatch):
    data = report()
    data['units'] = data['units'][:1]
    data.update(page_accounting_complete=False, units_omitted=1, reason_codes=['page_limit'], limited=True,
                text_characters=len(data['units'][0]['text']))
    install_endpoint(monkeypatch, data)
    extracted = extract_bytes(b'synthetic', '.tif')
    assert extracted.status == 'partial' and extracted.metadata['units_omitted'] == 1


@pytest.mark.parametrize('alter', [
    lambda p: p.update(original_unit_count=3), lambda p: p.update(original_unit_count=True),
    lambda p: p.update(units_omitted=1), lambda p: p['units'][1].update(ordinal=1),
    lambda p: p['units'][0].update(render_status='failed'), lambda p: p['units'][0].update(ocr_status='failed'),
    lambda p: p.update(text_characters=0), lambda p: p.update(limited=True),
    lambda p: p.update(legibility_verified=True), lambda p: p.update(nonvisual_content_present=None),
    lambda p: p.update(protocol='unrelated-protocol'),
])
def test_inconsistent_or_unsupported_claims_rejected(alter):
    data = report()
    alter(data)
    with pytest.raises(ValueError): validate_report(data, 'image', 1000)


def test_nonvisual_metadata_prevents_full_but_values_are_still_inspected(monkeypatch):
    data = report()
    data['nonvisual_content_present'] = True
    install_endpoint(monkeypatch, data)
    extracted = extract_bytes(b'synthetic', '.jpg')
    assert extracted.status == 'partial' and extracted.reason == 'image_nonvisual_metadata_not_inspected'
    assert extracted.metadata['page_accounting_complete'] and 'A12345' in extracted.text


def test_empty_successful_ocr_is_processed_not_legibility_claim(monkeypatch):
    install_endpoint(monkeypatch, report(texts=('', '')))
    extracted = extract_bytes(b'synthetic blank frames', '.tif')
    assert extracted.status == 'full' and extracted.examined == 2
    assert extracted.metadata['ocr_legibility_verified'] is False


def test_page_worker_request_failure_cannot_fall_back_to_false_complete(monkeypatch):
    install_endpoint(monkeypatch, {'error': 'accounting_worker_failed'}, status=502)
    extracted = extract_bytes(b'synthetic', '.png')
    assert extracted.status == 'failed' and extracted.reason == 'page_ocr_job_failed'


def test_public_page_endpoint_rejected_before_request(monkeypatch):
    calls = install_endpoint(monkeypatch, report())
    monkeypatch.setattr('app.extraction.private_host', lambda host: False)
    extracted = extract_bytes(b'synthetic', '.png')
    assert extracted.reason == 'page_ocr_endpoint_not_private' and not calls


def test_pdf_accounted_pages_and_native_parse_remain_explicit_separate_observations(monkeypatch):
    monkeypatch.setenv('TIKA_URL', 'http://127.0.0.1:9998')
    calls = install_endpoint(monkeypatch, report('pdf'), tika_payload=[{'X-TIKA:content':
        '<div class="page"><p>Native document text</p></div>', 'xmpTPg:NPages': '2'}])
    extracted = extract_bytes(b'%PDF-synthetic', '.pdf')
    assert extracted.status == 'partial' and extracted.examined == 2
    assert extracted.metadata['page_ocr']['page_accounting_complete']
    assert not extracted.metadata['pdf_instance_channels_reconciled']
    assert extracted.metadata['ocr_may_duplicate_native_or_embedded_text']
    assert 'A12345' in extracted.text and 'Native document text' in extracted.text
    assert calls[1][1]['headers']['X-Tika-PDFOcrStrategy'] == 'no_ocr'


def test_response_limit_and_malformed_payload_are_visible(monkeypatch):
    data = report(texts=('X' * 300000,))
    install_endpoint(monkeypatch, data)
    result = extract_bytes(b'synthetic', '.png', {'max_text_chars': 100})
    assert result.status == 'partial' and result.reason == 'page_ocr_response_limit'
    install_endpoint(monkeypatch, {'unexpected': 'SENSITIVE VALUE'})
    result = extract_bytes(b'synthetic', '.png')
    assert result.status == 'failed' and 'SENSITIVE' not in result.reason


def test_pdf_feature_flags_are_sanitized_and_cannot_claim_absence():
    from app.ocr_accounting import _PDF_COUNTS
    payload = report('pdf')
    payload['pdf_features'] = {'protocol': 'pdf-features/v1', 'status': 'completed', 'inventory_complete': True,
        'original_page_count': 2, 'encrypted': False, 'can_extract': True, 'ancillary_absent': False,
        'feature_counts': {key: int(key == 'annotations') for key in _PDF_COUNTS},
        'extra_private_value': 'PRIVATE SHOULD NOT PERSIST'}
    text, meta = validate_report(payload, 'pdf', 1000)
    assert meta['page_accounting_complete'] and not meta['pdf_features']['ancillary_absent']
    assert 'PRIVATE' not in json.dumps(meta)
    payload['pdf_features']['ancillary_absent'] = True
    with pytest.raises(ValueError): validate_report(payload, 'pdf', 1000)


def test_pdf_feature_timeout_does_not_erase_completed_ocr_accounting():
    payload = report('pdf')
    payload['reason_codes'] = ['pdf_feature_inspection_failed']
    text, meta = validate_report(payload, 'pdf', 1000)
    assert meta['page_accounting_complete']
    assert meta['pdf_features'] is None and meta['embedded_annotation_coverage'] == 'unverified'
