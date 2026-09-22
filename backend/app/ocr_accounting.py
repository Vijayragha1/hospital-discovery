"""Validate original-page/frame OCR accounting from the isolated local parser.

Only fixed coverage metadata is retained. Unit text is transient input to the
same detector as native extraction; it is never copied into object metadata.
"""
from __future__ import annotations

import json
import os
from urllib.parse import urlparse

IMAGE_SUFFIXES = {'.png', '.jpg', '.jpeg', '.tif', '.tiff', '.bmp'}
_REASONS = {
    'input_size_limit', 'input_unavailable', 'input_changed', 'page_limit', 'pixel_limit',
    'text_limit', 'job_timeout', 'processing_timeout', 'job_interrupted', 'dependency_unavailable',
    'output_limit', 'process_failed', 'image_stage_failed', 'unsupported_kind', 'unsupported_pdf_header',
    'page_dimensions_unavailable', 'render_output_invalid', 'pdf_inventory_failed', 'pdf_encrypted',
    'unsupported_image_format', 'image_inventory_failed', 'inventory_unavailable', 'inventory_invalid',
    'invalid_image', 'render_failed', 'ocr_invalid_utf8', 'nonvisual_content_present',
    'inventory_failed', 'encrypted_pdf', 'image_dependency_unavailable', 'processing_failed',
    'invalid_request', 'image_render_failed', 'unit_render_failed', 'pdf_feature_inspection_failed',
    'pdf_feature_limit', 'pdf_page_count_mismatch', 'extraction_not_permitted',
    'native_text_budget_exhausted', 'native_invalid_utf8', 'native_text_failed',
    'invalid_text_encoding',
}
_PDF_COUNTS = {'annotations', 'unknown_annotations', 'forms', 'xfa', 'layers', 'embedded_name_trees',
    'associated_files', 'file_specifications', 'embedded_streams', 'actions', 'metadata', 'other_text',
    'interactive_features', 'unknown_streams', 'image_resources', 'image_uses', 'unused_images',
    'unverified_image_uses', 'unsupported_resources', 'unsupported_operators', 'unknown_structure', 'parser_warnings',
    'nondefault_user_units', 'native_text_operations'}
_GEOMETRY_REASONS = {'verified', 'mapping_unverified', 'channel_incomplete', 'geometry_unavailable',
    'geometry_invalid', 'geometry_text_unverified', 'geometry_limit'}
MAX_DOCUMENT_WORDS = 10_000
MAX_DOCUMENT_WORD_CHARACTERS = 250_000
MAX_UNIT_PIXELS = 20_000_000
COORDINATE_SPACE = 'rendered_unit_normalized_v1'


def _int(value, low, high):
    return type(value) is int and low <= value <= high


def _pdf_features(value):
    if value is None:
        return None
    if (not isinstance(value, dict) or value.get('protocol') != 'pdf-features/v1'
            or value.get('status') not in {'completed', 'failed', 'limited'}):
        raise ValueError('invalid_pdf_features')
    for key in ('inventory_complete', 'can_extract', 'ancillary_absent'):
        if type(value.get(key)) is not bool:
            raise ValueError('invalid_pdf_features')
    pages = value.get('original_page_count')
    if (pages is not None and not _int(pages, 1, 100)) or (value.get('encrypted') is not None and type(value['encrypted']) is not bool):
        raise ValueError('invalid_pdf_features')
    counts = value.get('feature_counts')
    if not isinstance(counts, dict) or set(counts) != _PDF_COUNTS or not all(_int(n, 0, 200000) for n in counts.values()):
        raise ValueError('invalid_pdf_features')
    complete = value['status'] == 'completed' and value['inventory_complete'] and pages is not None
    absent = complete and value.get('encrypted') is False and value['can_extract'] and not any(
        count for name, count in counts.items() if name not in {'image_resources', 'image_uses', 'native_text_operations'})
    if value['inventory_complete'] != complete or value['ancillary_absent'] != absent:
        raise ValueError('inconsistent_pdf_features')
    return {'inventory_complete': complete, 'original_page_count': pages, 'encrypted': value.get('encrypted'),
            'can_extract': value['can_extract'], 'ancillary_absent': absent, 'feature_counts': counts}


def _transient_document_units(payload, kind, maximum, inventory_complete):
    """Sanitize geometry after accounting validation; never return it as metadata.

    Coordinates describe the rendered/oriented original unit, not raw image
    pixels or a patient record. Legacy units without geometry stay ineligible.
    """
    from .pdf_reconciliation import _lines, _words

    result = []
    word_count = word_characters = text_characters = 0
    for unit in payload['units']:
        geometry_present = any(key in unit for key in ('geometry_verified', 'geometry_reason', 'ocr_words', 'native_words'))
        verified = unit.get('geometry_verified', False)
        reason = unit.get('geometry_reason', 'geometry_unavailable')
        if (type(verified) is not bool or not isinstance(reason, str) or reason not in _GEOMETRY_REASONS
                or (geometry_present and 'geometry_verified' not in unit)
                or (verified and reason != 'verified') or (not verified and reason == 'verified')):
            raise ValueError('invalid_document_geometry_claim')
        width, height = unit.get('pixel_width'), unit.get('pixel_height')
        dimensions_valid = (_int(width, 1, MAX_UNIT_PIXELS) and _int(height, 1, MAX_UNIT_PIXELS)
                            and width * height <= MAX_UNIT_PIXELS)
        if ((width is not None or height is not None) and not dimensions_valid) or (verified and not dimensions_valid):
            raise ValueError('invalid_document_dimensions')
        processed = (unit['render_status'] == unit['ocr_status'] == 'completed' and unit['truncated'] is False)
        if kind == 'pdf':
            processed = processed and unit.get('native_status') == 'completed' and unit.get('native_text_truncated') is False
        if verified and not processed:
            raise ValueError('incomplete_document_geometry_channel')

        item = {'kind': kind, 'ordinal': unit['ordinal'], 'coordinate_space': COORDINATE_SPACE,
                'pixel_width': width, 'pixel_height': height, 'render_status': unit['render_status'],
                'ocr_status': unit['ocr_status'], 'text': unit['text'], 'truncated': unit['truncated'],
                'geometry_verified': verified, 'geometry_reason': reason,
                'coordinate_eligible': bool(verified and inventory_complete),
                'coordinate_reason': ('verified' if verified and inventory_complete else
                                      'document_inventory_incomplete' if verified else reason)}
        channels = [('ocr_words', unit['text'])]
        if kind == 'pdf':
            native = unit.get('native_text', '')
            item.update(native_text=native, native_status=unit.get('native_status', 'not_attempted'),
                        native_text_truncated=unit.get('native_text_truncated', False))
            channels.append(('native_words', native))
        for key, text in channels:
            text_characters += len(text)
            if text_characters > maximum:
                raise ValueError('document_text_limit')
            supplied = unit.get(key, [])
            if not isinstance(supplied, list):
                raise ValueError('invalid_document_word_inventory')
            # An explicitly unverified channel may have no usable word inventory.
            # A verified blank channel, however, must pass text/token equality.
            words = _words(supplied, text) if supplied or verified else []
            _lines(words)  # Reject repeated noncontiguous line identities.
            word_count += len(words)
            word_characters += sum(len(word['text']) for word in words)
            if word_count > MAX_DOCUMENT_WORDS or word_characters > MAX_DOCUMENT_WORD_CHARACTERS:
                raise ValueError('document_geometry_limit')
            item[key] = [{'text': word['text'], 'left': word['box'][0], 'top': word['box'][1],
                          'right': word['box'][2], 'bottom': word['box'][3],
                          'block': word['block'], 'line': word['line']} for word in words]
        result.append(item)
    return result


def document_units_from_report(payload, kind, maximum):
    """Validate a report and return private original-unit text/geometry.

    This is transient processing input, never persisted metadata or API output.
    Coordinate eligibility does not verify patient boundaries or source stability.
    """
    text, metadata = validate_report(payload, kind, maximum)
    units = _transient_document_units(payload, kind, maximum, metadata['page_accounting_complete'])
    if len(text) > maximum:  # Joining original units/channels also consumes output budget.
        for unit in units:
            unit['coordinate_eligible'] = False
            unit['coordinate_reason'] = 'document_text_truncated'
    return units


def validate_report(payload, kind, maximum):
    """Independently derive completion; do not trust a server's complete flag."""
    if (kind not in {'pdf', 'image'} or not isinstance(payload, dict)
            or payload.get('protocol') != 'parser-accounting/v1' or payload.get('kind') != kind):
        raise ValueError('invalid_accounting')
    total = payload.get('original_unit_count')
    if total is not None and not _int(total, 1, 1_000_000):
        raise ValueError('invalid_accounting')
    units = payload.get('units')
    if not isinstance(units, list) or len(units) > 100:
        raise ValueError('invalid_accounting')
    for key in ('page_accounting_complete', 'limited', 'legibility_verified'):
        if type(payload.get(key)) is not bool:
            raise ValueError('invalid_accounting')
    if payload['legibility_verified']:
        raise ValueError('unsupported_legibility_claim')
    raw_reasons = payload.get('reason_codes')
    if not isinstance(raw_reasons, list) or len(raw_reasons) > 100 or not all(isinstance(item, str) for item in raw_reasons):
        raise ValueError('invalid_accounting')
    reason_codes = sorted({item if item in _REASONS else 'worker_reported_incomplete' for item in raw_reasons})
    text_parts, metadata_units = [], []
    completed, characters, native_completed = 0, 0, 0
    native_available = kind == 'pdf' and bool(units) and all('native_status' in unit for unit in units if isinstance(unit, dict))
    if kind == 'pdf' and any(isinstance(unit, dict) and 'native_status' in unit for unit in units) and not native_available:
        raise ValueError('inconsistent_native_accounting')
    reconciliations = []
    for index, unit in enumerate(units, 1):
        if not isinstance(unit, dict) or unit.get('ordinal') != index or not _int(unit.get('ordinal'), 1, 100):
            raise ValueError('invalid_accounting')
        if total is None or index > total:
            raise ValueError('invalid_accounting')
        render, ocr = unit.get('render_status'), unit.get('ocr_status')
        if render not in {'not_attempted', 'completed', 'failed'} or ocr not in {'not_attempted', 'completed', 'failed', 'limited'}:
            raise ValueError('invalid_accounting')
        if render != 'completed' and ocr != 'not_attempted':
            raise ValueError('invalid_accounting')
        value = unit.get('text')
        if not isinstance(value, str) or type(unit.get('truncated')) is not bool:
            raise ValueError('invalid_accounting')
        if ocr not in {'completed', 'limited'} and value:
            raise ValueError('invalid_accounting')
        characters += len(value)
        if characters > maximum:
            raise ValueError('invalid_accounting')
        if ocr == 'completed' and not unit['truncated']:
            completed += 1
        native_metadata = {}
        if native_available:
            native_status, native = unit.get('native_status'), unit.get('native_text')
            if (native_status not in {'not_attempted', 'completed', 'failed', 'limited'}
                    or not isinstance(native, str) or type(unit.get('native_text_truncated')) is not bool
                    or (native_status not in {'completed', 'limited'} and native)):
                raise ValueError('invalid_native_accounting')
            characters += len(native)
            if characters > maximum:
                raise ValueError('invalid_native_accounting')
            native_completed += native_status == 'completed' and not unit['native_text_truncated']
            from .pdf_reconciliation import reconcile_page
            canonical, reconciliation = reconcile_page(unit)
            reconciliations.append(reconciliation)
            native_metadata = {'native_status': native_status, 'native_text_characters': len(native),
                'native_text_truncated': unit['native_text_truncated'], 'reconciliation': reconciliation}
        else:
            canonical = value
        # Form feeds are source-unit delimiters supplied by us, not by OCR text.
        text_parts.append(canonical.replace('\f', '\n'))
        metadata_units.append({'ordinal': index, 'render_status': render, 'ocr_status': ocr,
                               'text_truncated': unit['truncated'], 'text_characters': len(value), **native_metadata})
    if payload.get('text_characters') != characters or type(payload.get('text_characters')) is not int:
        raise ValueError('invalid_accounting')
    omitted = None if total is None else total - len(units)
    if payload.get('units_omitted') != omitted or (omitted is not None and type(payload.get('units_omitted')) is not int):
        raise ValueError('invalid_accounting')
    independent_feature_gaps = {'pdf_feature_inspection_failed', 'pdf_feature_limit'} if kind == 'pdf' else set()
    complete = (total is not None and completed == total and len(units) == total
                and (not native_available or native_completed == total)
                and not payload['limited'] and not (set(reason_codes) - independent_feature_gaps))
    if payload['page_accounting_complete'] != complete:
        raise ValueError('inconsistent_accounting')
    # Validate dimensions, all claimed geometry and shared whole-document limits
    # even though this public return value deliberately contains no coordinates.
    _transient_document_units(payload, kind, maximum, complete)
    nonvisual = payload.get('nonvisual_content_present')
    if kind == 'image' and type(nonvisual) is not bool:
        raise ValueError('invalid_accounting')
    metadata = {'extractor': 'isolated_page_ocr', 'ocr_requested': True, 'ocr_language': 'eng',
                'ocr_policy': 'every_original_page_or_frame', 'coverage_scope': 'rendered_pages_or_frames',
                'original_unit_count': total, 'units_omitted': omitted, 'units': metadata_units,
                'page_accounting_complete': complete, 'units_ocr_completed': completed,
                'ocr_legibility_verified': False, 'reason_codes': reason_codes,
                'nonvisual_content_present': nonvisual if kind == 'image' else True,
                'embedded_annotation_coverage': 'unverified' if kind == 'pdf' else 'not_applicable',
                'segment_numbers_are_original_unit_ordinals': True}
    if kind == 'pdf':
        metadata['pdf_features'] = _pdf_features(payload.get('pdf_features'))
        features = metadata['pdf_features']
        if features and features['original_page_count'] not in {None, total} and complete:
            raise ValueError('inconsistent_page_inventory')
        if features and features['ancillary_absent']:
            metadata['nonvisual_content_present'] = False
            metadata['embedded_annotation_coverage'] = 'none_present'
        metadata.update(pdf_native_channel_available=native_available, units_native_completed=native_completed,
            pdf_instance_channels_reconciled=bool(complete and native_available and all(r['reconciled'] for r in reconciliations)),
            duplicate_ocr_lines_suppressed=sum(r['duplicate_ocr_lines_suppressed'] for r in reconciliations),
            native_representation_verified=False)
        # Strict inventory proves native-text absence only when no text-showing
        # operation exists. Geometry agreement is not proof for native-text PDFs:
        # Poppler can silently omit off-page or overprinted native characters.
        native_absent = bool(complete and native_available and features and features['ancillary_absent']
            and features['feature_counts']['native_text_operations'] == 0
            and all(not unit['native_text'].strip() for unit in units))
        metadata['native_representation_verified'] = native_absent
        if native_absent:
            for unit in metadata_units:
                unit['reconciliation']['native_representation_verified'] = True
    return '\f'.join(text_parts), metadata


def extract_accounted(data, kind, maximum):
    from .extraction import ExtractionResult, _bounded, private_host
    endpoint = os.getenv('PAGE_OCR_URL', '').rstrip('/')
    parsed = urlparse(endpoint)
    if (parsed.scheme not in {'http', 'https'} or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or parsed.path not in {'', '/'} or not private_host(parsed.hostname)):
        return ExtractionResult(status='failed', reason='page_ocr_endpoint_not_private', unit='bytes')
    try:
        import requests
        limit = min(maximum, 1_000_000)
        with requests.Session() as session:
            session.trust_env = False
            with session.put(endpoint+'/v1/'+kind, data=data, headers={
                    'Content-Type': 'application/octet-stream', 'X-Max-Text-Chars': str(limit)},
                    timeout=(5, 65), allow_redirects=False, stream=True) as response:
                if response.status_code != 200:
                    return ExtractionResult(status='failed', reason='page_ocr_job_failed', unit='bytes')
                body = bytearray()
                for chunk in response.iter_content(65536):
                    body.extend(chunk)
                    if len(body) > limit * 8 + 131072:
                        return ExtractionResult(status='partial', reason='page_ocr_response_limit', unit='bytes')
                payload = json.loads(body)
                text, metadata = validate_report(payload, kind, limit)
        full = metadata['page_accounting_complete'] and kind == 'image' and not metadata['nonvisual_content_present']
        if kind == 'pdf':
            full = bool(metadata['page_accounting_complete'] and metadata['pdf_instance_channels_reconciled']
                        and metadata['native_representation_verified'] and metadata['pdf_features']['ancillary_absent'])
        metadata['completeness_verified'] = full
        if not metadata['page_accounting_complete']:
            reason = 'page_or_frame_ocr_incomplete'
        elif kind == 'pdf' and not full:
            reason = ('pdf_native_representation_and_nonpage_coverage_unverified' if metadata['pdf_instance_channels_reconciled']
                      else 'pdf_native_ocr_overlap_unresolved')
        elif kind == 'image' and metadata['nonvisual_content_present']:
            reason = 'image_nonvisual_metadata_not_inspected'
        else:
            reason = None
        result = ExtractionResult(status='full' if full else 'partial', reason=reason,
            examined=metadata['units_ocr_completed'], unit='pages' if kind == 'pdf' else 'frames', metadata=metadata,
            native_pages=[unit['native_text'] for unit in payload['units']] if metadata.get('pdf_native_channel_available') else None,
            document_units=_transient_document_units(payload, kind, limit, metadata['page_accounting_complete']))
        return _bounded(text, maximum, result)
    except Exception:
        return ExtractionResult(status='failed', reason='page_ocr_unavailable_or_invalid_response', unit='bytes')
