import copy
import json
import pytest

from app.extraction import _pdf_supplement
from app.pdf_reconciliation import reconcile_page


def words(text, y=.1, block=1, line=1, x=.1):
    result = []
    for token in text.split():
        width = len(token) * .008
        result.append(dict(text=token, left=x, right=x+width, top=y, bottom=y+.02, block=block, line=line))
        x += width + .01
    return result


def unit(native, ocr=None):
    ocr = copy.deepcopy(native) if ocr is None else ocr
    return dict(native_text=' '.join(w['text'] for w in native), text=' '.join(w['text'] for w in ocr),
        native_words=native, ocr_words=ocr, native_status='completed', ocr_status='completed',
        render_status='completed', native_text_truncated=False, truncated=False, geometry_verified=True)


def test_equal_spatial_lines_count_once_without_storing_values():
    text, meta = reconcile_page(unit(words('MRN: SYN100 diabetes')))
    assert text.count('SYN100') == 1
    assert meta['reconciled'] and meta['duplicate_ocr_lines_suppressed'] == 1
    assert 'SYN100' not in json.dumps(meta) and not meta['native_representation_verified']


def test_real_repeated_values_at_distinct_positions_survive():
    native = words('MRN: SYN100', .1, 1) + words('MRN: SYN100', .5, 2)
    text, meta = reconcile_page(unit(native))
    assert text.count('SYN100') == 2 and meta['duplicate_ocr_lines_suppressed'] == 2


def test_equal_value_in_separate_ocr_only_region_is_not_suppressed():
    native = words('MRN: SYN100', .1)
    ocr = copy.deepcopy(native) + words('MRN: SYN100', .5, 2)
    text, meta = reconcile_page(unit(native, ocr))
    assert text.count('SYN100') == 2 and meta['reconciled']


def test_competing_different_text_prevents_even_equal_candidate_suppression():
    native = words('MRN: SYN100')
    ocr = copy.deepcopy(native) + words('MRN: SYN200', .105, 2)
    text, meta = reconcile_page(unit(native, ocr))
    assert 'SYN100' in text and 'SYN200' in text
    assert meta['duplicate_ocr_lines_suppressed'] == 0 and not meta['reconciled']


def test_tiny_word_inside_large_same_text_region_is_not_a_duplicate():
    native = words('MRN: SYN100')
    ocr = copy.deepcopy(native)
    native[1].update(left=.22, right=.90, top=.10, bottom=.15)
    ocr[1].update(left=.58, right=.64, top=.11, bottom=.14)
    text, meta = reconcile_page(unit(native, ocr))
    assert text.count('SYN100') == 2 and not meta['reconciled']


def test_different_values_same_position_are_kept_separate_and_partial():
    text, meta = reconcile_page(unit(words('MRN: SYN100 diabetes'), words('MRN: SYN200 diabetes')))
    assert 'SYN100' in text and 'SYN200' in text and '\n\n' in text
    assert not meta['reconciled'] and meta['conflicting_ocr_lines'] == 1


def test_exact_spatial_words_resolve_different_column_line_grouping():
    native = words('MRN: SYN100', x=.1) + words('MRN: SYN200', block=2, x=.6)
    ocr = copy.deepcopy(native)
    for word in ocr: word.update(block=1, line=1)
    text, meta = reconcile_page(unit(native, ocr))
    assert meta['reconciled'] and meta['duplicate_ocr_lines_suppressed'] == 1
    assert text.count('SYN100') == text.count('SYN200') == 1


def test_removed_line_cannot_stitch_residual_ocr_fragments_into_one_record():
    native = words('separator line', .3)
    ocr = words('MRN: SYN100', .1, line=1) + words('separator line', .3, line=2) + words('diabetes', .5, line=3)
    text, meta = reconcile_page(unit(native, ocr))
    assert 'MRN: SYN100\n\ndiabetes' in text and meta['duplicate_ocr_lines_suppressed'] == 1


def test_unknown_mapping_and_channel_failures_never_claim_reconciliation():
    original = unit(words('MRN: SYN100'))
    for change in ({'geometry_verified':False}, {'native_status':'limited'}, {'truncated':True}):
        candidate = {**original, **change}
        text, meta = reconcile_page(candidate)
        assert 'SYN100' in text and not meta['reconciled']


@pytest.mark.parametrize('change', [
    {'left':float('nan')}, {'right':2}, {'left':True}, {'line':True}, {'text':'SYN100\fdiabetes'},
])
def test_invalid_geometry_is_rejected(change):
    data = unit(words('MRN: SYN100'))
    data['native_words'][0].update(change)
    with pytest.raises(ValueError): reconcile_page(data)


def test_word_inventory_must_represent_entire_channel():
    data = unit(words('MRN: SYN100'))
    data['native_text'] += ' OFFPAGE999'
    with pytest.raises(ValueError): reconcile_page(data)


def test_spatial_work_limit_retains_both_channels(monkeypatch):
    monkeypatch.setattr('app.pdf_reconciliation.MAX_CANDIDATE_PAIRS', 0)
    text, meta = reconcile_page(unit(words('MRN: SYN100')))
    assert text.count('SYN100') == 2 and meta['limit_reached'] and not meta['reconciled']


def test_tika_equal_pages_preserve_multiplicity_and_original_ordinals():
    html = '<div class="page"><p>MRN: SYN100 MRN: SYN100</p></div><div class="page"></div>'
    text, meta = _pdf_supplement(html, ['MRN: SYN100\nMRN: SYN100', ''])
    assert not text.strip() and meta['tika_native_pages_suppressed'] == 2
    text, meta = _pdf_supplement(html, ['MRN: SYN100', ''])
    assert text.count('SYN100') == 2 and meta['tika_unmatched_native_pages'] == 1


def test_tika_offpage_native_and_outside_page_text_are_preserved():
    html = '<p>Title SYN700</p><div class="page"><p>MRN: SYN100</p><p>MRN: OFFPAGE999</p></div>'
    text, meta = _pdf_supplement(html, ['MRN: SYN100'])
    assert 'SYN700' in text and 'OFFPAGE999' in text and meta['tika_nonpage_text_present']


@pytest.mark.parametrize('html', [
    '<p>MRN: SYN100</p>', '<div class="page"><p>MRN: SYN100</p>',
    '<div class="page"><div class="page">MRN: SYN100</div></div>',
])
def test_unknown_tika_page_mapping_retains_all_native_text(html):
    text, meta = _pdf_supplement(html, ['MRN: SYN100'])
    assert 'SYN100' in text and not meta['tika_page_mapping_verified']


def test_accounted_pdf_sorting_only_aligns_order_and_never_deduplicates_source(monkeypatch):
    from app.extraction import _extract_tika
    from test_ocr_accounting import install_endpoint, report
    monkeypatch.setenv('TIKA_URL', 'http://127.0.0.1:9998')
    html = '<p>Outside SECRET</p><div class="page"><p>MRN: SYN100 MRN: SYN100</p></div>'
    calls = install_endpoint(monkeypatch, report('pdf'), tika_payload=[
        {'X-TIKA:content': html}, {'X-TIKA:content': '<p>Embedded SECRET</p>'}])
    extracted = _extract_tika(b'%PDF synthetic', '.pdf', 10000, pdf_ocr=False,
                              pdf_native_pages=['MRN: SYN100'])
    headers = calls[0][1]['headers']
    assert headers['X-Tika-PDFsortByPosition'] == 'true'
    assert headers['X-Tika-PDFsuppressDuplicateOverlappingText'] == 'false'
    assert extracted.text.count('SYN100') == 2
    assert 'Outside SECRET' in extracted.text and 'Embedded SECRET' in extracted.text
    assert extracted.metadata['tika_unmatched_native_pages'] == 1
    assert extracted.metadata['tika_nonpage_text_present']
    assert extracted.status == 'partial'
    calls.clear()
    _extract_tika(b'%PDF synthetic', '.pdf', 10000)
    assert 'X-Tika-PDFsortByPosition' not in calls[0][1]['headers']


def test_same_page_token_permutation_is_not_equivalent_without_order_alignment():
    html = '<div class="page"><p>MRN: SYN100 diabetes MRN: SYN200 asthma</p></div>'
    text, meta = _pdf_supplement(html, ['MRN: SYN100 MRN: SYN200 diabetes asthma'])
    assert 'SYN100' in text and 'SYN200' in text
    assert meta['tika_native_pages_suppressed'] == 0 and meta['tika_unmatched_native_pages'] == 1
