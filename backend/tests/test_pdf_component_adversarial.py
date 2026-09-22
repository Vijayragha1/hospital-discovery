"""Adversarial component boundaries and page-wide reconciliation budgets."""
from collections import Counter
from copy import deepcopy
import json

import pytest

from app.document_channels import canonical_document_channels
from app.pdf_reconciliation import _lines, _overlaps, _words, reconciliation_plan, reconcile_page
from test_pdf_column_reconciliation import extraction, page


def word(text, x=.1, y=.1, *, block=1, line=1, width=.08, height=.02):
    return dict(text=text, left=x, right=x + width, top=y, bottom=y + height, block=block, line=line)


def broad_and_word_links(unit):
    native = _words(unit['native_words'], unit['native_text'])
    ocr = _words(unit['ocr_words'], unit['text'])
    return _overlaps(_lines(native), _lines(ocr)), _overlaps(native, ocr)


def assert_all_retained_unverified(unit):
    text, summary = reconcile_page(unit)
    assert not summary['reconciled']
    assert summary['duplicate_ocr_lines_suppressed'] == 0
    assert Counter(text.split()) == Counter(unit['native_text'].split() + unit['text'].split())
    result = canonical_document_channels(extraction(unit))
    assert not result.fallback
    assert result.channels and all(not item['coordinate_eligible'] for item in result.channels)
    assert Counter(token for item in result.channels for token in item['text'].split()) == Counter(text.split())
    return summary


@pytest.mark.parametrize('competing_channel', ['native', 'ocr'])
def test_competing_word_outside_broad_line_component_prevents_suppression(competing_channel):
    # Unusual extractor grouping gives each line a tall union box. The rogue
    # line overlaps a native/OCR word but falls below line-overlap thresholds.
    native = [word('EARLY', y=.1), word('PRIVATE100', y=.385)]
    ocr = deepcopy(native)
    rogue = [word('PRIVATE100', y=.39, block=2), word('LATE', y=.95, block=2)]
    if competing_channel == 'native':
        native += rogue
    else:
        ocr += rogue
    unit = page(native, ocr)
    broad, actual = broad_and_word_links(unit)
    assert dict(broad[1]) == {0: {0}}
    assert any(len(candidates) == 2 for links in actual for candidates in links.values())
    summary = assert_all_retained_unverified(unit)
    assert summary['conflicting_ocr_lines'] == (2 if competing_channel == 'ocr' else 1)


@pytest.mark.parametrize('same_text', [False, True])
def test_word_overlap_without_any_broad_line_edge_cannot_claim_reconciliation(same_text):
    native = [word('EARLY', y=.1), word('PRIVATE100', y=.385)]
    ocr = [word('PRIVATE100' if same_text else 'CONFLICT200', y=.39), word('LATE', y=.95)]
    unit = page(native, ocr)
    broad, actual = broad_and_word_links(unit)
    assert not broad[0] and not broad[1]
    assert dict(actual[1]) == {0: {1}}
    summary = assert_all_retained_unverified(unit)
    assert summary['conflicting_ocr_lines'] == 1


def components():
    # Three components share no grid cells. Each line comparison costs one
    # pair; each word inventory requires two pairs. The budgets must cover all
    # components together, including ones that could individually reconcile.
    return [word(token, x=x, y=y, block=index, width=.02, height=.01)
            for index, y in enumerate((.1, .35, .6), 1)
            for token, x in ((f'PRIVATE{index}00', .1), ('VALUE', .16))]


def test_word_candidate_budget_is_shared_across_components_and_discards_partial_plan(monkeypatch):
    import app.pdf_reconciliation as module
    native = components()
    unit = page(native, deepcopy(native))
    monkeypatch.setattr(module, 'MAX_CANDIDATE_PAIRS', 5)
    internal = _words(native, unit['native_text'])
    assert module._overlaps(_lines(internal), _lines(internal)) is not None
    assert module._overlaps(internal, internal) is None
    text, summary, native_lines, ocr_lines, suppressed = reconciliation_plan(unit)
    assert summary['limit_reached'] and not summary['reconciled']
    assert summary['duplicate_ocr_lines_suppressed'] == 0
    assert native_lines == ocr_lines == [] and suppressed == set()
    assert text == unit['native_text'] + '\n\n' + unit['text']
    assert Counter(text.split()) == Counter(unit['native_text'].split() * 2)


def test_grid_entry_budget_is_shared_across_components_not_reset_per_component(monkeypatch):
    import app.pdf_reconciliation as module
    native = components()
    monkeypatch.setattr(module, 'MAX_GRID_ENTRIES', 6)
    for index in range(3):
        single = native[index * 2:index * 2 + 2]
        assert reconcile_page(page(single, deepcopy(single)))[1]['reconciled']
    unit = page(native, deepcopy(native))
    text, summary, native_lines, ocr_lines, suppressed = reconciliation_plan(unit)
    assert summary['limit_reached'] and not summary['reconciled']
    assert native_lines == ocr_lines == [] and not suppressed
    assert Counter(text.split()) == Counter(unit['native_text'].split() * 2)


def test_ambiguous_component_does_not_prevent_safe_suppression_in_separate_component():
    native = [word('EXACT100', y=.1), word('NATIVE200', y=.4, block=2)]
    ocr = [word('EXACT100', y=.1), word('CONFLICT300', y=.4, block=2),
           word('OCR_ONLY400', y=.7, block=3)]
    unit = page(native, ocr)
    text, summary, _, _, suppressed = reconciliation_plan(unit)
    assert suppressed == {0}
    assert summary['duplicate_ocr_lines_suppressed'] == 1
    assert summary['conflicting_ocr_lines'] == 1 and not summary['reconciled']
    assert Counter(text.split()) == {'EXACT100': 1, 'NATIVE200': 1, 'CONFLICT300': 1, 'OCR_ONLY400': 1}
    result = canonical_document_channels(extraction(unit))
    assert [item['channel'] for item in result.channels] == ['native', 'ocr']
    assert all(not item['coordinate_eligible'] for item in result.channels)
    assert result.channels[1]['text'].split() == ['CONFLICT300', 'OCR_ONLY400']


def test_group_indexing_preserves_nonconsecutive_block_and_line_identities():
    native = [word('FIRST100', block=9, line=800), word('SECOND200', x=.6, block=3, line=7),
              word('THIRD300', y=.5, block=9, line=2)]
    ocr = deepcopy(native)
    for item in ocr[:2]:
        item.update(block=22, line=4)
    ocr[2].update(block=50, line=99)
    unit = page(native, ocr)
    text, summary, _, _, suppressed = reconciliation_plan(unit)
    assert summary['reconciled'] and suppressed == {0, 1}
    assert text.split() == ['FIRST100', 'SECOND200', 'THIRD300']
    result = canonical_document_channels(extraction(unit))
    assert [(item['block'], item['line']) for item in result.channels[0]['words']] == [(9, 800), (3, 7), (9, 2)]


def test_retained_metadata_and_transient_container_repr_do_not_include_source_geometry_or_values():
    native = components()
    unit = page(native, deepcopy(native))
    original = deepcopy(unit)
    extracted = extraction(unit)
    result = canonical_document_channels(extracted)
    serialized = json.dumps(extracted.metadata)
    assert unit == original
    assert 'PRIVATE' not in serialized and 'VALUE' not in serialized
    assert all(key not in serialized for key in ('native_words', 'ocr_words', '"box"', '"left"', '"right"'))
    assert 'PRIVATE' not in repr(extracted) and 'PRIVATE' not in repr(result)
    assert 'native_words' not in repr(result) and 'left' not in repr(result)
