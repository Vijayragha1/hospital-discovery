from app.extraction import _xhtml_text


def test_hocr_frames_and_words_remain_distinct_from_native_text():
    text, pages = _xhtml_text('''<html><head><title>ignored</title></head><body>
      <p>MRN: NATIVE123</p>
      <div class="ocr_page" id="page_1"><span class="ocrx_word">MRN:</span><span class="ocrx_word">FRAME123</span></div>
      <div class="ocr_page" id="page_2"><span class="ocrx_word">Diagnosis:</span><span class="ocrx_word">diabetes</span></div>
    </body></html>''')
    parts = [part.strip() for part in text.split('\f')]
    assert pages == 2
    assert parts == ['MRN: NATIVE123', 'MRN: FRAME123', 'Diagnosis: diabetes']
    assert 'ignored' not in text


def test_native_pdf_and_hocr_page_markers_each_preserve_boundaries():
    text, pages = _xhtml_text('<div class="page">native</div><div class="ocr_page">frame</div>')
    assert pages == 2
    assert text.split('\f') == ['native', 'frame']


def test_empty_hocr_frame_cannot_join_neighbors():
    text, pages = _xhtml_text('<div class="ocr_page">first</div><div class="ocr_page"></div><div class="ocr_page">third</div>')
    assert pages == 3
    assert text.split('\f') == ['first', '', 'third']


def test_word_separation_does_not_break_ordinary_native_inline_spans():
    text, pages = _xhtml_text('<p>demo@<span>example</span>.test</p>')
    assert text == 'demo@example.test' and pages == 0
