"""Bounded, transient native/OCR reconciliation within one original PDF page.

Only complete overlapping line components with mutually unique, spatially
corresponding NFC words are coalesced. Extractors may group columns differently;
no partial OCR line or global text set is deleted. Distinct repeats survive.
Different overlapping text is retained in separate source-channel blocks and
keeps the page unresolved. No value, box or line text enters retained metadata.
This is observation reconciliation, not proof of complete PDF representation.
"""
from collections import OrderedDict, defaultdict
import math
import unicodedata

MAX_WORDS = 10000
MAX_WORD_CHARACTERS = 250000
MAX_GRID_ENTRIES = 100000
MAX_CANDIDATE_PAIRS = 100000


def _normalized(text):
    return unicodedata.normalize("NFC", " ".join(text.split()))


def _words(value, text):
    if not isinstance(value, list) or len(value) > MAX_WORDS:
        raise ValueError("invalid_pdf_word_inventory")
    characters = 0
    words = []
    for item in value:
        if not isinstance(item, dict):
            raise ValueError("invalid_pdf_word_inventory")
        token = item.get("text")
        if not isinstance(token, str) or not token or len(token) > 4096 or any(c.isspace() for c in token):
            raise ValueError("invalid_pdf_word_inventory")
        characters += len(token)
        if characters > MAX_WORD_CHARACTERS:
            raise ValueError("invalid_pdf_word_inventory")
        box = tuple(item.get(key) for key in ("left", "top", "right", "bottom"))
        if any(type(n) not in {int, float} or not math.isfinite(n) or not 0 <= n <= 1 for n in box):
            raise ValueError("invalid_pdf_word_inventory")
        if box[0] >= box[2] or box[1] >= box[3]:
            raise ValueError("invalid_pdf_word_inventory")
        if any(type(item.get(key)) is not int or not 1 <= item[key] <= 1000000 for key in ("block", "line")):
            raise ValueError("invalid_pdf_word_inventory")
        words.append({"text": token, "box": box, "block": item["block"], "line": item["line"]})
    if _normalized(" ".join(w["text"] for w in words)) != _normalized(text):
        raise ValueError("pdf_word_text_mismatch")
    return words


def _lines(words):
    lines = OrderedDict()
    previous = None
    closed = set()
    for word in words:
        key = (word["block"], word["line"])
        if key != previous:
            if key in closed:
                raise ValueError("noncontiguous_pdf_line")
            if previous is not None:
                closed.add(previous)
            previous = key
        lines.setdefault(key, []).append(word)
    result = []
    for (block, ordinal), members in lines.items():
        result.append({"block": block, "line": ordinal, "words": members,
            "text": " ".join(item["text"] for item in members),
            "box": (min(w["box"][0] for w in members), min(w["box"][1] for w in members),
                    max(w["box"][2] for w in members), max(w["box"][3] for w in members))})
    return result


def _overlap(a, b, horizontal=.1, vertical=.3):
    x = max(0, min(a[2], b[2]) - max(a[0], b[0]))
    y = max(0, min(a[3], b[3]) - max(a[1], b[1]))
    return (x >= horizontal * min(a[2] - a[0], b[2] - b[0]) and
            y >= vertical * min(a[3] - a[1], b[3] - b[1]))


def _same_word(x, y):
    return (unicodedata.normalize("NFC", x["text"]) == unicodedata.normalize("NFC", y["text"])
               and _overlap(x["box"], y["box"], .8, .7)
               and max(x["box"][2] - x["box"][0], y["box"][2] - y["box"][0]) <= 2 * min(x["box"][2] - x["box"][0], y["box"][2] - y["box"][0])
               and max(x["box"][3] - x["box"][1], y["box"][3] - y["box"][1]) <= 3 * min(x["box"][3] - x["box"][1], y["box"][3] - y["box"][1])
               and abs(x["box"][0] + x["box"][2] - y["box"][0] - y["box"][2]) <= min(x["box"][2] - x["box"][0], y["box"][2] - y["box"][0])
               and abs(x["box"][1] + x["box"][3] - y["box"][1] - y["box"][3]) <= min(x["box"][3] - x["box"][1], y["box"][3] - y["box"][1]))


def _same_line(a, b):
    return len(a["words"]) == len(b["words"]) and all(_same_word(x, y) for x, y in zip(a["words"], b["words"]))


def _cells(box):
    # Broad spatial buckets are only an index; exact boxes decide each pair.
    for x in range(int(box[0] * 32), min(31, int(box[2] * 32)) + 1):
        for y in range(int(box[1] * 32), min(31, int(box[3] * 32)) + 1):
            yield x, y


def _overlaps(native, ocr):
    grid = defaultdict(list)
    entries = 0
    for index, line in enumerate(native):
        for cell in _cells(line["box"]):
            entries += 1
            if entries > MAX_GRID_ENTRIES:
                return None
            grid[cell].append(index)
    native_links, ocr_links = defaultdict(set), defaultdict(set)
    checked = 0
    for index, line in enumerate(ocr):
        candidates = set()
        for cell in _cells(line["box"]):
            candidates.update(grid.get(cell, ()))
        for candidate in candidates:
            checked += 1
            if checked > MAX_CANDIDATE_PAIRS:
                return None
            if _overlap(line["box"], native[candidate]["box"]):
                native_links[candidate].add(index)
                ocr_links[index].add(candidate)
    return native_links, ocr_links


def _render(lines, omit=frozenset()):
    # Keep channel/block boundaries. Never concatenate unrelated native and OCR
    # fragments into a synthesized patient record or sort columns into one row.
    blocks = []
    previous = None
    current = []
    for index, line in enumerate(lines):
        if index in omit:
            if current:
                blocks.append("\n".join(current))
                current = []
            previous = None
            continue
        if previous is not None and line["block"] != previous:
            blocks.append("\n".join(current))
            current = []
        current.append(line["text"])
        previous = line["block"]
    if current:
        blocks.append("\n".join(current))
    return "\n\n".join(blocks)


def _component_suppression(native_lines, ocr_lines, native_words, ocr_words, line_links):
    """Prove a whole connected component without relying on reading order.

    Word candidates cover the entire page, including competitors outside a
    component's broad line boxes. A match must be unique in both directions.
    This prevents a short overlapping word outside those boxes from silently
    losing its competing observation. Work is bounded by the same grid caps.
    """
    word_links = _overlaps(native_words, ocr_words)
    if word_links is None:
        return None
    native_links, ocr_links = line_links
    native_word_links, ocr_word_links = word_links
    native_indices, ocr_indices = [], []
    for lines, result in ((native_lines, native_indices), (ocr_lines, ocr_indices)):
        start = 0
        for line in lines:
            result.append(range(start, start + len(line["words"])))
            start += len(line["words"])
    overlapping_ocr_lines = {index for index, words in enumerate(ocr_indices)
                             if any(ocr_word_links.get(word) for word in words)}
    suppressed, visited = set(), set()
    for root in ocr_links:
        if root in visited:
            continue
        natives, ocrs, pending = set(), set(), [root]
        while pending:
            index = pending.pop()
            if index in ocrs:
                continue
            ocrs.add(index)
            for candidate in ocr_links[index]:
                if candidate not in natives:
                    natives.add(candidate)
                    pending.extend(native_links[candidate] - ocrs)
        visited.update(ocrs)
        expected_native = {word for line in natives for word in native_indices[line]}
        expected_ocr = {word for line in ocrs for word in ocr_indices[line]}
        if len(expected_native) != len(expected_ocr):
            continue
        matched_native = set()
        for index in expected_ocr:
            candidates = ocr_word_links[index]
            if len(candidates) != 1:
                break
            candidate = next(iter(candidates))
            if (candidate not in expected_native or len(native_word_links[candidate]) != 1
                    or not _same_word(native_words[candidate], ocr_words[index])):
                break
            matched_native.add(candidate)
        else:
            if matched_native == expected_native:
                suppressed.update(ocrs)
    return suppressed, overlapping_ocr_lines


def reconciliation_plan(unit):
    """Return one transient plan shared by text rendering and layout transport.

    Only the second item is safe for retained metadata; lines and suppression
    indexes stay in process memory. Unknown/limited geometry supplies no plan.
    """
    native, ocr = unit.get("native_text", ""), unit.get("text", "")
    fallback = "\n\n".join(value.replace("\f", "\n") for value in (native, ocr) if value)
    summary = {"policy": "spatial_exact_components_v2", "geometry_verified": False,
        "reconciled": False, "native_lines": None, "ocr_lines": None,
        "duplicate_ocr_lines_suppressed": 0, "conflicting_ocr_lines": None,
        "limit_reached": False, "native_representation_verified": False}
    if unit.get("geometry_verified") is not True:
        return fallback, summary, [], [], set()
    native_words = _words(unit.get("native_words"), native)
    ocr_words = _words(unit.get("ocr_words"), ocr)
    if len(native_words) + len(ocr_words) > MAX_WORDS or sum(len(w["text"]) for w in native_words + ocr_words) > MAX_WORD_CHARACTERS:
        raise ValueError("invalid_pdf_word_inventory")
    native_lines, ocr_lines = _lines(native_words), _lines(ocr_words)
    summary.update(geometry_verified=True, native_lines=len(native_lines), ocr_lines=len(ocr_lines))
    links = _overlaps(native_lines, ocr_lines)
    if links is None:
        summary["limit_reached"] = True
        return fallback, summary, [], [], set()
    _, ocr_links = links
    proof = _component_suppression(native_lines, ocr_lines, native_words, ocr_words, links)
    if proof is None:
        summary["limit_reached"] = True
        return fallback, summary, [], [], set()
    suppressed, overlapping_ocr_lines = proof
    # Extractors can give a line an unusually tall/wide bounding box. A real
    # word conflict must remain visible even when the broad line overlap test
    # misses it; full reconciliation requires both views to have no conflict.
    conflicts = len((set(ocr_links) | overlapping_ocr_lines) - suppressed)
    processed = (unit.get("native_status") == unit.get("ocr_status") == "completed"
                 and unit.get("render_status") == "completed"
                 and unit.get("native_text_truncated") is False and unit.get("truncated") is False)
    summary.update(reconciled=processed and conflicts == 0,
        duplicate_ocr_lines_suppressed=len(suppressed), conflicting_ocr_lines=conflicts)
    text = "\n\n".join(part for part in (_render(native_lines), _render(ocr_lines, suppressed)) if part)
    return text, summary, native_lines, ocr_lines, suppressed


def reconcile_page(unit):
    """Return transient text and fixed counters, preserving uncertain channels."""
    text, summary, _, _, _ = reconciliation_plan(unit)
    return text, summary
