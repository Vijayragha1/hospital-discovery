"""Conservative, transient record candidates within ONE original word channel.

An explicit patient field and spatial continuity make a heuristic candidate, not
proof of patient identity or hospital-validated accuracy. The caller must retain
the detector's ambiguous-identity gate and classify residual regions unlinked.
Text, boxes, indices and spans are transient processing inputs, not report data.
No patient value is inserted, normalized, deduplicated or placed in an error.
"""
from __future__ import annotations

import math
import re
from collections import defaultdict
from statistics import median


POLICY = "explicit_patient_fields_geometry_v1"
MAX_WORDS = 10_000
MAX_CHARACTERS = 250_000
MAX_OVERLAP_PAIRS = 100_000
MAX_GRID_ENTRIES = 100_000

_FIELD = re.compile(
    r"^(?P<label>medical\s+record\s+(?:number|no)|patient[ _-]+(?:name|id|number|no|aadhaar)|"
    r"mrn|uhid|abha(?:[ _-]+(?:number|no|id|address))?|patient)"
    r"(?=$|\s|[:#=])(?P<separator>\s*[:#=]?\s*)(?P<value>.*)$", re.I)
_ANY_FIELD = re.compile(r"\b(?:mrn|uhid|abha|patient[ _-]+(?:name|id|number|no|aadhaar))\b", re.I)
_NAME_BOUNDARY = re.compile(r"\bpatient[ _-]+name\b", re.I)
_EXPLICIT_FIELD = re.compile(
    r"\b(?:medical\s+record\s+(?:number|no)|patient(?:[ _-]+(?:name|id|number|no|aadhaar|abha))?|"
    r"mrn|uhid|abha(?:[ _-]+(?:number|no|id|address))?)\s*[:#=]", re.I)
_NONPATIENT = re.compile(
    r"^(?:research|general\s+information|patient\s+education|references|administrative|"
    r"signature|doctor|dr\.?|consultant|physician|relative|attendant|record|case)(?=\s|:|$)", re.I)
_ROLE_REFERENCE = re.compile(
    r"\b(?:doctor|consultant|physician|relative|mother|father|wife|husband|spouse|"
    r"sibling|brother|sister|attendant|previous\s+patient)\b.*\b(?:mrn|uhid|abha|patient[ _-]+id)\b", re.I)
_HEADER_QUALIFIER = re.compile(
    r"\b(?:previous|prior|doctor|consultant|physician|relative|mother|father|wife|husband|"
    r"spouse|sibling|brother|sister|attendant)\b", re.I)
_UNKNOWN_PATIENT_FIELD = re.compile(r"^patient\b.*[:#=]", re.I)
_PLACEHOLDERS = {"unknown", "unreadable", "redacted", "unavailable", "none", "nil", "null", "na", "n/a"}
_HEADER_WORDS = {"patient", "name", "id", "number", "no", "mrn", "uhid", "abha", "diagnosis",
                 "diagnoses", "clinical", "notes", "medication", "prescription", "result", "results"}
_CLINICAL_HEADERS = {"diagnosis", "diagnoses", "clinical", "medication", "prescription", "result", "results"}


def _checked(words):
    if not isinstance(words, list) or len(words) > MAX_WORDS:
        raise ValueError("document_layout_word_limit_or_invalid_input")
    checked, characters = [], 0
    for index, word in enumerate(words):
        if not isinstance(word, dict):
            raise ValueError("document_layout_invalid_word")
        token = word.get("text")
        if not isinstance(token, str) or not token or len(token) > 4096 or any(c.isspace() for c in token):
            raise ValueError("document_layout_invalid_word")
        characters += len(token)
        if characters > MAX_CHARACTERS:
            raise ValueError("document_layout_character_limit")
        box = tuple(word.get(k) for k in ("left", "top", "right", "bottom"))
        if (any(type(n) not in (int, float) or not math.isfinite(n) or not 0 <= n <= 1 for n in box)
                or box[0] >= box[2] or box[1] >= box[3]
                or any(type(word.get(k)) is not int or not 1 <= word[k] <= 1_000_000 for k in ("block", "line"))):
            raise ValueError("document_layout_invalid_geometry")
        checked.append({"index": index, "text": token, "box": box,
                        "block": word["block"], "line": word["line"]})
    return checked


def _box(words):
    return [min(w["box"][0] for w in words), min(w["box"][1] for w in words),
            max(w["box"][2] for w in words), max(w["box"][3] for w in words)]


def _sort_word(word):
    l, t, r, b = word["box"]
    return ((t + b) / 2, l, t, r, b, word["text"], word["block"], word["line"])


def _bands(words, height):
    """Spatial lines independent of OCR reading order and paragraph block IDs."""
    result = []
    for word in sorted(words, key=_sort_word):
        center = (word["box"][1] + word["box"][3]) / 2
        if result and abs(center - result[-1]["center"]) <= .45 * height:
            result[-1]["words"].append(word)
        else:
            result.append({"center": center, "words": [word]})
    for band in result:
        band["words"].sort(key=lambda w: (w["box"][0], *_sort_word(w)))
        band["box"] = _box(band["words"])
        band["text"] = " ".join(w["text"] for w in band["words"])
    return result


def _runs(band, height):
    runs = [[]]
    for word in band["words"]:
        if runs[-1] and word["box"][0] - runs[-1][-1]["box"][2] >= 4 * height:
            runs.append([])
        runs[-1].append(word)
    return [{"words": run, "box": _box(run), "text": " ".join(w["text"] for w in run)} for run in runs]


def _overlaps(words):
    """Bound candidate comparisons; no unbounded all-pairs geometry work."""
    grid, overlap, pairs, entries = defaultdict(list), set(), 0, 0
    for word in sorted(words, key=lambda w: (w["box"][0], *_sort_word(w))):
        l, t, r, b = word["box"]
        cells = [(x, y) for x in range(min(31, int(l * 32)), min(31, int(r * 32)) + 1)
                       for y in range(min(31, int(t * 32)), min(31, int(b * 32)) + 1)]
        candidates = {other["index"]: other for cell in cells for other in grid[cell]}
        for other in candidates.values():
            pairs += 1
            if pairs > MAX_OVERLAP_PAIRS:
                return overlap, True
            if (min(r, other["box"][2]) > max(l, other["box"][0])
                    and min(b, other["box"][3]) > max(t, other["box"][1])):
                overlap.update((word["index"], other["index"]))
        entries += len(cells)
        if entries > MAX_GRID_ENTRIES:
            return overlap, True
        for cell in cells:
            grid[cell].append(word)
    return overlap, False


def _header(text):
    match = _FIELD.match(text)
    if not match:
        return None
    label, value = match["label"].lower(), match["value"].strip()
    name = label in {"patient", "patient name", "patient_name", "patient-name"}
    if label == "patient" and not any(c in match["separator"] for c in ":#="):
        return None
    kind = "name" if name else "uhid" if label == "uhid" else "abha" if label.startswith("abha") else "mrn"
    first = value.split()[0].strip("\"':#=;,.") if value else ""
    if first.lower() in _PLACEHOLDERS or first.lower() in _HEADER_WORDS:
        plausible = False
    elif name:
        plausible = len(first) > 1 and any(c.isalpha() for c in first)
    elif kind == "abha" and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{1,49}@(?:abdm|sbx)", first, re.I):
        plausible = True
    else:
        plausible = bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9/_@.\-]{1,63}", first)) and any(c.isdigit() for c in first)
    return {"kind": kind, "plausible": plausible,
            "anchor_word_count": len(text.split()) if name else len(text[:match.start("value")].split()) + 1}


def _table_header(bands):
    for band in bands:
        tokens = [re.sub(r"[^a-z]", "", w["text"].lower()) for w in band["words"]]
        tokens = [token for token in tokens if token]
        if (tokens and all(token in _HEADER_WORDS for token in tokens)
                and set(tokens) & {"patient", "mrn", "uhid", "abha"}
                and set(tokens) & _CLINICAL_HEADERS):
            return True
    return False


def _gutter(bands, height):
    """Find an empty x interval supported by at least two independent lines."""
    events = []
    for index, band in enumerate(bands):
        for first, second in zip(band["words"], band["words"][1:]):
            left, right = first["box"][2], second["box"][0]
            if right - left >= 4 * height:
                events.extend(((left, 1, index), (right, -1, index)))
    events.sort()
    active, best = set(), None
    for position, (x, action, band_index) in enumerate(events):
        if action == 1:
            active.add(band_index)
        else:
            active.discard(band_index)
        if position + 1 == len(events):
            continue
        right = events[position + 1][0]
        if len(active) < 2 or right - x < 2 * height:
            continue
        top = min(bands[i]["box"][1] for i in active)
        bottom = max(bands[i]["box"][3] for i in active)
        score = (len(active), right - x, bottom - top, -x)
        if best is None or score > best[0]:
            best = (score, (x + right) / 2, top, bottom)
    return best[1:] if best else None


def _region(lines, candidate, reason):
    words, spans, parts, offset = [], [], [], 0
    for line in lines:
        if parts:
            parts.append("\n")
            offset += 1
        for index, word in enumerate(line["words"]):
            if index:
                parts.append(" ")
                offset += 1
            start = offset
            parts.append(word["text"])
            offset += len(word["text"])
            spans.append({"index": word["index"], "start": start, "end": offset})
            words.append(word)
    return {"kind": "record" if candidate else "residual", "association_candidate": candidate,
            "reason": reason, "text": "".join(parts), "word_indices": [w["index"] for w in words],
            "word_spans": spans, "box": _box(words)}


def _residual_lines(bands, reason, height):
    return [_region([run], False, reason) for band in bands for run in _runs(band, height)]


def _lane(words, height):
    regions, current, kinds, plausible = [], [], set(), False
    body_seen = False

    def finish():
        nonlocal current, kinds, plausible, body_seen
        if current:
            regions.append(_region(current, plausible, "explicit_patient_field" if plausible else "unreadable_patient_header"))
        current, kinds, plausible, body_seen = [], set(), False, False

    for band in _bands(words, height):
        runs = _runs(band, height)
        if len(runs) > 1:
            finish()
            regions.extend(_region([run], False, "unresolved_horizontal_layout") for run in runs)
            continue
        line = runs[0]
        header = _header(line["text"])
        # A second name header in one unsplit spatial line cannot safely share
        # the earlier identifier. Retain it rather than inventing a split point.
        if (any(match.start() > 0 for match in _NAME_BOUNDARY.finditer(line["text"]))
                or len(_EXPLICIT_FIELD.findall(line["text"])) > 1):
            finish()
            regions.append(_region([line], False, "unresolved_patient_headers"))
            continue
        if (_ROLE_REFERENCE.search(line["text"])
                or (header is not None and _HEADER_QUALIFIER.search(line["text"]))
                or (header is None and (_ANY_FIELD.search(line["text"])
                                        or _UNKNOWN_PATIENT_FIELD.match(line["text"])))):
            finish()
            regions.append(_region([line], False, "narrative_patient_reference"))
            continue
        if _NONPATIENT.match(line["text"]):
            finish()
            regions.append(_region([line], False, "nonpatient_section"))
            continue
        if current:
            previous = current[-1]["box"]
            anchor = current[0].get("anchor_box", current[0]["box"])
            if line["box"][1] - previous[3] > 1.5 * height:
                finish()
            elif abs(line["box"][0] - anchor[0]) > 2 * height:
                # A long name/header can extend into a neighbouring column.
                # Overlap with its full width does not establish continuity.
                finish()
        if header:
            # Unrelated words sharing a spatial line cannot widen the identity
            # field's footprint and pull a neighbouring column into this record.
            line["anchor_box"] = _box(line["words"][:header["anchor_word_count"]])
            # A name header always starts a new record. Other adjacent, distinct
            # demographic fields may belong together; the detector still rejects
            # conflicting identifiers. Once body text began, every header splits.
            if current and (header["kind"] == "name" or header["kind"] in kinds or body_seen
                            or not plausible or not header["plausible"]):
                finish()
            if not current:
                plausible = header["plausible"]
            current.append(line)
            kinds.add(header["kind"])
        elif current:
            current.append(line)
            body_seen = True
        else:
            regions.append(_region([line], False, "unlabelled_content"))
    finish()
    return regions


def segment_words(words):
    """Return a lossless partition of one validated original-unit text channel.

    Headered tables are deliberately residual until cell/row boundary fixtures
    support an independent table policy. No caller should promote a candidate to
    patient-linked health without the detector's own unique-patient anchor check.
    """
    checked = _checked(words)
    regions, limited, lane_count, table = [], False, 0, False
    overlap = set()
    if checked:
        height = median(w["box"][3] - w["box"][1] for w in checked)
        bands = _bands(checked, height)
        overlap, limited = _overlaps(checked)
        table = _table_header(bands)
        if limited or overlap or table:
            reason = "layout_limit" if limited else "overlapping_words" if overlap else "unverified_table_layout"
            regions = _residual_lines(bands, reason, height)
        else:
            gutter = _gutter(bands, height)
            if gutter:
                x, top, bottom = gutter
                crossing = [w for w in checked if w["box"][0] < x < w["box"][2]]
                if any(w["box"][1] < bottom and w["box"][3] > top for w in crossing):
                    regions = _residual_lines(bands, "crossing_column_gutter", height)
                else:
                    left = [w for w in checked if w["box"][2] <= x]
                    right = [w for w in checked if w["box"][0] >= x]
                    regions = _lane(left, height) + _lane(right, height)
                    if crossing:
                        regions.extend(_residual_lines(_bands(crossing, height), "unlabelled_content", height))
                    lane_count = 2
            else:
                regions = _lane(checked, height)
                lane_count = 1
    regions.sort(key=lambda r: (r["box"][1], r["box"][0], r["box"][3], r["box"][2], r["text"]))
    if sorted(index for region in regions for index in region["word_indices"]) != list(range(len(checked))):
        raise ValueError("document_layout_partition_failed")
    candidates = sum(region["association_candidate"] for region in regions)
    return {"policy": POLICY, "regions": regions, "word_count": len(checked),
            "candidate_regions": candidates, "residual_regions": len(regions) - candidates,
            "lane_count": lane_count, "overlapping_words": len(overlap),
            "table_layout_detected": table, "limit_reached": limited}
