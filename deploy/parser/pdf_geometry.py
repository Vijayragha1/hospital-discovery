"""Strict transient word geometry. No source text deduplication is performed."""
import csv
import io
import math
import re
import xml.etree.ElementTree as ET

MAX_GEOMETRY_BYTES = 4 * 1024 * 1024
MAX_WORDS = 10_000
MAX_WORD_CHARACTERS = 250_000


class GeometryError(ValueError):
    pass


def _number(value):
    try:
        result = float(value)
    except (TypeError, ValueError):
        raise GeometryError("geometry_invalid") from None
    if not math.isfinite(result):
        raise GeometryError("geometry_invalid")
    return result


def _tag(element):
    return element.tag.rsplit("}", 1)[-1]


def _word(text, box, width, height, block, line):
    left, top, right, bottom = map(_number, box)
    if not text or len(text) > 512 or any(character.isspace() or ord(character) < 32 or 127 <= ord(character) <= 159 for character in text):
        raise GeometryError("geometry_text_unverified")
    if not 0 <= left < right <= width or not 0 <= top < bottom <= height:
        raise GeometryError("geometry_invalid")
    return {"text": text, "left": left / width, "top": top / height,
            "right": right / width, "bottom": bottom / height, "block": block, "line": line}


def _limits(words):
    if len(words) > MAX_WORDS or sum(len(word["text"]) for word in words) > MAX_WORD_CHARACTERS:
        raise GeometryError("geometry_limit")


def native_words(data):
    if len(data) > MAX_GEOMETRY_BYTES:
        raise GeometryError("geometry_limit")
    # Poppler emits a fixed external XHTML doctype. ElementTree does not fetch
    # it. Reject entity declarations and internal subsets before XML parsing.
    if b"<!ENTITY" in data.upper() or re.search(br"<!DOCTYPE[^>]*\[", data, re.I):
        raise GeometryError("geometry_invalid")
    try:
        root = ET.fromstring(data)
    except (ET.ParseError, ValueError):
        raise GeometryError("geometry_invalid") from None
    pages = [element for element in root.iter() if _tag(element) == "page"]
    if len(pages) != 1:
        raise GeometryError("geometry_invalid")
    page = pages[0]
    width, height = _number(page.get("width")), _number(page.get("height"))
    if width <= 0 or height <= 0:
        raise GeometryError("geometry_invalid")
    words, seen = [], set()
    blocks = [element for element in page.iter() if _tag(element) == "block"]
    if len(blocks) > MAX_WORDS:
        raise GeometryError("geometry_limit")
    for block_number, block in enumerate(blocks, 1):
        lines = [element for element in block if _tag(element) == "line"]
        for line_number, line in enumerate(lines, 1):
            for element in line:
                if _tag(element) != "word" or list(element):
                    raise GeometryError("geometry_invalid")
                seen.add(id(element))
                words.append(_word(element.text or "", [element.get(key) for key in ("xMin", "yMin", "xMax", "yMax")],
                                   width, height, block_number, line_number))
                if len(words) > MAX_WORDS:
                    raise GeometryError("geometry_limit")
    if len(seen) != sum(_tag(element) == "word" for element in page.iter()):
        raise GeometryError("geometry_invalid")
    _limits(words)
    return width, height, words


def ocr_words(data, width, height):
    if len(data) > MAX_GEOMETRY_BYTES:
        raise GeometryError("geometry_limit")
    try:
        decoded = data.decode("utf-8", errors="strict")
        rows = csv.DictReader(io.StringIO(decoded), delimiter="\t", quoting=csv.QUOTE_NONE)
        if rows.fieldnames != ["level", "page_num", "block_num", "par_num", "line_num", "word_num", "left", "top", "width", "height", "conf", "text"]:
            raise GeometryError("geometry_invalid")
        words, block_ids, line_ids, sequence, pages = [], {}, {}, set(), 0
        for row_number, row in enumerate(rows):
            if row_number > MAX_WORDS * 5 or None in row:
                raise GeometryError("geometry_limit")
            level = int(row["level"])
            if not 1 <= level <= 5 or int(row["page_num"]) != 1:
                raise GeometryError("geometry_invalid")
            if level == 1:
                pages += 1
                if any(int(row[key]) != expected for key, expected in (("left", 0), ("top", 0), ("width", width), ("height", height))):
                    raise GeometryError("geometry_invalid")
            if level != 5 or not row["text"]:
                continue
            block, paragraph, line, word = [int(row[key]) for key in ("block_num", "par_num", "line_num", "word_num")]
            if min(block, paragraph, line, word) <= 0 or max(block, paragraph, line, word) > MAX_WORDS:
                raise GeometryError("geometry_invalid")
            identity = (block, paragraph, line, word)
            if identity in sequence:
                raise GeometryError("geometry_invalid")
            sequence.add(identity)
            block_key = (block, paragraph)
            block_id = block_ids.setdefault(block_key, len(block_ids) + 1)
            lines = line_ids.setdefault(block_key, {})
            line_id = lines.setdefault(line, len(lines) + 1)
            left, top = _number(row["left"]), _number(row["top"])
            words.append(_word(row["text"], (left, top, left + _number(row["width"]), top + _number(row["height"])),
                               width, height, block_id, line_id))
            if len(words) > MAX_WORDS:
                raise GeometryError("geometry_limit")
        if pages != 1:
            raise GeometryError("geometry_invalid")
        _limits(words)
        return words
    except (KeyError, TypeError, ValueError, UnicodeDecodeError, csv.Error) as error:
        if isinstance(error, GeometryError):
            raise
        raise GeometryError("geometry_invalid") from None


def verified_mapping(info, ordinal, width, height, pixel_width, pixel_height):
    try:
        text = info.decode("utf-8", errors="strict")
        number = r"([+-]?(?:\d+(?:\.\d*)?|\.\d+))"
        boxes = []
        for label in ("MediaBox", "CropBox"):
            found = re.search(r"^(?:Page\s+" + str(ordinal) + r"\s+)?" + label + r":\s*" + r"\s+".join([number] * 4) + r"\s*$", text, re.M)
            if not found:
                return False
            boxes.append(tuple(map(float, found.groups())))
        rotation = re.search(r"^Page(?:\s+" + str(ordinal) + r")?\s+rot:\s*(-?\d+)\s*$", text, re.M)
        # pdfinfo -box prints coordinates with two decimal places, whereas
        # pdftotext bbox emits six. Compare that displayed precision, not an
        # arbitrary wider tolerance: A4 is 595.28 vs 595.275600, for example.
        # Pixel dimensions and rectangle bounds remain independently exact.
        same_displayed_size = (format(boxes[0][2], ".2f") == format(width, ".2f")
                               and format(boxes[0][3], ".2f") == format(height, ".2f"))
        return (rotation is not None and int(rotation.group(1)) == 0 and boxes[0] == boxes[1]
                and boxes[0][:2] == (0, 0) and same_displayed_size
                and pixel_width == math.ceil(width * 200 / 72) and pixel_height == math.ceil(height * 200 / 72))
    except (ValueError, UnicodeDecodeError, OverflowError):
        return False


def word_lines(words):
    blocks = {}
    for word in words:
        blocks.setdefault(word["block"], {}).setdefault(word["line"], []).append(word["text"])
    return "\n\n".join("\n".join(" ".join(line) for line in block.values()) for block in blocks.values())
