"""Bounded local extraction. Only opt-in detector evidence retains bounded text excerpts."""
from __future__ import annotations

import ipaddress
import csv
import io
import json
import os
import re
import socket
import unicodedata
from collections import Counter
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urlparse


TEXT_SUFFIXES = {".txt", ".csv", ".tsv", ".log", ".json", ".jsonl", ".xml", ".md", ".hl7"}
TIKA_SUFFIXES = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".ods",
                 ".rtf", ".eml", ".msg", ".html", ".htm", ".png", ".jpg", ".jpeg", ".tif", ".tiff", ".bmp"}
ARCHIVE_SUFFIXES = {".zip", ".7z", ".rar", ".gz", ".tar", ".bz2", ".xz", ".tgz", ".pst", ".mbox"}

_CSV_HEADER_NAMES = {"mrn", "uhid", "patient_id", "patient id", "patient name", "patient_name", "name",
                     "first_name", "last_name", "diagnosis", "notes", "email", "phone", "dob", "abha",
                     "abha address", "insurance id", "id", "age", "gender", "address", "clinical notes"}


def structured_kind(text: str) -> str | None:
    """Recognize standalone structured values, including native database JSON cells."""
    beginning = text.lstrip()
    if beginning.startswith(("{", "[")):
        return "json"
    if re.match(r"<(?:\?xml\b|[A-Za-z_][\w:.-]*(?:\s|>|/))", beginning):
        return "xml"
    return None


def structured_text(text: str, kind: str, maximum: int = 1_000_000) -> tuple[str, str | None, dict]:
    """Render bounded sibling records separately; never inherit a parent patient ID.

    Only scalar fields in the same object/element are grouped. Parent/child clinical
    linkage is deliberately not inferred. Malformed/over-limit input is inspected
    as isolated field fragments and is explicitly partial, rather than flattened.
    """
    maximum = max(1, min(maximum, 10_000_000))
    reason = "structured_text_limit_reached" if len(text) > maximum else None
    bounded = text[:maximum]
    pieces, used, nodes = [], 0, 0

    def append(value):
        nonlocal used
        if not value.strip():
            return
        used += len(value) + bool(pieces)
        if used > maximum or len(pieces) >= 10000:
            raise ValueError("structured_limit")
        pieces.append(value)

    def checked(depth):
        nonlocal nodes
        nodes += 1
        if depth > 64 or nodes > 100000:
            raise ValueError("structured_limit")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate_json_key")
            result[key] = value
        return result

    def scalar(value):
        return value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)

    def parsed_nested(value):
        if structured_kind(value) == "xml":
            from defusedxml import ElementTree
            return "xml", ElementTree.fromstring(value, forbid_dtd=True, forbid_entities=True, forbid_external=True)
        return "json", json.loads(value, object_pairs_hook=pairs)

    def nested_record(kind, value, depth):
        if kind == "xml":
            xml_records(value, depth)
        else:
            json_records(value, depth)

    def json_records(value, depth=0):
        checked(depth)
        if isinstance(value, dict):
            fields = []
            nested = []
            for key, item in value.items():
                if isinstance(item, (dict, list)):
                    nested.append(("json", item))
                elif isinstance(item, str) and structured_kind(item):
                    # Serialized records inside a JSON string are also independent.
                    nested.append(parsed_nested(item))
                else:
                    fields.append(json.dumps(key, ensure_ascii=False) + ": " + scalar(item))
            append(" | ".join(fields))
            for kind, item in nested:
                nested_record(kind, item, depth + 1)
        elif isinstance(value, list):
            for item in value:
                json_records(item, depth + 1)
        else:
            append(scalar(value))

    def xml_records(element, depth=0):
        checked(depth)
        name = lambda tag: tag.rsplit("}", 1)[-1].rsplit(":", 1)[-1]
        fields = [name(key) + ": " + value for key, value in element.attrib.items()]
        embedded = []
        if element.text and element.text.strip():
            if structured_kind(element.text):
                embedded.append(parsed_nested(element.text))
            else:
                fields.append(name(element.tag) + ": " + element.text)
        children = list(element)
        repeated = {tag for tag, count in Counter(child.tag for child in children).items() if count > 1}
        nested = []
        for child in children:
            if not len(child) and not child.attrib and child.tag not in repeated:
                checked(depth + 1)
                if child.text:
                    if structured_kind(child.text):
                        embedded.append(parsed_nested(child.text))
                    else:
                        fields.append(name(child.tag) + ": " + child.text)
            else:
                nested.append(child)
        append(" | ".join(fields))
        for child in nested:
            xml_records(child, depth + 1)
        for kind, item in embedded:
            nested_record(kind, item, depth + 1)
        for child in children:
            if child.tail:
                append(child.tail)

    try:
        if reason:
            raise ValueError("structured_limit")
        if kind == "json":
            json_records(json.loads(bounded, object_pairs_hook=pairs))
        elif kind == "jsonl":
            for line in bounded.splitlines():
                if line.strip():
                    json_records(json.loads(line, object_pairs_hook=pairs))
        elif kind == "xml":
            from defusedxml import ElementTree
            xml_records(ElementTree.fromstring(bounded, forbid_dtd=True, forbid_entities=True, forbid_external=True))
        else:
            raise ValueError("invalid_structured_format")
    except Exception:
        reason = reason or "structured_record_boundaries_unverified"
        # Every delimiter becomes a boundary, including malformed single-line data.
        # This fallback may miss matches but cannot join one field to another.
        fragments = re.sub(r"</[^>]*>", "\f", bounded)
        fragments = re.sub(r"<([A-Za-z_][\w:.-]*)[^>]*>", lambda m: "\f" + m[1] + ": ", fragments)
        fragments = re.sub(r"[{}\[\],<>]|\\[nrtf]", "\f", fragments)
        pieces = fragments.split("\f")
    rendered = "\f".join(piece for piece in pieces if piece.strip())
    if len(rendered) > maximum:
        rendered = rendered[:maximum]
        reason = reason or "structured_text_limit_reached"
    return rendered, reason, {"segmentation": kind + "_object_boundaries", "structured_boundaries_verified": reason is None,
                              "parent_child_patient_linkage_inferred": False}


class _TikaXHTML(HTMLParser):
    """Retain page/row/block boundaries without rendering markup or fetching links."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self.page_boundaries = 0
        self._ignored = 0

    def handle_starttag(self, tag, attrs):
        if tag in {"head", "script", "style"}:
            self._ignored += 1
        if self._ignored:
            return
        classes = dict(attrs).get("class", "") or ""
        if tag == "div" and {"page", "ocr_page"}.intersection(classes.split()):
            self.parts.append("\f")
            self.page_boundaries += 1
        elif tag == "tr":
            self.parts.append("\f")
        elif tag in {"p", "section", "h1", "h2", "h3"}:
            self.parts.append("\n\n")
        elif tag == "br":
            self.parts.append("\n")
        elif tag in {"td", "th"}:
            self.parts.append("\t")
        elif tag == "span" and "ocrx_word" in classes.split():
            # hOCR words are discrete tokens even when adjacent markup lacks
            # whitespace. Do not apply this rule to arbitrary native HTML spans.
            self.parts.append(" ")

    def handle_endtag(self, tag):
        if tag in {"head", "script", "style"}:
            self._ignored = max(0, self._ignored - 1)
            return
        if self._ignored:
            return
        if tag in {"p", "section", "h1", "h2", "h3"}:
            self.parts.append("\n\n")
        elif tag == "tr":
            self.parts.append("\f")

    def handle_data(self, data):
        if not self._ignored:
            self.parts.append(data)


def _xhtml_text(content: str) -> tuple[str, int]:
    parser = _TikaXHTML()
    parser.feed(content)
    parser.close()
    return "".join(parser.parts).strip(" \n\r\t\f"), parser.page_boundaries


class _TikaPDFPages(_TikaXHTML):
    """Keep empty original page elements and text outside them explicit."""
    def __init__(self):
        super().__init__()
        self.depth = 0
        self.active = None
        self.pages = []
        self.ranges = []
        self.valid = True

    def handle_starttag(self, tag, attrs):
        before = len(self.parts)
        super().handle_starttag(tag, attrs)
        if tag == 'div':
            self.depth += 1
            if 'page' in (dict(attrs).get('class', '') or '').split():
                if self.active is not None:
                    self.valid = False
                else:
                    self.active = (self.depth, before, len(self.parts))

    def handle_endtag(self, tag):
        super().handle_endtag(tag)
        if tag == 'div':
            if self.active is not None and self.active[0] == self.depth:
                _, before, start = self.active
                self.pages.append(''.join(self.parts[start:]))
                self.ranges.append((before, len(self.parts)))
                self.active = None
            self.depth -= 1
            if self.depth < 0:
                self.valid = False

    def result(self):
        self.close()
        if self.active is not None or self.depth != 0:
            self.valid = False
        outside, start = [], 0
        for before, end in self.ranges:
            outside.extend(self.parts[start:before])
            start = end
        outside.extend(self.parts[start:])
        return self.pages, ''.join(outside), self.valid


def _pdf_supplement(content, native_pages):
    """Omit equal whole-page native observations, never global value sets.

    Tika can expose native text outside the page that Poppler omits. Keep every
    unmatched page, unknown mapping and non-page text as explicit fallback.
    Equality preserves ordered NFC tokens and repeats. It is not proof of
    original native representation or correct patient record layout.
    """
    parser = _TikaPDFPages()
    parser.feed(content)
    pages, outside, valid = parser.result()
    normalized = lambda text: unicodedata.normalize('NFC', ' '.join(text.split()))
    valid = valid and bool(pages) and len(pages) == len(native_pages)
    if not valid:
        text, _ = _xhtml_text(content)
        return text, {'tika_page_mapping_verified': False, 'tika_native_pages_suppressed': 0,
                      'tika_unmatched_native_pages': None, 'tika_nonpage_text_present': bool(outside.strip())}
    unmatched = [page for page, native in zip(pages, native_pages) if normalized(page) != normalized(native)]
    return '\f'.join([*unmatched, outside] if outside.strip() else unmatched), {
        'tika_page_mapping_verified': True, 'tika_native_pages_suppressed': len(pages) - len(unmatched),
        'tika_unmatched_native_pages': len(unmatched), 'tika_nonpage_text_present': bool(outside.strip())}


def _csv_text(text: str, suffix: str, maximum: int) -> tuple[str, dict]:
    """Keep the first record even when a header is inferred; bound header expansion."""
    import re
    records = csv.reader(io.StringIO(text), delimiter="\t" if suffix == ".tsv" else ",", strict=True)
    first = next(records, [])
    labels = [value.strip() for value in first]
    header = bool(labels) and all(re.fullmatch(r"[A-Za-z][A-Za-z_ -]{0,63}", value) for value in labels)
    header = header and any(value.lower() in _CSV_HEADER_NAMES for value in labels)
    pieces = []
    remaining = maximum + 1
    structured_cells = 0
    structured_verified = True

    def append(rendered):
        nonlocal remaining
        if pieces:
            pieces.append("\f")
            remaining -= 1
        pieces.append(rendered[:max(0, remaining)])
        remaining -= min(len(rendered), max(0, remaining))

    def append_row(row, labels=None):
        nonlocal structured_cells, structured_verified
        scalar_fields, nested = [], []
        for index, value in enumerate(row):
            kind = structured_kind(value)
            if kind:
                structured_cells += 1
                rendered, reason, _ = structured_text(value, kind, maximum)
                structured_verified &= reason is None
                nested.append(rendered)
            else:
                scalar_fields.append(f"{labels[index] if index < len(labels) else 'field'}: {value}" if labels else value)
        # Retain ordinary cells as one row record, while standalone nested JSON
        # or XML cells are independent. Never label them with the outer row ID.
        if scalar_fields:
            append(" | ".join(scalar_fields))
        for rendered in nested:
            if remaining <= 0:
                break
            if rendered:
                append(rendered)

    if first:
        append_row(first)
    if remaining > 0:
        for row in records:
            append_row(row, labels if header else None)
            if remaining <= 0:
                break
    return "".join(pieces), {"segmentation": "csv_record_boundaries", "header_inferred": bool(header),
                              "first_record_retained": True, "structured_cells": structured_cells,
                              "structured_cell_boundaries_verified": bool(structured_verified),
                              "outer_row_patient_linkage_inferred_for_nested_cells": False}


@dataclass
class ExtractionResult:
    text: str = field(default="", repr=False)
    status: str = "full"
    reason: str | None = None
    examined: int = 0
    unit: str = "characters"
    metadata: dict = field(default_factory=dict)
    # Transient native channel only; never put page text into object metadata.
    native_pages: list[str] | None = field(default=None, repr=False)
    # Private original-unit channels only. Geometry is not a patient boundary,
    # and Tika supplemental text has no asserted mapping into these coordinates.
    document_units: list[dict] | None = field(default=None, repr=False)


def private_host(host: str) -> bool:
    """Prevent patient-bearing requests to public addresses, including DNS results."""
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)}
        return bool(addresses) and all(
            (ipaddress.ip_address(address).is_private or ipaddress.ip_address(address).is_loopback)
            and not ipaddress.ip_address(address).is_unspecified
            and not ipaddress.ip_address(address).is_multicast
            for address in addresses
        )
    except (OSError, ValueError):
        return False


def extraction_capabilities() -> dict:
    return {"native_text_formats": sorted(TEXT_SUFFIXES), "tika_configured": bool(os.getenv("TIKA_URL")),
            "page_frame_ocr_configured": bool(os.getenv("PAGE_OCR_URL")),
            "ocr_language": "eng", "archives_enabled": False,
            "limitations": ["handwriting_not_supported", "tika_page_completeness_not_proven", "no_dicom_pipeline"]}


def _bounded(text: str, maximum: int, result: ExtractionResult) -> ExtractionResult:
    if len(text) > maximum:
        result.status, result.reason = "partial", "text_limit_reached"
        text = text[:maximum]
        result.metadata["text_truncated"] = True
        result.metadata["completeness_verified"] = False
        for unit in result.document_units or []:
            unit['coordinate_eligible'] = False
            unit['coordinate_reason'] = 'document_text_truncated'
    result.text = text
    result.metadata["returned_text_characters"] = len(text)
    if result.unit == "characters":
        result.examined = len(text)
    return result


def extract_bytes(data: bytes, suffix: str, options: dict | None = None) -> ExtractionResult:
    options = options or {}
    suffix = suffix.lower()
    maximum = max(1, min(int(options.get("max_text_chars", 1_000_000)), 10_000_000))
    if suffix in ARCHIVE_SUFFIXES:
        return ExtractionResult(status="excluded", reason="archive_scanning_disabled", unit="bytes")
    if suffix in TEXT_SUFFIXES:
        encoding = "utf-16" if data.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig"
        result = ExtractionResult(metadata={"extractor": "native_text", "encoding": encoding})
        try:
            text = data.decode(encoding)
        except UnicodeError:
            text = data.decode(encoding, errors="replace")
            result.status, result.reason = "partial", "encoding_replacement"
        if "\x00" in text:
            return ExtractionResult(status="unsupported", reason="binary_content_in_text_file", unit="bytes")
        # Preserve explicit record boundaries without persisting parsed values.
        if suffix in {".csv", ".tsv"}:
            try:
                text, metadata = _csv_text(text, suffix, maximum)
                result.metadata.update(metadata)
                if metadata["structured_cell_boundaries_verified"] is False:
                    result.status, result.reason = "partial", "csv_structured_cell_boundaries_unverified"
                    result.metadata["patient_linkage_context_verified"] = False
            except csv.Error:
                result.status, result.reason = "partial", "csv_structure_or_field_limit"
                result.metadata["patient_linkage_context_verified"] = False
                text = "\f".join(text.splitlines())
        elif suffix in {".json", ".jsonl", ".xml"}:
            text, structure_reason, metadata = structured_text(text, suffix[1:], maximum)
            result.metadata.update(metadata)
            if structure_reason:
                result.status, result.reason = "partial", structure_reason
        elif suffix == ".hl7":
            text = "\f".join(text.splitlines())
            result.metadata["segmentation"] = "source_record_lines"
        return _bounded(text, maximum, result)
    if suffix not in TIKA_SUFFIXES:
        return ExtractionResult(status="unsupported", reason="unsupported_file_format", unit="bytes")
    if os.getenv("PAGE_OCR_URL"):
        from .ocr_accounting import IMAGE_SUFFIXES, extract_accounted
        if suffix in IMAGE_SUFFIXES:
            # One canonical OCR channel, retaining every original frame boundary.
            accounted = extract_accounted(data, "image", maximum)
            # Frame completion does not prove that flattened OCR preserves the
            # layout of several patient records on the same printed page.
            accounted.metadata["patient_linkage_context_verified"] = False
            return accounted
        if suffix == ".pdf":
            accounted = extract_accounted(data, "pdf", maximum)
            if accounted.status == 'full':
                accounted.metadata['patient_linkage_context_verified'] = False
                return accounted
            native = _extract_tika(data, suffix, maximum, pdf_ocr=False, pdf_native_pages=accounted.native_pages)
            reconciled = bool(accounted.metadata.get('pdf_instance_channels_reconciled')
                and native.metadata.get('tika_page_mapping_verified')
                and native.metadata.get('tika_unmatched_native_pages') == 0
                and not native.text.strip())
            metadata = {**native.metadata, "page_ocr": accounted.metadata,
                        "native_parse_status": native.status, "native_parse_reason": native.reason,
                        "completeness_verified": False, "native_and_ocr_observations": True,
                        "ocr_may_duplicate_native_or_embedded_text": not reconciled,
                        "pdf_instance_channels_reconciled": reconciled,
                        "patient_linkage_context_verified": False,
                        "segment_numbers_are_extraction_ordinals": True}
            text = "\f".join(piece for piece in (accounted.text, native.text) if piece)
            reason = (accounted.reason if not accounted.metadata.get("page_accounting_complete")
                      else 'pdf_native_representation_and_nonpage_coverage_unverified' if reconciled
                      else "pdf_native_ocr_and_nonpage_coverage_unverified")
            status = "failed" if accounted.status == native.status == "failed" else "partial"
            return _bounded(text, maximum, ExtractionResult(status=status, reason=reason,
                examined=accounted.examined, unit="pages", metadata=metadata,
                native_pages=accounted.native_pages, document_units=accounted.document_units))
    return _extract_tika(data, suffix, maximum)


def _extract_tika(data: bytes, suffix: str, maximum: int, *, pdf_ocr: bool = True,
                  pdf_native_pages: list[str] | None = None) -> ExtractionResult:
    tika_url = os.getenv("TIKA_URL", "").rstrip("/")
    if not tika_url:
        return ExtractionResult(status="unsupported", reason="tika_not_configured", unit="bytes")
    parsed = urlparse(tika_url)
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or not private_host(parsed.hostname)):
        return ExtractionResult(status="failed", reason="tika_endpoint_not_private", unit="bytes")
    try:
        import requests
    except ImportError:
        return ExtractionResult(status="failed", reason="requests_dependency_missing", unit="bytes")
    headers = {"Accept": "application/json", "Content-Type": "application/octet-stream",
               "X-Tika-PDFOcrStrategy": "ocr_and_text" if pdf_ocr else "no_ocr", "X-Tika-OCRLanguage": "eng",
               "X-Tika-OCROutputType": "hocr",
               "X-Tika-OCRskipOcr": "false", "X-Tika-PDFextractInlineImages": "true",
               "writeLimit": str(maximum), "maxEmbeddedResources": "100"}
    if suffix == ".pdf":
        headers["Content-Type"] = "application/pdf"
        if pdf_native_pages is not None:
            # Align spatial reading order for the exact same-page comparison.
            # This never changes the equality gate or suppresses repeats, and
            # sorted Tika text itself remains ineligible for patient linkage.
            headers["X-Tika-PDFsortByPosition"] = "true"
            headers["X-Tika-PDFsuppressDuplicateOverlappingText"] = "false"
    try:
        with requests.Session() as session:
            session.trust_env = False  # Never inherit an outbound proxy or .netrc credentials.
            # /rmeta returns XHTML containing PDF page elements. /rmeta/text flattens
            # those boundaries and can incorrectly combine different patients.
            with session.put(tika_url + "/rmeta", data=data, headers=headers, timeout=(5, 60),
                             allow_redirects=False, stream=True) as response:
                if response.status_code != 200:
                    return ExtractionResult(status="failed", reason="tika_parse_failed", unit="bytes")
                body = bytearray()
                response_limit = maximum * 8 + 65536
                for chunk in response.iter_content(65536):
                    body.extend(chunk)
                    if len(body) > response_limit:
                        return ExtractionResult(status="partial", reason="tika_response_limit_reached", unit="bytes")
                payload = json.loads(body)
        if not isinstance(payload, list) or not all(isinstance(item, dict) for item in payload):
            return ExtractionResult(status="failed", reason="tika_response_invalid", unit="bytes")
        pieces = [item.get("X-TIKA:content", "") for item in payload]
        if not all(isinstance(piece, str) for piece in pieces):
            return ExtractionResult(status="failed", reason="tika_response_invalid", unit="bytes")
        structured = [_xhtml_text(piece) for piece in pieces]
        supplement_metadata = {}
        if suffix == '.pdf' and pdf_native_pages is not None and pieces:
            supplement, supplement_metadata = _pdf_supplement(pieces[0], pdf_native_pages)
            structured[0] = (supplement, structured[0][1])
        text = "\f".join(piece for piece, _ in structured if piece.strip())
        metadata = {"extractor": "tika", "ocr_requested": True, "ocr_language": "eng", "ocr_output_type": "hocr",
                    "ocr_policy": "ocr_and_text" if pdf_ocr else "native_and_embedded_only", "completeness_verified": False,
                    "segmentation": "xhtml_pages_rows_and_embedded_objects",
                    "observed_page_boundaries": sum(count for _, count in structured),
                    "segment_numbers_are_extraction_ordinals": True,
                    "ocr_may_duplicate_native_or_embedded_text": True,
                    "embedded_objects_returned": max(0, len(payload) - 1),
                    "patient_linkage_context_verified": False, **supplement_metadata}
        pages = None
        for item in payload:
            for key in ("xmpTPg:NPages", "meta:page-count"):
                try:
                    if key in item:
                        pages = max(pages or 0, int(item[key]))
                except (TypeError, ValueError):
                    pass
        if pages is not None:
            metadata["reported_page_count"] = pages
        # Metadata's page count is not proof of pages actually inspected by OCR.
        result = ExtractionResult(status="partial", reason="page_or_embedded_content_coverage_unverified",
                                  examined=0, unit="pages" if suffix == ".pdf" else "characters", metadata=metadata)
        if not text.strip():
            result.reason = "no_readable_text"
        if any(any("EXCEPTION" in key.upper() or "TRUNCATED" in key.upper() or "LIMIT_REACHED" in key.upper() for key in item) for item in payload):
            result.reason = "parser_reported_incomplete_extraction"
        return _bounded(text, maximum, result)
    except Exception:
        # Network/parser errors can include document names or response content.
        return ExtractionResult(status="failed", reason="tika_unavailable_or_invalid_response", unit="bytes")
