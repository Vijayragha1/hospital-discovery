"""Transient, conservative layout inputs from the actual extraction stream.

These channels are observations, not patient records. Their values and boxes
must never be put in metadata, logs, or API responses. Only existing PDF spatial
reconciliation can suppress observations; text equality across units cannot.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .ocr_accounting import COORDINATE_SPACE, _transient_document_units
from .pdf_reconciliation import _render, reconciliation_plan


@dataclass
class CanonicalDocumentChannels:
    channels: list[dict] = field(default_factory=list, repr=False)
    residual_text: str = field(default="", repr=False)
    fallback: bool = False
    reason: str = "aligned"


def _fallback(text, reason):
    return CanonicalDocumentChannels(residual_text=text, fallback=True, reason=reason)


def _sanitized_units(units):
    if not isinstance(units, list) or not units or len(units) > 100:
        raise ValueError("invalid_document_units")
    kind = units[0].get("kind") if isinstance(units[0], dict) else None
    if kind not in {"image", "pdf"}:
        raise ValueError("invalid_document_units")
    for ordinal, unit in enumerate(units, 1):
        if (not isinstance(unit, dict) or unit.get("kind") != kind
                or type(unit.get("ordinal")) is not int or unit["ordinal"] != ordinal
                or unit.get("coordinate_space") != COORDINATE_SPACE
                or type(unit.get("coordinate_eligible")) is not bool):
            raise ValueError("invalid_document_units")
    # Reuse the independent shape/token/dimension/status and whole-document
    # budget checks. The original inventory gate is preserved below, never
    # inferred from the presence of coordinates or the number of units here.
    clean = _transient_document_units({"units": units}, kind, 10_000_000, True)
    for original, unit in zip(units, clean):
        eligible, reason = original["coordinate_eligible"], original.get("coordinate_reason")
        if eligible:
            if not unit["coordinate_eligible"] or reason != "verified":
                raise ValueError("invalid_document_eligibility")
        elif reason not in {unit["geometry_reason"], "document_inventory_incomplete", "document_text_truncated"}:
            raise ValueError("invalid_document_eligibility")
        # A locally verified map with incomplete original inventory is still
        # unusable for downstream association.
        if not eligible and reason == "verified":
            raise ValueError("invalid_document_eligibility")
        unit.update(coordinate_eligible=eligible, coordinate_reason=reason)
    return clean


def _public_words(lines):
    return [{"text": word["text"], "left": word["box"][0], "top": word["box"][1],
             "right": word["box"][2], "bottom": word["box"][3],
             "block": word["block"], "line": word["line"]}
            for line in lines for word in line["words"]]


def _entry(unit, channel, text, words, eligible, reason, fragment=1):
    return {"kind": unit["kind"], "ordinal": unit["ordinal"], "channel": channel,
            "fragment": fragment, "coordinate_space": COORDINATE_SPACE,
            "words": words, "text": text, "coordinate_eligible": eligible,
            "reason": reason}


def _pdf_channels(unit):
    canonical, summary, native, ocr, suppressed = reconciliation_plan(unit)
    canonical = canonical.replace("\f", "\n")
    if not summary["geometry_verified"] or summary["limit_reached"]:
        reason = "reconciliation_limit" if summary["limit_reached"] else unit["coordinate_reason"]
        channels = [_entry(unit, name, unit[key].replace("\f", "\n"), [], False, reason)
                    for name, key in (("native", "native_text"), ("ocr", "text")) if unit[key]]
        return canonical, channels

    eligible = unit["coordinate_eligible"] and summary["reconciled"]
    reason = (unit["coordinate_reason"] if not unit["coordinate_eligible"] else
              "verified" if eligible else "native_ocr_overlap_unresolved")
    channels = []
    if native:
        # Ordinary block IDs are layout hints, not established record barriers.
        channels.append(_entry(unit, "native", _render(native), _public_words(native), eligible, reason))
    fragments, current = [], []
    for index, line in enumerate(ocr):
        if index in suppressed:
            if current:
                fragments.append(current)
                current = []
        else:
            current.append(line)
    if current:
        fragments.append(current)
    for ordinal, fragment in enumerate(fragments, 1):
        channels.append(_entry(unit, "ocr" if ordinal == 1 else f"ocr-{ordinal}",
                               _render(fragment), _public_words(fragment), eligible, reason, ordinal))
    return canonical, channels


def canonical_document_channels(extracted):
    """Partition actual returned text into canonical channels and a supplement.

    ``start``/``end`` are exact offsets in ``extracted.text``. Structural
    separators between channels/units contain no source tokens. The returned
    residual is an untouched suffix after the accounted units; it never gains
    coordinates. On any truncation/alignment/validation failure the whole
    actual text becomes residual and no coordinate channels are returned.

    Patient boundaries require a separate decision. This function never alters
    the extraction, its metadata, or its patient-linkage flag.
    """
    text = extracted.text
    metadata = extracted.metadata
    units = extracted.document_units
    if not isinstance(text, str):
        raise TypeError("invalid_extracted_text")
    if not units:
        return _fallback(text, "document_units_unavailable")
    if (isinstance(metadata, dict) and (metadata.get("text_truncated") is True
            or isinstance(metadata.get("page_ocr"), dict) and metadata["page_ocr"].get("text_truncated") is True)):
        return _fallback(text, "document_text_truncated")
    try:
        units = _sanitized_units(units)
        if any(unit["coordinate_reason"] == "document_text_truncated" for unit in units):
            return _fallback(text, "document_text_truncated")
        all_channels, canonical_units = [], []
        offset = 0
        for unit in units:
            if unit["kind"] == "pdf":
                canonical, channels = _pdf_channels(unit)
                if "\n\n".join(channel["text"] for channel in channels) != canonical:
                    raise ValueError("unit_text_mismatch")
            else:
                canonical = unit["text"].replace("\f", "\n")
                if unit["coordinate_eligible"] and canonical.split() != [word["text"] for word in unit["ocr_words"]]:
                    # Accounting permits NFC-equivalent inventories. Layout
                    # consumes exact character spans, so do not silently change
                    # the original raster spelling to match those coordinates.
                    return _fallback(text, "document_text_alignment_unverified")
                channels = ([_entry(unit, "ocr", canonical, unit["ocr_words"],
                                    unit["coordinate_eligible"], unit["coordinate_reason"])] if canonical else [])
            local = 0
            for index, channel in enumerate(channels):
                if index:
                    local += 2  # Reconciliation separates native/OCR fragments.
                end = local + len(channel["text"])
                if canonical[local:end] != channel["text"]:
                    raise ValueError("unit_text_mismatch")
                channel.update(start=offset + local, end=offset + end)
                local = end
            canonical_units.append(canonical)
            all_channels.extend(channels)
            offset += len(canonical) + 1  # Original page/frame form-feed.
        accounted = "\f".join(canonical_units)
        if text == accounted:
            residual = ""
        elif units[0]["kind"] == "pdf" and accounted and text.startswith(accounted + "\f"):
            residual = text[len(accounted) + 1:]
        elif units[0]["kind"] == "pdf" and not accounted:
            # Extraction omits an empty accounted prefix when Tika supplements
            # it. Blank units have no words to attribute to that suffix.
            residual = text
        else:
            return _fallback(text, "document_text_alignment_unverified")
        if any(text[channel["start"]:channel["end"]] != channel["text"] for channel in all_channels):
            return _fallback(text, "document_text_alignment_unverified")
        return CanonicalDocumentChannels(all_channels, residual, reason="unmapped_supplement" if residual else "aligned")
    except (KeyError, TypeError, ValueError, OverflowError):
        # Fixed reason only: exceptions from untrusted channel data must not
        # become logs, object metadata, or a diagnostic containing patient text.
        return _fallback(text, "document_channels_invalid")
