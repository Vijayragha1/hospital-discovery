"""Transient original-unit layout planning shared by file and object-store scans.

The plan contains processing text and geometry only in memory. Persisted layout
metadata contains fixed policy/reason codes and counts; neither record text nor
patient identifiers are copied into it.
"""
from contextlib import nullcontext
import re

POLICY = "explicit_patient_fields_geometry_v1"


def _word_spans(text, words):
    tokens = list(re.finditer(r"\S+", text))
    if len(tokens) != len(words) or any(token.group() != word["text"] for token, word in zip(tokens, words)):
        raise ValueError("document_word_span_mismatch")
    return [{"index": index, "start": token.start(), "end": token.end()} for index, token in enumerate(tokens)]


def _validate_regions(regions, words):
    seen = []
    for region in regions:
        if type(region.get("association_candidate")) is not bool:
            raise ValueError("invalid_document_region_plan")
        spans = region["word_spans"]
        if region["word_indices"] != [span["index"] for span in spans]:
            raise ValueError("document_region_inventory_mismatch")
        tokens = list(re.finditer(r"\S+", region["text"]))
        if len(tokens) != len(spans):
            raise ValueError("document_region_text_mismatch")
        for token, span in zip(tokens, spans):
            index = span["index"]
            if (type(index) is not int or not 0 <= index < len(words)
                    or (span["start"], span["end"]) != token.span()
                    or token.group() != words[index]["text"]):
                raise ValueError("document_region_text_mismatch")
            seen.append(index)
    if sorted(seen) != list(range(len(words))):
        raise ValueError("document_region_word_conservation_failed")


def _plan(extracted):
    from .document_channels import canonical_document_channels
    from .document_layout import segment_words

    canonical = canonical_document_channels(extracted)
    units = [{"kind": unit["kind"], "ordinal": unit["ordinal"],
              "pixel_width": unit["pixel_width"], "pixel_height": unit["pixel_height"],
              "coordinate_space": unit["coordinate_space"], "channels": []}
             for unit in extracted.document_units]
    by_ordinal = {unit["ordinal"]: unit for unit in units}
    if len(by_ordinal) != len(units):
        raise ValueError("duplicate_document_unit")
    regions = []
    complete = not canonical.fallback and not canonical.residual_text.strip()
    complete = complete and all(unit["coordinate_eligible"] for unit in extracted.document_units)
    for channel in canonical.channels:
        words, text = channel["words"], channel["text"]
        unit = by_ordinal[channel["ordinal"]]
        channel_id = channel["channel"]
        if (not re.fullmatch(r"[a-z]+(?:-[1-9][0-9]*)?", channel_id)
                or any(item["id"] == channel_id for item in unit["channels"])):
            raise ValueError("invalid_document_channel")
        unit["channels"].append({"id": channel_id, "words": words})
        if channel["coordinate_eligible"]:
            proposed = segment_words(words)
            if proposed["policy"] != POLICY:
                raise ValueError("document_layout_policy_mismatch")
            channel_regions = proposed["regions"]
            _validate_regions(channel_regions, words)
        else:
            complete = False
            channel_regions = [{"text": text, "word_spans": _word_spans(text, words),
                                "association_candidate": False}]
        kind = "page" if unit["kind"] == "pdf" else "frame"
        for index, region in enumerate(channel_regions, 1):
            regions.append({"prefix": f"{kind}:{unit['ordinal']}/channel:{channel_id}/region:{index}",
                "unit": unit["ordinal"], "channel": channel_id, "text": region["text"],
                "word_spans": region["word_spans"], "association_candidate": region["association_candidate"]})
    # Text without validated source coordinates is still examined exactly once.
    unmapped = canonical.residual_text
    layout = {"policy": POLICY, "complete": complete, "units": units, "regions": regions}
    summary = {"policy": POLICY, "original_units": len(units),
        "coordinate_eligible_units": sum(unit["coordinate_eligible"] for unit in extracted.document_units),
        "candidate_records": sum(region["association_candidate"] for region in regions),
        "unverified_regions": sum(not region["association_candidate"] for region in regions) + bool(unmapped.strip()),
        "original_word_mapping_complete": complete, "patient_association_accuracy_validated": False}
    return layout, unmapped, summary


def analyze_document(location, data, suffix, extracted, options, detector):
    """Return findings; update only values-free extraction coverage metadata."""
    layout, unmapped = None, ""
    eligible_api = callable(getattr(detector, "analyze_layout_region", None))
    if extracted.document_units and eligible_api:
        try:
            layout, unmapped, summary = _plan(extracted)
            extracted.metadata["document_layout"] = summary
        except (ValueError, KeyError, TypeError, OverflowError):
            # Geometry/segmentation failure cannot drop the original observations
            # or enable the old flattened-stream association heuristic.
            extracted.metadata["document_layout"] = {"policy": POLICY, "candidate_records": 0,
                "original_word_mapping_complete": False, "reason": "document_layout_unavailable",
                "patient_association_accuracy_validated": False}
    observation_scope = getattr(detector, "_observation_context", None)
    association_scope = getattr(detector, "_association_context", None)
    document = {"data": data, "suffix": suffix.lower(), "text": extracted.text, "metadata": extracted.metadata}
    if layout is not None:
        document["layout"] = layout
    association = association_scope(location, document=document) if association_scope else nullcontext()
    capture = options.get("capture_evidence", False)
    with association:
        with observation_scope(location) if observation_scope else nullcontext():
            if layout is None:
                kwargs = {"capture_evidence": True} if capture else {}
                if extracted.metadata.get("patient_linkage_context_verified") is False or extracted.document_units:
                    kwargs["context"] = "patient_linkage_unverified"
                return detector.analyze(extracted.text, **kwargs) if extracted.text else []
            findings = []
            for region in layout["regions"]:
                if region["text"].strip():
                    findings.extend(detector.analyze_layout_region(region["text"], prefix=region["prefix"],
                        association_candidate=region["association_candidate"], capture_evidence=capture))
            if unmapped.strip():
                findings.extend(detector.analyze_layout_region(unmapped,
                    prefix="document:unmapped/channel:unmapped/region:1", association_candidate=False,
                    capture_evidence=capture))
            return findings
