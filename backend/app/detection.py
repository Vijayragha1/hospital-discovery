"""Local classification with bounded actual-match evidence only when explicitly enabled."""
from __future__ import annotations

import importlib.metadata
import hashlib
import re
import unicodedata
from collections import defaultdict
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from .extraction import structured_kind, structured_text
from .provenance import processing_runtime_identity, provenance_is_known


class DetectorUnavailable(RuntimeError):
    """An explicitly selected production detector cannot run offline."""


_PIPELINE_FILES = ("detection.py", "extraction.py", "ocr_accounting.py", "pdf_reconciliation.py",
                   "document_channels.py", "document_layout.py", "document_analysis.py",
                   "scanning.py", "database_connectors.py", "cloud_connectors.py", "provenance.py")
_RULES_SHA256 = hashlib.sha256(b"".join(
    name.encode("utf-8") + b"\x00" + Path(__file__).with_name(name).read_bytes()
    for name in _PIPELINE_FILES
)).hexdigest()


_D = ((0,1,2,3,4,5,6,7,8,9),(1,2,3,4,0,6,7,8,9,5),
      (2,3,4,0,1,7,8,9,5,6),(3,4,0,1,2,8,9,5,6,7),
      (4,0,1,2,3,9,5,6,7,8),(5,9,8,7,6,0,4,3,2,1),
      (6,5,9,8,7,1,0,4,3,2),(7,6,5,9,8,2,1,0,4,3),
      (8,7,6,5,9,3,2,1,0,4),(9,8,7,6,5,4,3,2,1,0))
_P = ((0,1,2,3,4,5,6,7,8,9),(1,5,7,6,2,8,3,0,9,4),
      (5,8,0,3,7,9,6,1,4,2),(8,9,1,6,0,4,3,5,2,7),
      (9,4,5,3,1,2,6,8,7,0),(4,2,8,6,5,7,3,9,0,1),
      (2,7,9,3,8,0,6,4,1,5),(7,0,4,6,9,1,3,2,5,8))


def valid_aadhaar(value: str) -> bool:
    digits = re.sub(r"[ -]", "", value)
    if not re.fullmatch(r"[2-9][0-9]{11}", digits) or len(set(digits)) == 1:
        return False
    checksum = 0
    for index, char in enumerate(reversed(digits)):
        checksum = _D[checksum][_P[index % 8][int(char)]]
    return checksum == 0


_PATIENT_LABEL_SEPARATOR = r'''["']?\s*[:#=]\s*'''
# Keep original offsets intact. In particular, do not normalize CRLF to LF;
# exclude its two halves from backtracking into a false blank paragraph.
_LINE_BREAK = r"(?:\r\n|\r(?!\n)|(?<!\r)\n)"
_PATIENT_BOUNDARY = re.compile(_LINE_BREAK + r"[^\S\r\n]*" + _LINE_BREAK + "|" + _LINE_BREAK
                                + r'''(?=\s*["']?(?:patient(?:[ _-]*(?:name|id|number|no))?|mrn|uhid)'''
                                + _PATIENT_LABEL_SEPARATOR + r")", re.I)


def source_segments(text: str) -> Iterator[tuple[str, str]]:
    """Keep pages, paragraph boundaries, table rows and patient headers separate."""
    kind = structured_kind(text)
    if kind:
        text, _, _ = structured_text(text, kind, 10_000_000)
    for page_number, page in enumerate(text.split("\f"), 1):
        blocks = _PATIENT_BOUNDARY.split(page)
        for block_number, block in enumerate(blocks, 1):
            rows = block.splitlines() if "\t" in block else [block]
            for row_number, row in enumerate(rows, 1):
                # The stream can contain CSV rows or embedded documents: these are
                # extraction ordinals, not asserted PDF page numbers or patient IDs.
                yield f"segment:{page_number}/block:{block_number}/row:{row_number}", row


def _segments(text: str, *, single_record: bool = False) -> Iterator[tuple[str, str, int, bool, str]]:
    sources = [("record", text)] if single_record else source_segments(text)
    for segment_id, source in sources:
        # Bound NLP memory; independently classify chunks, never merge people.
        for offset in range(0, len(source), 12000 - 256):
            chunk = source[offset:offset + 12000]
            if chunk.strip():
                yield segment_id, chunk, offset, offset + len(chunk) < len(source), source


def match_evidence(source: str, start: int, end: int, segment: str) -> dict | None:
    """Build evidence from one actual segment; never accept fabricated/invalid spans."""
    if not (0 <= start < end <= len(source)):
        return None
    excerpt_start = max(0, start - 80)
    return {"value": source[start:end][:256], "excerpt": source[excerpt_start:excerpt_start + 400],
            "start": start, "end": end, "segment": segment, "offset_scope": "segment"}


_EMAIL = re.compile(r"(?<![\w.+-])[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9](?:[A-Z0-9.-]*[A-Z0-9])?\.[A-Z]{2,}(?![\w.-])", re.I)
_AADHAAR = re.compile(r"(?<![0-9])[2-9][0-9]{3}[ -]?[0-9]{4}[ -]?[0-9]{4}(?![0-9])")
_PAN = re.compile(r"\b[A-Z]{3}[ABCFGHJLPT][A-Z][0-9]{4}[A-Z]\b", re.I)
_PHONE = re.compile(r"(?<![\w\d])(?:\+?91[ -]?)?[6-9][0-9]{4}[ -]?[0-9]{5}(?!\d)")
_HOSPITAL_ID = re.compile(r"\b(mrn|uhid|medical\s+record\s+(?:number|no)|patient[ _-]?(?:id|number|no))[\"']?\s*[:#=>\-]?\s*[\"']?([A-Z0-9][A-Z0-9/_\-]{2,31})\b", re.I)
_ABHA = re.compile(r"\b(?:ABHA(?:[ _-]*(?:number|no|id))?|health[ _-]*id)[\"']?\s*[:#=>\-]?\s*[\"']?([0-9]{2}(?:[ -]?[0-9]{4}){3})(?![0-9])", re.I)
_ABHA_ADDRESS = re.compile(r"(?<![\w.@-])[A-Z0-9][A-Z0-9._-]{1,49}@(?:abdm|sbx)(?![\w.])", re.I)
_INSURANCE = re.compile(r"\b(?:insurance|policy|tpa)[ _-]?(?:id|number|no)[\"']?\s*[:#=>\-]?\s*[\"']?([A-Z0-9][A-Z0-9/\-]{3,39})\b", re.I)
_DOB = re.compile(r"\b(?:dob|date[ _-]of[ _-]birth|birth[ _-]?date)[\"']?\s*[:#=>]?\s*[\"']?([0-9]{4}[-/][0-9]{1,2}[-/][0-9]{1,2}|[0-9]{1,2}[-/][0-9]{1,2}[-/][0-9]{2,4})\b", re.I)
_HEALTH = re.compile(r"\b(?:diagnos(?:is|es|ed)|discharge\s+summary|medical\s+history|prescription|lab(?:oratory)?\s+(?:result|report|test)s?|blood\s+(?:test|group)|hba1c|haemoglobin|hemoglobin|diabet(?:es|ic)|hypertension|carcinoma|cancer|chemotherapy|pregnan(?:cy|t)|hiv|tuberculosis|medication|clinical\s+notes?)\b", re.I)
_CLINICAL_COLUMN = re.compile(r"\b(?:diagnosis|diagnoses|medication|prescription|clinical[ _]notes?|lab[ _]results?|medical[ _]history)(?:[ _-](?:code|codes|text|description))?\b", re.I)


class Detector:
    def __init__(self, mode: str = "presidio", model: str = "en_core_web_lg", *, _observation_sink=None, _association_sink=None):
        # Private local-evaluator hook. It is never a scan/API option and does not
        # add raw observations to returned findings or the persistence pipeline.
        if _observation_sink is not None and not callable(_observation_sink):
            raise ValueError("invalid_observation_sink")
        self._observation_sink = _observation_sink
        self._observation_scope = None
        if _association_sink is not None and not callable(_association_sink):
            raise ValueError("invalid_association_sink")
        self._association_sink = _association_sink
        self._association_scope = None
        self._layout_scope = None
        if mode not in {"rules", "presidio"}:
            raise DetectorUnavailable("detector_mode_invalid")
        self.mode = mode
        self.model = model
        self._analyzer = None
        self.version = "hospital-rules/1.0+sha256-" + _RULES_SHA256
        self.capabilities = {
            "mode": mode, "languages": ["en"], "offline": True,
            "name_detection": mode == "presidio", "clinical_classifier": "rules_and_context",
            "evidence_capture": {"supported": True, "default": False, "max_examples_per_finding": 3,
                                 "max_value_characters": 256, "max_excerpt_characters": 400,
                                 "offset_scope": "segment"},
            "limitations": ["not_exhaustive", "english_only", "clinical_dictionary_is_limited",
                            "no_patient_diagnosis_association", "abha_format_is_not_issuance_validation"],
        }
        if mode == "rules":
            self.capabilities["limitations"].append("rules_mode_has_no_name_or_address_ner")
            self._record_runtime()
            return
        try:
            import spacy
            from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
            from presidio_analyzer.nlp_engine import SpacyNlpEngine
            from presidio_analyzer.predefined_recognizers import SpacyRecognizer, CreditCardRecognizer
            # spacy.load does not fetch weights. Never invoke download or model providers.
            nlp = spacy.load(model)
            if not nlp.has_pipe("ner"):
                raise DetectorUnavailable("ner_pipeline_missing")
            engine = SpacyNlpEngine(models=[])
            engine.nlp = {"en": nlp}
            # Do not load the default EmailRecognizer: its tldextract validation can
            # fetch the public suffix list. Email/phone rules above are fully local.
            registry = RecognizerRegistry(recognizers=[SpacyRecognizer(), CreditCardRecognizer()],
                                          supported_languages=["en"])
            self._analyzer = AnalyzerEngine(nlp_engine=engine, registry=registry, supported_languages=["en"])
            self.version += "/presidio-" + importlib.metadata.version("presidio-analyzer")
            self.version += "/spacy-" + spacy.__version__ + "/model-" + str(nlp.meta.get("lang", "en"))
            self.version += "_" + str(nlp.meta.get("name", "unknown")) + "-" + str(nlp.meta.get("version", "unknown"))
            self.capabilities["model"] = model
            self._record_runtime()
        except DetectorUnavailable:
            raise
        except Exception:
            raise DetectorUnavailable("presidio_or_local_model_unavailable") from None

    def _record_runtime(self):
        self.version += "/" + processing_runtime_identity()
        self.capabilities["processing_runtime_recorded"] = provenance_is_known(self.version)
        if not self.capabilities["processing_runtime_recorded"]:
            self.capabilities["limitations"].append("processing_runtime_identity_unverified")

    @contextmanager
    def _observation_context(self, location, *, finding_segment=None, prefix_length=0):
        """Supply final-object identity to an optional synchronous evaluator."""
        if self._observation_sink is None:
            yield
            return
        previous = self._observation_scope
        self._observation_scope = (location, finding_segment, prefix_length)
        try:
            yield
        finally:
            self._observation_scope = previous

    def _observe(self, source, segment, kind, start, end, reason):
        if self._observation_sink is None or self._observation_scope is None:
            return
        location, finding_segment, prefix = self._observation_scope
        adjustment = prefix if segment == "segment:1/block:1/row:1" else 0
        valid = adjustment <= start < end <= len(source)
        # An invalid/synthetic-label span is an unmatched prediction, not a
        # fabricated source value or a silently omitted false positive.
        self._observation_sink({"location": location, "entity_type": kind,
            "classification": "personal_data", "reason": reason,
            "segment": finding_segment or segment, "source_segment": segment,
            "start": start - adjustment, "end": end - adjustment,
            "value": source[start:end] if valid else None, "source_span_valid": valid})

    @contextmanager
    def _association_context(self, location, *, document=None, cell=None, references=()):
        """Transient source identity and row references; never persisted or an API option."""
        previous = self._association_scope
        self._association_scope = {"location": location, "references": references,
                                   "finding_segment": "column" if cell is not None else None}
        try:
            if self._association_sink is not None:
                self._association_sink({"event": "source", "location": location, "document": document, "cell": cell})
            yield
        finally:
            self._association_scope = previous

    @staticmethod
    def _patient_anchor(kind, source, start, end):
        if not 0 <= start < end <= len(source):
            return None
        if kind in {"MRN", "UHID", "ABHA", "ABHA_ADDRESS"}:
            return kind, source[start:end]
        # A name or Aadhaar elsewhere in a clinical note can belong to a staff
        # member or relative. Require an explicit adjacent patient label.
        before = source[max(0, start - 80):start]
        label = ((r"\bpatient(?:[ _-]*name)?" if kind == "PERSON" else r"\bpatient[ _-]*aadhaar")
                 + _PATIENT_LABEL_SEPARATOR + r"$")
        if kind in {"PERSON", "IN_AADHAAR"} and re.search(label, before, re.I):
            return kind, source[start:end]
        return None

    @staticmethod
    def _document_patient_anchor(kind, source, start, end):
        """Only an actual labelled field can identify an inferred document record.

        Bare ABHA addresses and identifiers in clinical prose remain PII; their
        presence is not evidence that the record concerns that person.
        """
        if not 0 <= start < end <= len(source):
            return None
        beginning = max(source.rfind("\n", 0, start), source.rfind("\r", 0, start)) + 1
        label = source[beginning:start].strip()
        fields = {
            "MRN": r"(?:mrn|medical\s+record\s+(?:number|no)|patient[ _-]?(?:id|number|no))",
            "UHID": r"uhid",
            "ABHA": r"(?:abha(?:[ _-]*(?:number|no|id))?|patient[ _-]*abha)",
            "ABHA_ADDRESS": r"(?:patient[ _-]*)?abha[ _-]*address",
            "IN_AADHAAR": r"patient[ _-]*aadhaar",
            "PERSON": r"patient(?:[ _-]*name)?",
        }
        pattern = fields.get(kind)
        if pattern and re.fullmatch(pattern + r'''["']?\s*[:#=]\s*["']?''', label, re.I):
            return kind, source[start:end]
        return None

    def analyze_layout_region(self, text: str, *, prefix: str, association_candidate: bool,
                              capture_evidence: bool = False) -> list[dict]:
        """Internal geometry-pipeline entry; no user approval flag enables it.

        Candidate regions are one inferred record; uncertain residuals keep the
        ordinary boundaries and cannot establish a patient association. Prefixes
        contain original-unit ordinals, channel IDs and region ordinals only.
        """
        if (type(association_candidate) is not bool or not isinstance(prefix, str)
                or len(prefix) > 180 or not re.fullmatch(r"[a-z]+:[a-z0-9_-]+(?:/[a-z]+:[a-z0-9_-]+)*", prefix)):
            raise ValueError("invalid_document_region")
        previous = self._layout_scope
        self._layout_scope = {"prefix": prefix, "candidate": association_candidate}
        try:
            return self.analyze(text, context="" if association_candidate else "patient_linkage_unverified",
                                capture_evidence=capture_evidence)
        finally:
            self._layout_scope = previous

    def analyze(self, text: str, context: str = "", capture_evidence: bool = False) -> list[dict]:
        if not isinstance(capture_evidence, bool):
            raise ValueError("invalid_capture_evidence_option")
        # A database row may contain an array of unrelated patient records. Its
        # outer identifier is never evidence for a nested structured record.
        if structured_kind(text):
            context = context.replace("patient_reference_present", "").replace("patient_reference_ambiguous", "")
        findings = []
        segment_anchors = defaultdict(set)
        seen_entities, seen_health = set(), set()
        for segment_id, segment, offset, more_after, source in _segments(
                text, single_record=bool(self._layout_scope and self._layout_scope["candidate"])):
            if self._layout_scope:
                segment_id = self._layout_scope["prefix"] + "/" + segment_id
            detections: dict[tuple[str, int, int], tuple[float, str]] = {}

            def add(kind, start, end, confidence, reason):
                # A match touching an artificial cut may be a fragment. The overlapping
                # neighboring window owns the complete entity, preventing double counts.
                if (offset > 0 and start == 0) or (more_after and end == len(segment)):
                    return
                detections[(kind, start, end)] = (confidence, reason)

            for match in _AADHAAR.finditer(segment):
                if valid_aadhaar(match.group()):
                    add("IN_AADHAAR", *match.span(), .96, "format_and_verhoeff_checksum")
            for match in _PAN.finditer(segment):
                add("IN_PAN", *match.span(), .9, "pan_format_candidate")
            for match in _ABHA.finditer(segment):
                add("ABHA", *match.span(1), .88, "abha_format_and_label_candidate")
            for match in _ABHA_ADDRESS.finditer(segment):
                add("ABHA_ADDRESS", *match.span(), .9, "abha_address_format_candidate")
            for match in _INSURANCE.finditer(segment):
                if any(char.isdigit() for char in match.group(1)):
                    add("INSURANCE_ID", *match.span(1), .85, "insurance_identifier_label_and_format")
            for match in _HOSPITAL_ID.finditer(segment):
                if any(c.isdigit() for c in match.group(2)):
                    kind = "UHID" if match.group(1).lower() == "uhid" else "MRN"
                    add(kind, *match.span(2), .9, "hospital_identifier_label_and_format")
            for match in _EMAIL.finditer(segment):
                add("EMAIL_ADDRESS", *match.span(), .95, "email_format")
            for match in _PHONE.finditer(segment):
                # Do not re-label a substring of a validated Indian identifier as a phone.
                if not any(start <= match.start() and end >= match.end() for (_, start, end) in detections):
                    add("PHONE_NUMBER", *match.span(), .75, "indian_phone_format_candidate")
            for match in _DOB.finditer(segment):
                add("DATE_OF_BIRTH", *match.span(1), .9, "birth_date_label_and_format")
            if self._analyzer is not None:
                try:
                    entities = self._analyzer.analyze(
                        text=segment, language="en", score_threshold=.5,
                        entities=["PERSON", "LOCATION", "CREDIT_CARD"],
                    )
                except Exception:
                    raise DetectorUnavailable("local_ner_analysis_failed") from None
                for entity in entities:
                    if not any(kind == entity.entity_type and start < entity.end and end > entity.start
                               for kind, start, end in detections):
                        add(entity.entity_type, entity.start, entity.end, round(float(entity.score), 3), "local_presidio_recognizer")
            grouped, examples = defaultdict(list), defaultdict(list)
            for (kind, start, end), (confidence, reason) in detections.items():
                identity = (segment_id, kind, start + offset, end + offset)
                if identity in seen_entities:
                    continue
                seen_entities.add(identity)
                anchor_function = self._document_patient_anchor if self._layout_scope else self._patient_anchor
                anchor = anchor_function(kind, source, start + offset, end + offset)
                if anchor:
                    segment_anchors[segment_id].add((anchor[0], unicodedata.normalize("NFC", anchor[1])))
                grouped[(kind, reason)].append(confidence)
                self._observe(source, segment_id, kind, start + offset, end + offset, reason)
                if capture_evidence and len(examples[(kind, reason)]) < 3:
                    evidence = match_evidence(source, start + offset, end + offset, segment_id)
                    if evidence:
                        examples[(kind, reason)].append(evidence)
            for (kind, reason), scores in grouped.items():
                finding = {"entity_type": kind, "classification": "personal_data",
                           "confidence": max(scores), "match_count": len(scores),
                           "reason": reason, "segment": segment_id}
                if capture_evidence:
                    finding["evidence"] = examples[(kind, reason)]
                findings.append(finding)
            health = []
            for match in _HEALTH.finditer(segment):
                if (offset > 0 and match.start() == 0) or (more_after and match.end() == len(segment)):
                    continue
                identity = (segment_id, match.start() + offset, match.end() + offset)
                if identity not in seen_health:
                    seen_health.add(identity)
                    health.append(match)
            health_column = offset == 0 and bool(_CLINICAL_COLUMN.search(context)) and bool(segment.strip())
            if health or health_column:
                finding = {"entity_type": "HEALTH_INFORMATION",
                                 "classification": "clinical_content", "confidence": .7,
                                 "match_count": max(1, len(health)),
                                 "reason": "clinical_terms_or_field_context",
                                 "segment": segment_id}
                if capture_evidence:
                    finding["evidence"] = [match_evidence(source, match.start() + offset, match.end() + offset, segment_id)
                                           for match in health[:3]]
                findings.append(finding)
        merged = {}
        for finding in findings:
            if finding["entity_type"] == "HEALTH_INFORMATION":
                anchors = set(segment_anchors[finding["segment"]])
                references = self._association_scope["references"] if self._association_scope else ()
                anchors.update((kind, unicodedata.normalize("NFC", value)) for kind, value in references)
                # Prefer an explicit identifier over a labelled name, but never
                # treat distinct identifiers (including across types) as aliases.
                identifiers = {item for item in anchors if item[0] != "PERSON"}
                if identifiers:
                    anchors = identifiers
                schema = {value for kind, value in anchors if kind == "PATIENT_REFERENCE"}
                explicit = {value for kind, value in anchors if kind != "PATIENT_REFERENCE"}
                if schema & explicit:
                    anchors = {item for item in anchors if item[0] != "PATIENT_REFERENCE" or item[1] not in explicit}
                ambiguous = len(anchors) > 1 or "patient_reference_ambiguous" in context
                unverified = "patient_linkage_unverified" in context
                linked = not ambiguous and not unverified and (len(anchors) == 1 or "patient_reference_present" in context)
                finding["classification"] = "patient_linked_health" if linked else "clinical_content"
                finding["confidence"] = .85 if linked else .7
                finding["reason"] = ("clinical_content_with_unverified_patient_layout" if unverified else
                    "clinical_content_with_ambiguous_patient_references" if ambiguous else
                    "clinical_content_with_patient_reference" if linked else "clinical_terms_or_field_context")
                finding_anchors = list(anchors) if linked else []
            else:
                finding_anchors = []
            key = (finding["entity_type"], finding["classification"], finding["reason"], finding["segment"])
            if key not in merged:
                merged[key] = dict(finding)
            else:
                merged[key]["match_count"] += finding["match_count"]
                merged[key]["confidence"] = max(merged[key]["confidence"], finding["confidence"])
                if capture_evidence:
                    merged[key]["evidence"].extend(finding["evidence"][:3 - len(merged[key]["evidence"])])
            if finding["entity_type"] == "HEALTH_INFORMATION" and self._association_sink is not None and self._association_scope:
                self._association_sink({"event": "clinical", "location": self._association_scope["location"],
                    "source_segment": finding["segment"], "segment": self._association_scope["finding_segment"] or finding["segment"],
                    "classification": finding["classification"], "entity_type": "HEALTH_INFORMATION",
                    "reason": finding["reason"], "match_count": finding["match_count"], "anchors": finding_anchors})
        return list(merged.values())
