# End-to-end evaluation

`scripts/evaluate.py` loads reference sources through the actual `scan_source` connector, extraction and detector pipeline. Schema version 2 scores **exact matching-value occurrences within each source object**. Version 3 adds **original-record clinical presence and patient-reference association** for explicitly supported mappings. Transient observations must reconcile with final scanner findings. Legacy object-label presence metrics remain diagnostics; they cannot establish an accuracy acceptance candidate.

Occurrence matching uses the entity class and exact Unicode NFC-normalized value. Repeated annotations represent repeated occurrences, not a set of unique values. A wrong OCR value produces a missed expected occurrence and an incorrect observed occurrence; case folding, punctuation removal, fuzzy matching and O/0 substitution are not applied. Results report TP/FP/FN, precision/recall, positive/negative source-object counts and coverage separately for database, digital and OCR categories.

The version-2 PII metric remains **object-scoped value-occurrence scoring**. It cannot distinguish the same value moved between records in one object. Version 3 separately checks clinical record identity and its exact patient reference; it does not extract diagnoses or measure semantic patient-to-diagnosis relationships. Neither unit measures OCR character accuracy, unique patients or arbitrary original PDF spans. Schema-only PII instance classes remain unsupported. Hospital-reviewed originals, gold annotations and held-out validation are still required.

Values and excerpts are not placed in evaluation reports. Version 2 uses fresh run-local keyed counters and generated report sample IDs; neither matching values nor their keyed tokens are exported. Reference manifests contain the actual annotated values and original locations, so keep them as sensitive hospital-local assets. Evaluation does not require enabling persistent evidence capture.

Opt-in matching-value/excerpt capture is a separate application behavior, not a change to these accuracy metrics. Validate it with synthetic fixtures before using hospital examples: capture disabled retains no values; enabled capture keeps at most three examples per finding with the 256-character value/400-character excerpt bounds; snippets remain within their detector segment; OCR and context-only classifications remain honestly labeled; aggregate counts continue beyond the example limit. Check the encrypted evidence table, administrator/reviewer-only audited reveal, absence from ordinary lists and CSV/JSON exports, and deletion when the parent finding is purged or replaced. A prior metadata-only scan must report no evidence and require a new scan, not invent an example from metadata.

Also test an existing catalog created before the evidence feature: initialization should add its separate table, preserve existing findings, and support capture on a new scan without altering old finding columns. Capture tests and excerpt inspection do not establish patient-linkage accuracy or hospital acceptance.

```sh
# Explicit rules-only smoke test; no claim of name/address detection:
python3 scripts/evaluate.py fixtures/evaluation/instances-heldout.json \
  --calibration fixtures/evaluation/instances-calibration.json --mode rules \
  --output work/synthetic-evaluation.json

# Production model, offline; local environment must already contain its weights:
python3 scripts/evaluate.py /secure/reference/heldout.json \
  --calibration /secure/reference/calibration.json --mode presidio \
  --output /secure/reports/evaluation.json

python3 -m pytest scripts
```

The API image also includes this utility and synthetic fixtures, so an offline host does not need to install Python dependencies:

```sh
# From the deployed bundle's deploy/ directory:
docker compose -f compose.yaml -f compose.images.yaml exec api python /app/scripts/evaluate.py \
  /app/fixtures/evaluation/instances-heldout.json --calibration /app/fixtures/evaluation/instances-calibration.json \
  --mode presidio --output /tmp/synthetic-evaluation.json
docker compose -f compose.yaml -f compose.images.yaml cp api:/tmp/synthetic-evaluation.json ../synthetic-evaluation.json
```

Calibration and held-out manifests must declare distinct splits and sample IDs. Within either manifest, the same resolved source file or the same SQLite database/location cannot count twice, even under different sample IDs or source entries. The harness also rejects identical source-file content appearing across calibration and evaluation. It cannot establish patient independence, detect near duplicates or identify all duplicate copies within a split; reviewers must enforce those boundaries too.

Declare `priority_classes` separately for `database`, `digital` and `ocr`. These are the hospital-approved labels the pilot must validate. A declared class with no samples still appears as unvalidated; leaving out a category cannot silently pass. This legacy version-1 example illustrates diagnostic object-label annotations only, **not a sufficient reference set or an acceptance candidate**:

```json
{
  "split": "evaluation",
  "synthetic": false,
  "priority_classes": {
    "database": ["personal_data:MRN", "patient_linked_health:HEALTH_INFORMATION"],
    "digital": ["personal_data:MRN", "patient_linked_health:HEALTH_INFORMATION"],
    "ocr": ["personal_data:MRN", "patient_linked_health:HEALTH_INFORMATION"]
  },
  "sources": [{
    "id": "approved-reference-documents",
    "kind": "filesystem",
    "config": {"root": "heldout-documents"},
    "category": "digital",
    "samples": [{
      "id": "heldout-001",
      "location": "reference-001.txt",
      "expected": ["personal_data:MRN", "patient_linked_health:HEALTH_INFORMATION"],
      "expected_status": "full"
    }]
  }]
}
```

Use category `ocr` for printed-image/scanned references, `database` for a read-only SQLite reference export, and `digital` for text-bearing files. SQLite config uses `path`; sample locations use `main/table/column`. Add every expected object, including negatives and inaccessible/unsupported examples. Live production source credentials are not accepted by this harness.

Version 2 requires the following top-level declaration and an exhaustive `instances` list on every sample, including `[]` on reviewed negative objects:

```json
{
  "schema_version": 2,
  "split": "evaluation",
  "synthetic": true,
  "instance_scoring": {
    "unit": "object_value_occurrence",
    "normalization": "exact_nfc_v1",
    "annotations_complete": true
  },
  "priority_classes": {"digital": ["personal_data:MRN"]},
  "sources": [{
    "kind": "filesystem",
    "config": {"root": "heldout-documents"},
    "category": "digital",
    "samples": [{
      "id": "private-reference-001",
      "location": "reference-001.txt",
      "expected": ["personal_data:MRN"],
      "expected_status": "full",
      "instances": [{
        "entity_type": "MRN",
        "classification": "personal_data",
        "value": "MRN-000001",
        "occurrence_id": "annotation-1"
      }]
    }]
  }]
}
```

This deliberately small synthetic example still has acceptance blockers. An optional `occurrence_id` must be unique within its sample, but does not assert a scanner record/page/span match. Record/page/span fields on PII occurrences are rejected. Supported value classes are Aadhaar, PAN, ABHA/ABHA address, insurance ID, MRN, UHID, email, phone, date of birth, person, location and credit card. Diagnostic value labels must agree with the exhaustive annotations. Reported `instance_scoring.results` use this unit; the top-level `results` remain diagnostic object-presence metrics.

Version 3 retains the complete PII `instances` contract and adds this top-level declaration:

```json
"association_scoring": {
  "unit": "original_record_clinical_association_v1",
  "normalization": "exact_nfc_v1",
  "annotations_complete": true
}
```

Every sample also supplies `records`, including all clinical-negative records. For an original JSON document containing a `patients` array:

```json
"records": {
  "mapping": "json_pointer_v1",
  "items": [
    {"locator": {"json_pointer": "/patients/0"}, "clinical": true,
     "patient_reference": {"entity_type": "MRN", "value": "SYN100"}},
    {"locator": {"json_pointer": "/patients/1"}, "clinical": true,
     "patient_reference": null},
    {"locator": {"json_pointer": "/patients/2"}, "clinical": false,
     "patient_reference": null}
  ]
}
```

`clinical` is the reviewer's original-record judgment. A null patient reference means there is no demonstrated patient association for that record, including clinical teaching material and negative records. A positive association requires one exact value and anchor type: MRN, UHID, ABHA, ABHA address, explicitly labelled patient Aadhaar/name, or a schema patient reference. These values and original locators are private gold data, not public report fields. Do not annotate detector-produced segment IDs or substitute keyword counts for clinical records.

The supported mappings are deliberately bounded:

| Mapping | Original locator and validation |
|---|---|
| `json_pointer_v1` | Native `.json` scalar-bearing objects, including nested objects/arrays. Original JSON pointers are enumerated independently and rendered content must exactly agree with actual extraction. Parent scalar fields are a separate record; patient IDs are never inherited into children. Serialized JSON/XML strings, scalar-array records and embedded form feeds remain unsupported by this evaluator mapping. |
| `text_spans_v1` | Native `.txt`, `.md` and `.log` files with hospital-reviewed `{start, end}` offsets in the original decoded Unicode text. Non-whitespace must be exhaustively covered by non-overlapping records. A detector segment crossing two annotated records blocks mapping rather than guessing which patient it belongs to. These are record boundaries, not scored entity spans. |
| `document_rectangles_v1` | PDF pages or raster frames with independently reviewed `{unit, rect: [left, top, right, bottom]}` rectangles in `rendered_unit_normalized_v1` coordinates. Gold includes the original SHA-256, page/frame kind and complete rendered unit dimensions. Nonoverlapping rectangles must own every observed word exactly once; include negative/background regions. Mixed or unmapped predictions remain errors and missed positive records remain false negatives. |
| `database_primary_key_v1` | Read-only SQLite reference exports, scoped to the sample column, with `{primary_key: {id: 1}}`. Numeric and string keys remain distinct; row ordinals are not identifiers. Nested JSON cells add `json_pointer`. Null/absent/blob/oversized or duplicated keys, active WAL/journal exports and changed original files block mapping. Null and empty scalar cells are still accounted for as negative records. |

The database observer obtains bounded key values with their actual SQLite types only during evaluation; regular production projections and public metadata do not gain raw keys. Other file layouts, including XML, CSV, Office and unknown embedded structures, remain unsupported for v3 association mapping even if their PII discovery works. PDF/raster mapping requires validated original geometry and independent rectangle annotations; a detected region ID is never a gold locator. An annotation gap, unsupported mapping, observation limit or disagreement with final clinical finding counts blocks association acceptance. Failed/unreturned objects contribute no provisional positive detections; their positive gold records remain missed. Sampled or partial objects retain missed original records and cannot pass accuracy acceptance.

`association_scoring.results` separates two measures:

| Measure | What is matched |
|---|---|
| `record_clinical_presence` | One clinical judgment per original record, whether its final health finding is linked or unlinked. It is not a count of diagnoses, keywords or patients. |
| `record_patient_reference_association` | The original record identity **and** exact NFC-normalized patient-reference class/value. A wrong or swapped patient reference produces FP and FN even when object-level PII values are all correct. The same identifier in two original records supplies two separate associations. |

Both measures reconcile transient observations against final finding groups/counts and use fresh run-local keyed identities. Reports expose only aggregate metrics, record/object sample counts and fixed incomplete-reason codes. There are no raw keys, original pointers, patient values or their keyed tokens in reports. The clinical-content priority label requires the clinical-presence measure; a patient-linked-health priority requires **both** measures. The floor remains 30 positive and 30 negative source objects per required category/measure, in addition to reported positive/negative record counts. Many records in one document do not establish independent-object validation.

The detector now treats distinct patient identifiers in a record/row as ambiguous instead of assuming they are aliases. Unlabelled staff/relative names do not become patient anchors merely because a note contains the word “patient.” Empty clinical cells do not become clinical findings from their synthetic column label. Explicit patient headers using `=`, `:` or `#` separate text records; ordinary prose mentioning a patient name does not. Native CSV/TSV keeps scalar cells together within their own row but isolates standalone JSON/XML cells from the outer row and from nested sibling records. Malformed structured cells are partial and suppress patient linkage. These extraction safeguards do not add CSV/TSV to the supported v3 reference mappings.

A parser's `patient_linkage_context_verified=false` keeps the flattened extraction stream unlinked. For eligible PDF/raster word geometry, a separate automatic layout policy can establish bounded candidate records and require an explicit unique patient field within each record. Uncertain regions and unmapped Tika supplements remain unlinked. Completing every image frame does not establish patient identity or accuracy. See [document discovery](document-discovery.md); hospital validation remains outstanding.

The [v3 calibration manifest](../fixtures/evaluation/association-calibration.json) and [held-out manifest](../fixtures/evaluation/association-heldout.json) are small synthetic examples with original JSON records, repeated equal patient references and negatives:

```sh
python3 scripts/evaluate.py fixtures/evaluation/association-heldout.json \
  --calibration fixtures/evaluation/association-calibration.json --mode presidio \
  --output work/synthetic-association-evaluation.json
```

Their synthetic status, small object counts and missing database/OCR samples keep acceptance false. Automated tests also inject swapped references, wrong clinical judgments, final-finding mismatches and failures, and exercise original text spans, nested JSON and typed-key database rows. These validate scoring behavior; they do not establish hospital accuracy.

For a hospital acceptance candidate, include original reference sources and both positive and negative objects for every declared priority class in all three categories. The defaults require at least 30 positive and 30 negative source objects per category/class and occurrence precision **and** recall of at least 0.95. Many occurrences within one file do not count as many independent positive objects. A smaller configurable sample floor is useful only for development; lowering it below 30, or lowering the programmatic target below 0.95, blocks the candidate flag. These are evidence floors, not a statistical guarantee of 95% generalization.

Reports contain explicit `acceptance_blockers`. The candidate requires a non-synthetic held-out evaluation, the production `presidio` detector, complete occurrence annotations, nonempty priority declarations in all three categories, passing supported priority metrics, and matching coverage expectations with no unexpected objects. Clinical priorities additionally require complete v3 original-record association annotations/mappings and passing clinical measures. Rules-only or version-1 smoke tests cannot qualify. An expected gap can satisfy a coverage-accounting check, but non-full coverage still leaves that category's accuracy metrics unvalidated. A failed extraction contributes missed annotated occurrences; it is not dropped. Observation limits, disagreement with final finding counts, changed reference inputs or a category labelled OCR without the actual OCR path block occurrence acceptance. Non-priority results remain visible for review.

`acceptance_candidate` means these machine-checkable prerequisites passed for the supported units. It never sets `hospital_validated` to true or replaces independent reviewer sign-off, semantic diagnosis assessment or operational acceptance. Hospital-reviewed original rectangles and held-out document evaluation remain required; successful structured/native-text association evaluation cannot stand in for those hospital document cases.

With the isolated OCR endpoint, supported raster files can be `full` when every original frame was rendered and OCR completed without limits and no uninspected nonvisual metadata is present. That is processing coverage, not a legibility or recognition-accuracy guarantee. PDF reconciliation compares complete connected native/OCR line groups: every word needs a mutually unique exact-NFC spatial match. It retains whole unresolved OCR lines and repeated occurrences at distinct positions. Accounted PDF fallback requests Tika position sorting with overlap deduplication disabled, then uses the unchanged exact ordered-token check for the same original page; unmatched and non-page text remains supplemental. Native-bearing PDFs remain partial because off-page/overprinted content is not fully proved; only blank or raw-pixel image-only PDFs can potentially become full after zero-native-operation, ancillary-content, geometry and OCR gates pass. Encoded DCT/JPX/JBIG2 image metadata, Office and legacy Tika-only paths remain partial. These processing gates do not establish patient identity. Version 3 can map independently annotated rectangles only when validated original geometry is available; unmapped or uncertain layout remains an explicit blocker. Keep mixed PDFs in representative evaluation; successful raster metrics cannot stand in for required PDF or patient-linkage cases.

The [packaged OCR occurrence report](../fixtures/evaluation/packaged-ocr-instance-evaluation.json) exercises two synthetic original raster objects through the deployed production detector. Both have full processing coverage, observations reconcile with final findings, and exact MRN/UHID occurrences are observed. It also reports an additional PERSON false positive. Sample sizes and missing categories keep `acceptance_candidate=false`; this is evidence that scoring works, not evidence for the 95% hospital target. The [release summary](../fixtures/evaluation/ocr-instance-release-validation.json) records the images/runtime and separate parser checks.

The included small fixture set exercises actual local text extraction, negative examples, patient-boundary separation and explicit unsupported/archive gaps. It is intentionally too small for accuracy claims and does not validate OCR, hospital name detection or a live database. Separate automated cases now exercise JSON/JSONL/XML sibling and nested records, original files through the connector, nested database cells, malformed input, and actual excerpt boundaries. Parent/child patient linkage is deliberately not inferred across nested objects. These synthetic cases establish implementation behavior, not patient-linkage accuracy on hospital documents.

The hospital set must add Aadhaar/PAN/ABHA, Indian names and initials, hospital ID formats, multi-patient tables, mixed PDFs, scans, encryption, corruption, permission failures, truncation and detector-version changes. Run these against the deployed container set with external networking blocked.

`scripts/integration_postgres.py` separately creates disposable synthetic PostgreSQL and API checker containers using already-loaded images. Both use a temporary internal network with no published ports, non-root users and tmpfs storage, and are cleaned up on exit. The latest backend and checker code are mounted read-only. It tests source grants, read-only transactions, actual server statement cancellation, 1,000-row sampling, gated complete scanning of 2,500-row selected tables and cancellation coverage. It never connects to the hospital:

```sh
python3 scripts/integration_postgres.py --image <loaded-postgres-image> --client-image <loaded-api-image> \
  --output work/postgres-integration.json
```

The historical [PostgreSQL integration report](../fixtures/evaluation/postgres-integration.json) records 17 passing checks against an actual disposable PostgreSQL container with 2,500 synthetic rows, including verified TLS rejection cases and shared catalog-lock behavior. The version-2 [rules occurrence report](../fixtures/evaluation/synthetic-instance-results.json) and [production-detector occurrence report](../fixtures/evaluation/synthetic-instance-presidio-results.json) each retain explicit acceptance blockers. Earlier [file-label results](../fixtures/evaluation/synthetic-results.json) and [production label results](../fixtures/evaluation/synthetic-presidio-results.json) are diagnostic historical evidence. These small synthetic sets do not establish hospital accuracy or the 95% target.
