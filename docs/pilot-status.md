# Pilot completion audit

The intended outcome is PII and patient-linked health-information discovery in the
client's environment, with all processing and retained data under client control.
The local application and offline bundle are implementation evidence. They are
not a completed hospital deployment or hospital acceptance.

The user confirmed **both a database and a file share** for the first pilot.
This confirms the source categories, not individual endpoints or connection
settings. The database engine/version, file-share protocol, exact approved
scope and document formats still need hospital confirmation. Hosting remains
undecided. The inventory rows remain templates until those details are supplied.

The current bundle is release `20260922035303`. [Current validation](implementation-validation.md) proves the exercised native-column and repeated-identifier routes against unchanged independent gold, plus the original PDF safeguards. Hospital deployment and acceptance remain unverified.

Historical release `20260922034011` introduced automatic document record candidates and independent rectangle scoring. Its [validation record](implementation-validation.md) includes the native-column limitation observed in that release. Current reconciliation behavior is described below; historical release evidence does not establish hospital accuracy or deployment acceptance.

Historical release `20260922024917` has [recovery evidence](../fixtures/evaluation/recovery-release-validation.json) recording 508 passing portable tests and 44 subtests, plus 30 actual isolated PostgreSQL backup/restore checks. Restored access and jobs are quarantined before reopening; current approved retention is drained. Hospital-host recovery remains to be verified. The preceding boundary release `20260922022904` retains the following historical evidence. Its
[release evidence](../fixtures/evaluation/boundary-release-validation.json)
records 488 passing regression tests and 44 subtests, 26 packaged original-file
boundary checks, 17 PDF checks, 32 HTTPS checks and 10 comparison checks, plus
offline image/model, source/runtime and default-egress verification. Earlier
platform-specific parser, UI and live-connector checks are historical; no
hospital deployment or accuracy acceptance is implied.

The current pipeline separates structured CSV/TSV cells from outer-row identities,
recognizes explicit patient headers with `=` across LF/CRLF/CR while preserving
original offsets, disables patient linkage from unverified document regions, and
preserves returned embedded-image frame boundaries through hOCR. Original DOCX
checks detected native identifiers, embedded scan text and both frames of an
embedded TIFF in distinct segments. Office results remain partial with linkage
disabled; the checks do not prove complete embedding inventory.

Eligible PDFs and raster files now use validated transient word geometry to
infer candidate records in compact forms, stacked forms and supported columns.
The detector requires an explicit unique patient reference within a candidate;
uncertain regions and unmapped supplements remain unlinked. This does not
promote processing coverage or establish hospital accuracy. Independent original
page/frame rectangle annotations can evaluate clinical presence and exact
patient-reference association without using algorithm-generated region IDs.
See [document discovery](document-discovery.md).

| Requirement | Current evidence | Remaining proof or work |
|---|---|---|
| Structured discovery | PostgreSQL, MySQL and SQL Server adapters; bounded sampling, read-only checks, cancellation tests and synthetic integrations | Confirm the hospital engine/version, grants, identifier columns, approved tables and measured workload. |
| Unstructured discovery | Mounted folders, SMB, Tika and English Tesseract; original-page/frame accounting; bounded PDF inventory; complete spatial word correspondence across connected native/OCR line groups and ordered same-page Tika fallback; native/embedded-image DOCX functional probe | Validate the hospital corpus. Native-bearing PDFs remain partial because original text representation is unverified. Only eligible blank/raw-pixel image-only PDFs can become full with every processing/geometry/ancillary gate satisfied. Encoded-image metadata and Office/Tika-only paths remain partial. Full raster processing alone does not establish patient identity or OCR accuracy. |
| Indian PII and patient-linked classification | Local Presidio/spaCy, patterns/checksums, identifier/context rules, database relationships and record-boundary tests; transient geometry candidates for eligible PDF/raster content with explicit unique patient fields | Calibrate hospital identifier formats and evaluate names, initials, clinical terms and patient linkage using hospital-reviewed examples. Uncertain geometry/regions, unmapped Tika content and Office layouts remain unlinked. |
| Accuracy | Version-2 exact-value occurrences; version-3 original-record clinical presence and exact patient-reference association for native JSON/text, typed-key SQLite exports and independently annotated original PDF-page/raster-frame rectangles; synthetic evaluations retain acceptance blockers | Obtain hospital-held-out annotations, including complete document records and negative/background rectangles. CSV/TSV, Office and unvalidated document geometry remain unsupported association mappings; semantic diagnosis assessment is not implemented. Demonstrate targets separately for database, digital and OCR; many records in one object do not establish independent sample size. |
| Findings, matching values and review | Authenticated dashboard; opt-in encrypted bounded evidence; audited reveal and feedback; CSV/JSON reports omit raw matches | Hospital approval for evidence capture, review ownership and retention; validate real-document excerpts and OCR errors. |
| Coverage | Full/sampled/partial/inaccessible/unsupported/excluded/failed states; visible limits and interrupted reads | Reconcile every object in the approved pilot scope. A completed scan is not a claim of complete coverage. |
| Repeat scans | Object changes and finding-group deltas; coverage, detector, policy and runtime-provenance gates | Run two hospital scans with controlled source changes and access loss. These are aggregate recognizer observations, not individual-patient changes or proof of erasure. |
| Self-hosting and offline installation | Linux/amd64 image archive, bundled models/OCR/UI assets, checksums, image import, isolated packaged scans and egress probes | Choose the host. Verify approved private source routes, trusted certificates, blocked external egress, encrypted volumes/swap/backups and recovery on that host. The synthetic same-release restore drill passes; it does not attest the hospital backup system. |
| Safe operation | Read-only connector operations, database concurrency locks, bounded reads/parser resources, retention cleanup and credential renewal tests | Approve scan windows, canonical endpoints, stop thresholds, workload limits and retention; verify these against actual infrastructure. |
| Delivery | Source archive, offline installation bundle, source-inventory template, supported-format matrix, synthetic reports and operating runbook | Complete the hospital inventory and acceptance record. A template is not an approved client source inventory. |

Connected groups of overlapping native/OCR lines can reconcile differing column
grouping only when every word has a mutually unique counterpart with equal
NFC-normalized text and verified spatial agreement. Real repeats survive;
uncertain groups remain separate observations with linkage disabled for the
page channels. The accounted-PDF Tika fallback requests `sortByPosition`, but
still requires exact ordered same-page text agreement after NFC/whitespace
normalization; outside-page, unmatched and returned embedded content remains
unlinked supplemental text. Eligible document candidates can be evaluated
against independent original-page/frame rectangles. These changes do not complete hospital
acceptance. Native-bearing PDFs lack independent source-text representation
proof and ancillary content can remain uninspected. Unvalidated geometry and
unmapped content still block document association mapping or acceptance;
partial required content cannot be relabelled full. Value-occurrence scoring
does not measure original spans, and record association is not semantic diagnosis
extraction. The preceding boundary release passed 26 original-file boundary checks and 17 packaged PDF
checks; the earlier 65 PDFBox cases remain historical evidence;
the synthetic packaged v3 example mapped all five original records but remains
an unvalidated accuracy result. Remaining requirements cannot be replaced
by a passing smoke test or by relabelling partial content full.
Hospital input is separately required for hosting, approved source access,
operating limits, identifier formats and representative reference data.

See the [validation record](implementation-validation.md),
[discovery flow](discovery-flow.md),
[acceptance checklist](acceptance-checklist.md), [evaluation method](evaluation.md)
and [source inventory template](hospital-inventory.csv).
