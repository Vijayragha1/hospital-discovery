# Hospital pilot acceptance checklist

Use this checklist with the [hospital inventory template](hospital-inventory.csv),
[operator runbook](runbook.md), and [evaluation method](evaluation.md). It records
hospital acceptance; automated tests and synthetic demonstrations do not complete
these gates. Keep a hospital-local evidence reference, owner, date, and outcome
for each item. An unchecked item remains open.

Consult the [pilot completion audit](pilot-status.md) before scheduling acceptance.
The application reconciles complete connected PDF native/OCR line groups only
when every word has a mutually unique exact-NFC spatial counterpart. Version-3
original-record clinical presence/patient-reference scoring supports native JSON
and text mappings, typed-key SQLite reference exports, and independently reviewed
original PDF-page/raster-frame rectangles. Automatic document record candidates
remain a heuristic requiring hospital validation. Native PDF representation
proof, uninspected ancillary content, unvalidated document geometry and Office
association mappings remain open. Hospital source access, operating limits and
reference data are separate site inputs.

Historical recovery release `20260922024917` has
[synthetic release evidence](../fixtures/evaluation/recovery-release-validation.json)
for 508 passing regression tests and 44 subtests, plus
[30 same-release PostgreSQL recovery checks](../fixtures/evaluation/recovery-integration.json).
See the [current validation record](implementation-validation.md) for current
release results and historical recovery, boundary, parser, UI and connector checks. Keep this hospital
checklist unapproved until its own site-specific requirements and remaining
implementation gates pass.

## 1. Confirm the hospital scope

Both a database and a file share are confirmed pilot categories. Their exact
approved scope, endpoints, database engine/version and file-share protocol remain
unknown; no hospital installation or source access is established by that confirmation.

- [ ] Complete one inventory row per approved database, share, or cloud resource. Replace the
  `TEMPLATE-*` rows and leave unknown values blank. Record estimates as estimates,
  with units. `NOT_APPROVED` is the starting status.
- [ ] Confirm the HIS engine and version. They are currently unknown. PostgreSQL,
  MySQL 8.x/9.x InnoDB, and SQL Server adapters are implemented; verify the actual
  version, table types, driver behavior, and privileges before admission. Other
  engines need an implemented, validated connector.
- [ ] Confirm the approved file-server endpoints, protocols, shares, folder allowlists,
  expected counts/volumes, languages, and file types. Record unsupported content
  and inaccessible locations explicitly.
- [ ] For cloud sources, record the private endpoint, region, named bucket,
  container or table, exact prefix/partition, expected volume, and allowed request
  costs. No account-wide resource discovery or automatic scope expansion is implied.
- [ ] Document approved schemas/tables/folders and patient relationships. Obtain
  hospital-specific UHID/MRN/insurance formats and pseudonymous examples for
  calibration; those formats are currently unknown.
- [ ] Identify hospital IT, clinical reviewer, privacy owner, and MSSP operator.
  Record the authorized pilot scope and evidence location.

The inventory is a planning record, not an application import. Do not put patient
values, passwords, connection strings containing secrets, or private keys in it.
Completed endpoint/path inventories can themselves be sensitive and must stay on
approved hospital storage.

## 2. Pass the deployment and operating gates

- [ ] Verify bundle checksums/provenance, runtime inventories, local model loading,
  and the hospital TLS certificate. Record the deployed image/detector versions.
- [ ] Retain the generated `compose.images.yaml` override for every deployment
  command. Verify that API and worker receive the same `DISCOVERY_RUNTIME_ID`
  recorded in `release.json`, generated from the immutable API/Tika image IDs,
  with the recorded platform/images. Never copy an old identity across processing
  changes or reuse it for an altered external parser. This is deployment
  provenance, not remote attestation of an arbitrary parser endpoint.
- [ ] Demonstrate encrypted host volumes and encrypted or disabled swap. Include
  logs, temporary storage, exports, backups, and separately escrowed keys in the
  storage and recovery controls; application field encryption alone is insufficient.
- [ ] Verify dedicated source accounts have read access only. Confirm read-only
  host/container mounts or SMB grants. For databases, verify engine-specific
  restricted grants, cancellation/recovery and lock limits. MySQL requires direct
  grants and read-only transactions; SQL Server relies on effective permission
  checks, not a read-only transaction flag.
- [ ] Mount the approved public CA bundle through `deploy/compose.trust.yaml` and
  set `SOURCE_DATABASE_CA_FILE` for PostgreSQL/MySQL/SQL Server. Verify certificate identity
  checks and failure on untrusted or wrong-name certificates. PostgreSQL must use
  `sslmode=verify-full`, including existing registrations. Use `SOURCE_CLOUD_CA_FILE` only
  where private cloud endpoints require the hospital CA.
- [ ] Review cloud IAM/SAS permissions separately from the connection check.
  Confirm resource scope, read/list-only access and expiry; account for KMS grants
  where needed. Test expired credentials and permission loss without exposing
  signed URLs or credentials in reports/logs.
- [ ] Obtain approval for findings, audit, exported-report, and backup retention.
  Record findings and audit retention in the application before scanning. Record
  exported-report and backup retention in hospital policy, with named owners and
  separate purge procedures; application cleanup does not remove those copies.
- [ ] Exercise expiry while a scan is running or paused. Confirm stored findings,
  coverage objects and evidence are removed, new expired writes are rejected,
  and the minimal active-scan marker disappears after worker release. Verify
  startup recovery and bounded backlog cleanup; do not equate cleanup with memory
  zeroization, physical database erasure or removal from independent backups.
- [ ] Exercise administrator credential replacement with success, failed credentials,
  and an active scan. Preserve source identity/history and prior credentials on a
  failed check; keep secrets out of responses and audit detail.
- [ ] Record whether the pilot uses default classification-only scans or optional
  capture of actual matching values/excerpts. Include encrypted captured evidence
  in finding and backup retention. Confirm operators can request capture but only
  administrators/reviewers can reveal it, with an audit event for every reveal.
- [ ] Record the permitted scan window **with timezone**, approved concurrency,
  CPU/I/O/latency budget, monitoring owner, and explicit stop thresholds. Confirm
  measured scanner capacity rather than treating staging sizing as a hospital limit.
- [ ] Prove approved source reachability while internet, unauthorized internal
  destinations, public DNS/HTTPS, and unauthorized IPv6 traffic are blocked.
  Keep the parser off source-access networks. Cloud storage requires exact
  `CLOUD_HOST_ALLOWLIST` entries and private-only DNS answers/routes; preserve the
  default-deny firewall. Approve the fixed IMDSv2 route separately only when using
  an EC2 instance role. Repeat install/start/scan with public internet blocked and
  only the approved private source routes available.
- [ ] Complete pause/cancel, worker restart, temporary-file cleanup, session/role,
  and encrypted backup/restore checks using an isolated test scope.
- [ ] Restore a matching release/schema with the original `APP_SECRET_KEY` and
  `SESSION_SECRET`, keeping API, worker, web/ingress stopped and discovery-source
  routes blocked. Follow the [restore procedure](runbook.md#retention-backup-and-recovery)
  and run `python -m app.cli prepare-restored-catalog --retention-days N --audit-retention-days M --confirm-isolated-restore`
  with current hospital-approved periods, each 1–3650 days, before exposing services.
  Confirm `offline_preparation_completed`, drained expiry, revoked sessions, disabled restored users/sources,
  cleared heartbeats, cancelled old scan work and revoked full-scan approvals.
- [ ] Bootstrap a currently authorized administrator with `init-admin` and a fresh
  username after preparation; existing disabled names cannot be reused by that command.
  Review other account authorization, retained decryption/evidence/review history and
  comparison identities. Approve source scopes/grants and private routes before
  administrator connection checks; keep the worker stopped until source safety
  is revalidated and workload limits are reapproved. Start new scans explicitly.
  The passing synthetic drill covers same-release restore only; its API checks
  do not exercise ingress/TLS. It does not establish the hospital's encrypted
  backup, key custody, site isolation or recovery acceptance.

## 3. Validate detection and coverage

- [ ] Have hospital reviewers annotate representative calibration and held-out
  sets separately. Exclude overlapping patients/documents and near duplicates
  across splits; retain sufficient positive and negative cases per class.
- [ ] Test Indian names/initials, patient versus clinician names, Aadhaar/PAN/ABHA,
  hospital identifiers, clinical free text, declared patient relationships, and
  multi-patient documents without cross-patient diagnosis association.
- [ ] Include JSON/JSONL/XML sibling and nested records, serialized payloads in
  database cells, explicit Patient Name headers and malformed structures. Confirm
  another record's identity never supplies linkage or an excerpt; review missed
  legitimate associations caused by conservative parent/child separation.
- [ ] Test digital documents, printed scans, mixed PDFs, poor OCR, encrypted/corrupt
  files, unsupported languages/handwriting, missing permissions, truncation,
  interrupted scans, and source changes during reads. Include S3/Blob ETag changes,
  object listing pagination/limits, and Azure Table entity/partition boundaries for
  each cloud connector in scope; local emulator results are not provider acceptance.
- [ ] Evaluate from original source through extraction/OCR to final findings.
  Report sample sizes, precision/recall, and coverage separately for databases,
  digital documents, and OCR. The initial target is **at least 95% precision and
  recall per priority class**, not an established performance claim.
- [ ] Declare `priority_classes` for all three categories in the held-out manifest.
  Use exhaustive value-occurrence annotations, the production Presidio
  detector, at least 30 positive/30 negative original objects per category/class
  and a target of at least 0.95. Review every
  `acceptance_blockers` entry. Do not reuse the same original object as multiple
  samples or treat a machine-generated candidate flag as hospital acceptance.
- [ ] For clinical priorities, provide complete version-3 original-record
  annotations including negatives, and inspect clinical-presence and exact
  patient-reference association metrics. Use `json_pointer_v1` for supported native
  `.json` records, `text_spans_v1` for reviewed original `.txt`/`.md`/`.log` spans,
  `database_primary_key_v1` for typed-primary-key SQLite reference exports, or
  `document_rectangles_v1` for eligible original PDF pages/raster frames. Wrong/swapped
  references must yield FP and FN; repeated equal identifiers in different records
  remain distinct. Do not use detector segment or generated region IDs as gold record locators.
- [ ] Bind independent document rectangles to original file SHA-256, page/frame
  ordinals and complete rendered dimensions in `rendered_unit_normalized_v1`.
  Include all records and negative/background regions; nonoverlapping rectangles
  must own every observed word exactly once. Check that mixed/unmapped predictions
  remain errors and missed positive records remain false negatives. Review
  automatic compact, stacked and supported column candidates against these
  annotations; do not derive the gold rectangles from detected regions.
- [ ] Keep unsupported mappings visible: XML, CSV/TSV, Office and unknown embedded
  structures do not have supported version-3 record mappings; PDF/raster mappings
  require validated original geometry and independent rectangles. Version-2 PII
  metrics do not establish original record/page/span identity, and version-3
  association is not semantic diagnosis extraction. Schema-only PII occurrence
  classes remain unsupported; object-label presence is diagnostic only. Keep
  private gold keys/pointers/values out of aggregate evaluation reports.
- [ ] Check every original PDF page and supported image frame against its
  render/OCR status, including blank and failed units. Images are full only when
  all frames complete without limits and no uninspected nonvisual metadata is
  present. Native-bearing PDFs remain partial while original native representation
  is unverified. Only blank/raw-pixel image-only PDFs may be full after every
  zero-native-operation, ancillary, geometry and complete-OCR gate passes.
  Encoded JPEG/JPX/JBIG2 metadata remains partial. A clean feature manifest or
  complete page OCR alone cannot clear these gaps; keep mixed PDFs in the set.
- [ ] Exercise connected native/OCR line groups with differing column grouping,
  distinct repeated values, side-by-side patients, missing/conflicting words,
  competing overlaps, off-page native text and overprinted text. Coalescing must
  require complete mutually unique exact-NFC word correspondence with verified
  positions; uncertain groups retain whole OCR lines, and removed lines must not
  join residual fragments. Check that accounted-PDF Tika fallback requests
  `sortByPosition` with overlapping-text deduplication disabled and is omitted
  only for equal ordered text on the same original page after NFC/whitespace
  normalization. Outside-page, unmatched/unmapped and returned embedded content
  must survive as unlinked supplements. Unverified layout must not establish
  patient linkage. Do not treat observation reconciliation as full native-text
  representation or unique-patient counting.
- [ ] Reconcile every approved object against full, sampled, partial, inaccessible,
  unsupported, excluded, or failed coverage. Keep no-match sampled results explicit;
  match counts must never be presented as unique patients.
- [ ] Check source changes, detector changes, unchanged exclusions, reduced sampling,
  and lost access across repeat scans. Missing observations must not be described
  as successful removal. Confirm reports/logs contain no raw patient values.
- [ ] Check object counts separately from finding-group deltas. Groups identify
  detected type, classification, reason and segment; before/after counts are
  recognizer matches, not unique values or patients. Exercise new, changed,
  unchanged and no-longer-observed groups without loading matching values or excerpts.
- [ ] Verify that attributed finding deltas require full comparable object reads,
  matching detector/policy and known runtime provenance. New objects also need a
  baseline without coverage gaps. Missing/partial/sampled content must show
  unknown finding changes instead of removal. Evidence-capture changes alone
  must not change eligibility.
- [ ] Compare against a legacy scan with no runtime marker and an external-parser
  run with unknown provenance: both must require a new baseline. Changing the
  packaged API or Tika image must change the generated runtime identity; web-only
  changes must not. Native local runs without Tika use a package-inventory hash.
- [ ] Check capture off by default; three-example, 256-character value and
  400-character excerpt limits; segment boundaries; OCR errors; and legitimate
  empty evidence for context/schema-only findings. Do not equate examples with
  all matches or infer stable database keys/PDF page locations from segment labels.
- [ ] Confirm ordinary finding lists and CSV/JSON exports omit captured evidence,
  storage is encrypted, reveal responses are not cached, and evidence is deleted
  with its finding. Upgrade a restored older catalog and verify old findings
  remain intact without invented examples; obtaining examples requires a new scan.

## 4. Approve staged expansion

- [ ] Start with one database query at a time, batches of at most 100 rows, and
  at most **1,000 sampled rows per table**. Where supported, use a five-second
  statement limit and one-second lock-wait limit. Measure source impact during
  the agreed window and verify the stop procedure.
- [ ] Verify a simultaneous API connection check and worker scan cannot query the
  same configured relational database. Use a canonical hostname/IP and database
  spelling; separate aliases/catalogs/standalone scripts are outside that shared
  lock. Keep other hospital workload monitoring and stop thresholds in place.
- [ ] Before full reads, record source-specific workload approval and an explicit
  table/folder scope. Full database scans require a selected table list. Use a
  replica/export when a complete live read cannot meet the operating budget.
  Azure Table remains sampled-only (at most 1,000 entities); its key-ordered sample
  is not random or representative, and there is no full-scan approval override.
- [ ] Have hospital reviewers accept findings, documented coverage gaps,
  unsupported formats, accuracy evidence, and remaining limitations for the
  agreed pilot scope. Record unresolved items with owners and disposition.

**Decision:** pending / approved for named pilot scope / rejected  
**Hospital decision owner:** ____________________  
**Scope and release reference:** ____________________  
**Evidence location and date:** ____________________  
**Open limitations and follow-up owners:** ____________________
