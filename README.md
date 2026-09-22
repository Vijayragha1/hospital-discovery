# Hospital Discovery

A self-hosted discovery pilot for PII and patient-linked health information across approved databases, file servers, and privately routed cloud storage. It includes a FastAPI API, PostgreSQL findings catalog, separate scan worker and React dashboard. Presidio/spaCy run locally; Tika/Tesseract process documents and printed English scans. No LLM service or OpenMetadata dependency is required.

**Deploy from GitHub:** follow the [deployment guide](docs/deploy-from-github.md) to download the tested offline bundle from this private repository's Releases, verify it, and install it inside the client environment. The hospital host does not need GitHub or internet access. GitHub's source-code archives do not include the runtime images or NLP models.

The deployment is portable to a client-controlled Linux VM, either on hospital premises or in approved private cloud infrastructure. Hosting placement is still undecided. The hospital's actual installation, private routing/egress controls, encrypted storage and acceptance remain outstanding; the local demonstration is not that deployment.

Implemented workflows include authenticated roles, source registration/connection checks, scan controls, explicit coverage gaps, finding review, audit history, repeat-scan comparisons and local reports. Sensitive source configuration, paths and review notes are encrypted at the application layer. Connectors issue read/list operations; hospital-approved credentials must independently prohibit writes.

Repeat-scan comparisons show object coverage and changes in finding groups, with baseline/current recognizer-match counts. A group is a detected type, classification, detection reason and segment; these counts are not unique values or patients. Finding deltas require complete comparable reads with matching detector/policy and recorded processing-runtime identity. Sampled content, lost access, legacy scans without runtime identity and parser changes cannot establish disappearance. "No longer observed" is never proof of removal.

JSON/JSONL/XML records and nested structured database values are segmented before detection. CSV/TSV keeps ordinary cells in their row but separates standalone JSON/XML cells into independent records; a nested record does not inherit the containing row's patient identity. Malformed nested cells remain partial and disable patient linkage. Explicit patient-name/ID/MRN/UHID headers accept `:`, `#` and `=` separators across LF, CRLF and CR line endings without rewriting original text offsets. These boundary rules do not establish patient-to-diagnosis association accuracy.

PDFs and supported raster files can also use validated transient word positions to infer candidate patient records in compact forms, stacked forms and supported two-column layouts. An explicit unique patient reference is required within each candidate. Identity never crosses pages/frames, native/OCR channels or removed duplicate-line barriers. Uncertain regions and unmapped Tika content remain unlinked while their PII and clinical content are still detected. Coordinates and processing text are not retained. This is a conservative heuristic requiring hospital calibration, not established patient-association accuracy; see [document discovery](docs/document-discovery.md).

Administrators add sources through a guided flow: choose a connector, enter its connection details, then review and connect. The application shows deployment-approved hosts and folders, checks the connection before saving, and gives connector-specific guidance when a check fails. Implemented connectors are PostgreSQL, MySQL, Microsoft SQL Server, SMB / Windows shares, mounted folders, S3-compatible storage, Azure Blob Storage, and Azure Table Storage. SQLite is available only for development fixtures. Cloud scope is one named bucket/container/table; Azure Table scans sample at most 1,000 entities. Connecting a source does not start a scan or bypass retention and workload approvals.

By default, scans retain classifications and locations without matching values or excerpts. Enable **capture evidence** for a new scan to retain up to three encrypted examples per finding, with a matching value of at most 256 characters and a surrounding excerpt of at most 400 characters. Administrators and reviewers can reveal these examples on demand; each reveal is audited. Operators may enable capture but cannot reveal evidence. Normal finding lists and CSV/JSON reports remain free of captured values and excerpts. Existing scans need a new scan to capture evidence; original source files are not retained.

This is **pilot software, not a hospital-validated production release**. The actual HIS engine, version, cloud endpoints, and account grants still require hospital inventory and acceptance. MySQL is restricted to 8.x/9.x InnoDB with direct read-only grants; SQL Server compatibility must be verified against the actual deployment. The isolated OCR helper inventories original PDF pages/image frames and records each native-extraction/render/OCR outcome. Supported raster files can be fully processed when all frames succeed and no uninspected nonvisual metadata is present. Office/Tika-only results remain partial. Rules-only development mode has no name/address NER. Neither synthetic tests nor a completed scan establish the 95% accuracy target.

Release **`20260922035303`** resolves verified native-PDF column grouping and preserves repeated identifiers. **743 tests and 44 subtests passed**; packaged Presidio checks pass exact fixture metrics for ten originals without special exceptions. Native PDFs remain partial and hospital accuracy remains unvalidated. See the [validation record](docs/implementation-validation.md).

Historical release **`20260922034011`** added automatic labelled document-record candidates and independent page/frame rectangle evaluation. **705 tests and 44 subtests passed**; its packaged Presidio checks covered 9 synthetic originals, including an explicitly failing native-column accuracy case retained as historical evidence. Current PDF reconciliation behavior is described below. Hospital acceptance remains pending. See the [validation record](docs/implementation-validation.md).

Historical release **`20260922024917`** added safe offline catalog restoration: restored sessions, accounts, sources and old jobs are quarantined, original encryption/comparison keys are checked, and current approved retention is drained before reopening access. The [validation record](docs/implementation-validation.md) records 508 passing portable tests and a 30-check synthetic PostgreSQL backup/restore drill. Hospital deployment and acceptance remain pending.

The preceding boundary release **`20260922022904`** hardens CSV/header boundaries, suppresses patient linkage from unverified raster layouts, and preserves embedded-image frame boundaries through hOCR. PII and clinical-content findings remain available; complete raster processing does not prove a patient-record layout. Original synthetic DOCX checks detected typed identifiers, embedded-image text and both frames of an embedded TIFF with distinct segments. Office coverage remains partial because independent embedding inventory is unverified.

The [release summary](fixtures/evaluation/boundary-release-validation.json) records 488 passing regression tests and 44 subtests, 26 packaged original-file boundary checks, 17 PDF checks, 32 HTTPS checks and 10 comparison checks. Offline image/model loading, blocked default egress, source/image identities and runtime stamps passed. Earlier platform-specific parser, UI and live-connector checks are historical, as detailed in [the validation record](docs/implementation-validation.md). Packaged OCR and record evaluation remain synthetic and explicitly fail acceptance prerequisites.

The PDF path reconciles whole connected groups of overlapping native/OCR lines only when every word has a mutually unique counterpart with equal NFC-normalized text and verified spatial agreement on the same original page. This resolves differing column grouping when the complete group matches, preserves real repeats at different positions, and retains uncertain observations. Only whole matched OCR lines are removed; their boundaries cannot join residual fragments. The accounted-PDF Tika fallback requests `sortByPosition` with overlapping-text deduplication disabled, then applies an exact ordered same-page text comparison after NFC/whitespace normalization. Unmatched or unmapped pages, outside-page text and returned embedded content remain unlinked supplements. Native-bearing PDFs remain partial because off-page and overprinted text representation is not independently proven. Only blank or simple raw/lossless-pixel image-only PDFs can become full, requiring zero native text operations, strict absence of uninspected ancillary content, verified geometry and complete page OCR. Encoded JPEG/JPX/JBIG2 image metadata keeps PDFs partial; successful visible OCR cannot clear that gap.

Version-2 evaluation scores exact value occurrences within each original file or database-column object. Version 3 adds original-record clinical presence and exact patient-reference association for supported native JSON/text records, typed-primary-key SQLite reference exports, and independently reviewed original PDF-page/raster-frame rectangles. Document gold binds to original file bytes, dimensions and unit ordinals; algorithm-generated region IDs cannot serve as reference annotations. Missing or mixed records remain errors, and partial coverage cannot pass accuracy acceptance. CSV/TSV, Office and unvalidated document geometry remain unsupported association mappings; these metrics do not score semantic diagnosis relationships. Both database and file-share pilot categories are confirmed, but the exact approved sources, hosting, operating limits and hospital reference data remain site inputs. See the [pilot completion audit](docs/pilot-status.md).

## Run and deploy

See [the runbook](docs/runbook.md) for offline packaging, source-network isolation, hospital certificates, read-only grants, workload gates, retention and recovery. Deployment does not automatically turn on routed source access. PostgreSQL, MySQL and SQL Server require a mounted trusted CA through `deploy/compose.trust.yaml` and `SOURCE_DATABASE_CA_FILE`; PostgreSQL uses `sslmode=verify-full`. API checks and worker scans share a lock for each configured relational database. Cloud sources require `CLOUD_HOST_ALLOWLIST`, private endpoint DNS, and an explicit firewall-approved private route. No unrestricted internet route is needed.

The evaluation report declares acceptance blockers, including missing priority classes for database/digital/OCR categories, insufficient evidence, rules-only inference, unsupported record mappings and incomplete coverage. A candidate requires the production detector, exhaustive matching-value annotations and at least 95% precision/recall with 30 positive and 30 negative source objects per required class/category. Clinical priorities additionally require complete version-3 record annotations and passing clinical-presence/association measures. Object-label presence is diagnostic only. Missing hospital-reviewed document rectangles, unvalidated geometry and partial required content still block the relevant accuracy acceptance; every candidate also needs hospital review.

```sh
# Online staging machine, from this directory:
python3 scripts/bundle.py build /secure/staging/hospital-discovery-bundle --platform linux/amd64

# Offline hospital machine, after transferring the entire bundle:
python3 scripts/bundle.py install /secure/received/hospital-discovery-bundle
```

The bundle includes runtime images, local NLP/OCR data, compiled UI assets, image IDs/digests, dependency inventories, manifests, checksums and install scripts. Hospital secrets and source data are not bundled. Retain the exact image archive for reproducible installation; source rebuilds can change transitive dependencies. Keep `deploy/compose.images.yaml` in every deployment command: it pins the platform/images and stamps both API and worker with a processing-runtime identity derived from the immutable API/Tika images. This records the supplied deployment, not remote attestation of a different parser; never copy an old identity across runtime changes.

## Documentation

- [Discovery flow diagram](docs/discovery-flow.md)
- [Document layout, patient candidates and independent evaluation](docs/document-discovery.md)
- [Implemented behavior, executed validation and remaining limits](docs/implementation-validation.md)
- [Requirement-by-requirement pilot completion audit](docs/pilot-status.md)
- [Operator runbook and release gates](docs/runbook.md)
- [Hospital inventory template](docs/hospital-inventory.csv)
- [Hospital pilot acceptance checklist](docs/acceptance-checklist.md)
- [Supported connectors, formats and honest coverage limits](docs/supported-formats.md)
- [Database safety, verified TLS, concurrency and limits](docs/database-connectors.md)
- [S3 and Azure scope, credentials, private routing, and limits](docs/cloud-connectors.md)
- [Evaluation method](docs/evaluation.md)
- [Dependency/license notes](docs/licenses.md)

Open source components provide parsing and detection primitives. Their output still needs a representative hospital reference set, clinical-context review and documented workload limits before a live rollout.
