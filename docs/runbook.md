# Hospital operator runbook

## Release status and deployment gate

This is a pilot implementation. Hospital accuracy, production workload limits and end-to-end deployment acceptance require the local reference set and hospital sign-off. A successful synthetic test does not establish 95% precision/recall. The isolated OCR path accounts for original pages/frames; supported raster files can be full when all frames complete and no nonvisual metadata remains uninspected. Native-bearing PDFs and Office/Tika-only extraction remain partial. The narrow blank/raw-pixel image-only PDF eligibility rules are described below.

The [pilot completion audit](pilot-status.md) separates outstanding product work from hospital inputs. The release includes exact spatial PDF line reconciliation and version-3 original-record clinical presence/patient-reference evaluation for supported native JSON/text and typed-key SQLite reference exports. Native PDF representation proof, uninspected ancillary content, and arbitrary PDF/OCR/Office record mappings remain open. Record association is not semantic diagnosis extraction.

The recovery release adds isolated restored-catalog preparation to the discovery behavior below. Its [release evidence](../fixtures/evaluation/recovery-release-validation.json) records 508 passing regression tests and 44 subtests, with no skips, errors or failures and two dependency warnings, plus 30 actual PostgreSQL backup/restore checks. Use the release identity and runtime stamp recorded in that summary and the generated image override; never copy a stamp into a different runtime. Prior boundary-release, parser, UI and live-connector checks remain historical in the [validation record](implementation-validation.md). Repeat site-specific checks on the chosen hospital host; synthetic verification is not hospital acceptance or Office completeness proof.

Record the hospital, owner, approved sources, source engine/version, volume, language, scan window, retention policy and workload budget before adding credentials. Implemented database adapters are PostgreSQL, MySQL 8.x/9.x InnoDB, and Microsoft SQL Server. MySQL rejects MariaDB, non-InnoDB tables and active roles; use dedicated direct read-only grants. SQL Server version/driver compatibility must be validated against the hospital deployment; do not infer a validated version range from a generic driver. S3, Azure Blob and Azure Table use explicitly named resources over approved private routes; see [cloud connector requirements](cloud-connectors.md).

Hosting placement has not been chosen. The same self-hosted bundle can run on a client-controlled Linux VM on hospital premises or in an approved private cloud network. Record the chosen owner/location, connectivity to each source, backup destination and key custody before installation. A developer-host preview or successful synthetic container test does not prove the hospital's installation, egress restrictions, encryption or source access.

Use a Linux host with Docker Engine and Compose v2, Python 3.10+, an encrypted data volume and swap disabled or encrypted. Docker Engine 29 was validated for building and installation. Installation requires support for `docker image inspect --platform`; building additionally requires `docker image save --platform`. Confirm these capabilities before transferring the bundle to an offline host. Begin staging evaluation with 8 vCPU, 16 GiB RAM and at least 30 GiB free disk; measure real working set before choosing hospital capacity. Store Docker data, backups and exported reports on encrypted hospital storage. Application encryption protects sensitive fields, not every database field or filesystem metadata; Docker volumes are not automatically encrypted.

## Build on an approved online staging machine

From the repository root:

```sh
python3 scripts/bundle.py build /secure/staging/hospital-discovery-bundle --platform linux/amd64
```

The builder resolves base-image tags to immutable registry digests before building. It installs the versioned backend requirements, npm lockfile and spaCy `en_core_web_lg` 3.8.0; builds Tika 3.3.2 with English Tesseract, Poppler, Pillow and the private page/frame gateway; compiles the bounded PDF feature inspector against that exact Tika jar in a staging JDK; verifies the Apache artifact's signature against Apache's published keys; captures image IDs and installed package inventories; tests offline model loading; exports all runtime images; and writes SHA256SUMS. The runtime image does not need a JDK or runtime dependency downloads. No client data belongs on this machine.

The builder also computes `DISCOVERY_RUNTIME_ID` from versioned canonical metadata containing the immutable API and Tika image IDs. API images contain the detector, NLP model and native-extraction dependencies; Tika images contain the document parser, Tesseract and OCR language data. Web-only and catalog-only changes do not alter this identity. `release.json` records it, and `deploy/compose.images.yaml` supplies the same 64-character hexadecimal value to both API and worker while pinning every service's image and platform.

Only staging build steps fetch dependencies. Registry digests and inventories capture the actual release; a subsequent source rebuild can resolve different OS/transitive packages. To reproduce an approved installation exactly, retain the built image archive and manifest. `--base-lock path/to/base-images.lock.json` reuses base digests on source rebuilds. For stricter source reproducibility, freeze transitive Python and OS repositories using the generated inventories before a release rebuild. Do not advertise byte-identical source builds.

Review dependency licenses and vulnerabilities using the inventories before approving a release. The Apache KEYS file is downloaded over HTTPS during the build; verify the release signer fingerprint independently under the hospital's supply-chain policy. Keep manifests with change approval. SHA256SUMS detects corruption; establish bundle provenance by signing or transporting its checksum through a separately trusted channel.

## Offline install

Transfer the complete bundle directory through the hospital-approved channel. Provision Docker/Compose beforehand; the install script never installs host tools or contacts a registry.

```sh
python3 scripts/bundle.py verify /secure/received/hospital-discovery-bundle
python3 scripts/bundle.py install /secure/received/hospital-discovery-bundle
cd /secure/received/hospital-discovery-bundle
python3 scripts/configure_deployment.py --source-mount /srv/hospital/discovery-input
```

The configuration generator refuses to overwrite secrets. Its `.env` is mode 0600 and contains a distinct encryption key, session secret and catalog password. Escrow both `APP_SECRET_KEY` and `SESSION_SECRET` separately from the catalog. Losing the encryption key makes encrypted credentials and locations unreadable; the session secret also determines stored comparison identities. Replacing either is not a supported rotation procedure. Restrict Docker administration to trusted operators because administrators can inspect containers and environment variables.

Install a hospital-issued certificate as `deploy/certs/server.crt` and its private key as `deploy/certs/server.key`, readable only by container UID/GID 10001 and authorized host administrators. Caddy uses those files and does not request external certificates. For staging only, a self-signed certificate may be supplied and explicitly trusted by the staging browser. Set the intended intranet bind address in `.env`; the default is loopback.

Mount the hospital's approved share read-only at `/srv/hospital/discovery-input` before starting. The container bind is also read-only. A dedicated account must lack create/update/delete permissions on source systems. The source directory must already exist; a typo must not silently create an empty source.

```sh
cd deploy
docker compose -f compose.yaml -f compose.images.yaml config --quiet
docker compose -f compose.yaml -f compose.images.yaml up -d --pull never --no-build
docker compose -f compose.yaml -f compose.images.yaml exec api python -m app.cli init-admin --username hospital-admin
```

Enter the administrator password at the prompt. Open `https://<hospital-host>:8443`, verify the certificate, log in, approve retention settings and register the approved sources. The starting retention values are 30 days for findings and 365 days for audit history, **unapproved**; scanning is blocked until an administrator records hospital-approved settings. Change any staging identity before production. Use reviewer accounts for classification reviews and operator accounts for scanning.

## Network containment and source reachability

Catalog, parser and frontend service networks are internal. This intentionally prevents API/worker reachability to routed database, SMB and cloud endpoints. It is suitable for mounted-file scanning and isolated demonstrations. The parser has only its internal network and no host port. Catalog PostgreSQL is never published. All UI scripts, fonts and models are local.

TLS ingress uses a separate ordinary Docker bridge because an internal-only bridge does not provide published host ports on the validated Docker runtime. A minimal `ingress_guard` helper owns the published web network namespace. It resolves the internal API address, installs default-deny IPv4/IPv6 packet rules and becomes healthy only after rules succeed. Non-root Caddy shares that namespace and starts afterward. Outbound packets are limited to established connection replies and the resolved API IPv4 address on TCP 8765; DNS and all other new outbound traffic are blocked. IPv6 ingress is disabled for this pilot. The helper alone runs as root with namespace-scoped `NET_ADMIN`; Caddy/API/worker/parser receive no such capability. No host networking, Docker socket or source data is mounted into the helper.

The Docker host must support the helper's namespace firewall capability. If policy prevents it, ingress stays unavailable; do not remove the guard to make the UI work. Keep the hospital perimeter firewall as defense in depth. Because the upstream address is fixed when the guard starts, recreate the guard and web together after replacing the API container:

```sh
docker compose -f compose.yaml -f compose.images.yaml up -d --force-recreate ingress_guard web --pull never --no-build
```

For live sources, the hospital administrator must first provision a Docker network with host/perimeter firewall rules. Then use the explicit `compose.sources.yaml` override to connect **only** API/worker to it. Docker's ordinary bridge networking is not an egress denylist; the override alone does not block outbound traffic. Apply the firewall before starting any connector-enabled service, including traffic to the host, other internal services, DNS and IPv6. Docker-published ports can bypass uncomplicated host firewall rules: test effective packet flow with Docker's firewall chains or an upstream firewall.

| Direction | Allowed destination | Ports/purpose |
|---|---|---|
| Analyst subnet → web | Approved scanner VM | TCP 8443 (or hospital reverse proxy) |
| API/worker → source | Each approved database IP only | PostgreSQL TCP 5432, MySQL TCP 3306, SQL Server TCP 1433, or recorded source port |
| API/worker → private storage | Each approved S3/Azure private endpoint IP only | TCP 443 or explicitly recorded HTTPS endpoint port |
| API/worker → EC2 identity (optional) | Fixed IMDSv2 address `169.254.169.254` | TCP 80; only for approved EC2 instance-role authentication |
| API/worker → source | Each approved SMB IP only | TCP 445 |
| API/worker → DNS | Hospital resolver only, if hostnames used | UDP/TCP 53; omit if IPs suffice |
| Host → clock | Hospital time service if required | Host only; no parser egress |
| Any scanner container → internet/other IPs | None | Deny all IPv4 and IPv6 |

Permit established replies and required local catalog/API/parser flows; deny other new flows. Tika must never join source-access networking. Set `DATABASE_HOST_ALLOWLIST`, `SMB_HOST_ALLOWLIST`, and `CLOUD_HOST_ALLOWLIST` to exact approved names in `.env`; these application checks supplement the network firewall. Cloud HTTPS endpoints must resolve exclusively to approved private addresses, using S3/VPC or Azure private endpoints. Public or mixed public/private DNS responses are rejected, including in development. The storage firewall exceptions must remain private and explicit; do not enable internet access to make a check pass. An EC2 instance role requires a separately approved fixed IMDSv2 route, not arbitrary metadata or credential-provider URLs.

```sh
# The hospital administrator creates this approved network with its firewall policy first.
# Set SOURCE_NETWORK=<approved-network-name> in .env.
docker compose -f compose.yaml -f compose.images.yaml -f compose.sources.yaml up -d --pull never --no-build
```

Prove public DNS/HTTPS, unauthorized internal addresses and IPv6 destinations are blocked, while the approved source connection succeeds. Preserve test evidence without credentials or patient content. No cloud analytics, telemetry or LLM endpoints are required.

### Trust for source connections

PostgreSQL, MySQL and SQL Server require `SOURCE_DATABASE_CA_FILE`, an absolute path to a trusted PEM bundle inside the API/worker containers. PostgreSQL uses `sslmode=verify-full`, the deployment CA, a TLS 1.2 minimum and disabled GSS encryption; the source's configured name/IP must pass libpq identity verification. MySQL and SQL Server verify certificate subject alternative names; SQL Server supports a matching DNS name or IPv4 address. There is no browser bypass or browser-supplied trust path. Existing PostgreSQL registrations must have this CA configured before their next check or scan; preflight rebuilds TLS settings rather than preserving a weaker stored DSN.

For cloud endpoints signed by a private CA, set `SOURCE_CLOUD_CA_FILE`; otherwise the SDK's verified trust store is used. Keep this public-certificate directory separate from client keys and secrets, readable by the non-root runtime. Add these deployment settings to `deploy/.env` after creating the approved directory:

```dotenv
SOURCE_TRUST_DIR=/srv/hospital/discovery-trust
SOURCE_DATABASE_CA_FILE=/source-trust/database-ca.pem
# Optional when private storage uses a hospital-issued certificate:
SOURCE_CLOUD_CA_FILE=/source-trust/cloud-ca.pem
```

Only set the optional cloud path if that file exists. The trust override mounts the directory read-only and does not add networking. From the deployed bundle's `deploy/` directory, include both approved overrides when needed:

```sh
docker compose -f compose.yaml -f compose.images.yaml -f compose.sources.yaml -f compose.trust.yaml config --quiet
docker compose -f compose.yaml -f compose.images.yaml -f compose.sources.yaml -f compose.trust.yaml up -d --pull never --no-build
```

Keep the same override set for subsequent operations on this deployment. See [cloud networking and SAS requirements](cloud-connectors.md) for private endpoint DNS, precise SAS scope/expiry, S3 instance-role limitations and containment tests.

Always retain `compose.images.yaml`, including when enabling source/trust overrides or recreating services. Do not copy an old `DISCOVERY_RUNTIME_ID` into a changed runtime or invent one manually. Rebuild the approved bundle and use its generated override when API, model, parser, OCR data or processing dependencies change. The identity records the supplied image deployment; it does not remotely attest an arbitrary `TIKA_URL`. An altered external parser must not reuse the supplied parser's identity.

## Registering a source

Sign in as an administrator and open **Sources → Register source**. Follow **Choose source → Connection details → Review & connect**, using **Continue** and **Back** to check the scope before selecting **Connect source**. The displayed hosts and folders come from the deployment allowlists; the application does not search the hospital network or browse the administrator's computer. SQLite appears under development fixtures only in development mode. Choices are grouped under **Databases**, **File shares**, and **Cloud storage**. Unsupported HIS engines need a validated connector before registration; the form does not enumerate cloud resources.

| Connector | Details to prepare |
|---|---|
| Mounted folder | Choose an approved root as seen inside the scanner containers, then optionally enter a relative subfolder such as `Pilot`. With the supplied deployment, the host's `SOURCE_MOUNT` appears as `/sources`; the location is not the host path or a laptop folder. |
| PostgreSQL / MySQL / SQL Server | An approved server, database, dedicated read-only username and password, plus deployment CA trust. Defaults are PostgreSQL `5432/public`, MySQL `3306` with schema equal to the database name, and SQL Server `1433/dbo`. Open **Advanced** to narrow table scope. Blank table selection covers the schema for bounded sampling; full scans require explicit selected tables and separate workload approval. SQL Server uses SQL authentication and a DNS name or IPv4 address matching its certificate. |
| SMB / Windows share | An approved server, share name, optional relative subfolder, and dedicated read-only account. Paste a Windows network path and select **Use path** to fill the location fields, or enter them separately. Enter the domain separately only when the account name does not already include it. The connector requires encrypted SMB. |
| S3 / compatible storage | Approved HTTPS endpoint, region (initial default `ap-south-1`), named bucket and optional exact prefix. Choose a dedicated access key/optional session token or the scanner’s approved EC2 instance role. No bucket enumeration. |
| Azure Blob Storage | Approved Blob account HTTPS endpoint, named container, optional exact blob prefix, and container service SAS with read/list (`sp=rl`, `sr=c`), HTTPS-only and explicit expiry. ADLS Gen2 is accessed through this Blob endpoint. |
| Azure Table Storage | Approved Table account HTTPS endpoint, named table, optional exact partition key, and table service SAS (`tn=<table>`, `sp=r`), HTTPS-only and explicit expiry. Samples at most 1,000 entities; no full-table mode. |
| SQLite development fixture | An existing fixture database file beneath an approved scanner directory. This is unavailable in production. |

Review the selected scope before connecting. Passwords, access keys/session tokens and SAS tokens are masked in the review summary. Changing connector type clears the prior connection details; changing S3 authentication mode clears key credentials. The application performs the connector checks and saves the source only after they pass; a failed check does not save its source configuration or credentials. Saved credentials are encrypted locally and are never returned by source-list responses. Connection errors and audit events use fixed diagnostic text and identifiers, without passwords or source content.

For a failed check, use the connector-specific guidance:

- If a host or folder is not approved, ask the hospital deployment administrator to confirm scope and update the allowlist. The form cannot grant network access or mount a new share. Apply the network containment steps above before enabling routed database, SMB or cloud access.
- For a mounted folder, verify the host mount exists, the container path is correct, and the scanner account can list/read it. A directory check does not prove every child is readable or that host permissions are read-only; enforce the read-only mount and account permissions separately.
- For databases, verify connectivity, engine/version, TLS trust, database/schema/table names, dedicated account permissions and cancellation/recovery. MySQL requires direct grants without active roles; SQL Server validates effective server/database/object permissions and uses TDS attention for cancellation. Do not use a privileged account to make the check pass.
- If a relational database is busy with another application connection check or scan, wait until it finishes and retry. The API returns HTTP 409; this contention does not invalidate an earlier successful safety check. A worker run remains queued until it can obtain the same database lock. Use one canonical hostname/IP and database spelling for the physical database; aliases and separate application catalogs do not share this guarantee.
- For SMB, verify server/share/subfolder spelling, credentials/domain, encryption support and read access. Confirm the account cannot create, change or delete source files during hospital acceptance.
- For cloud storage, verify the exact private endpoint DNS/allowlist, approved route, resource name, region and token expiry/scope. Do not put SAS in the endpoint URL. Empty scopes can pass listing without proving later object reads; review grants independently. Cloud checks use only read/list requests and do not prove an identity cannot write.
- If the local catalog is unavailable, restore application/catalog health and retry. Avoid repeatedly submitting a request whose outcome is uncertain; first check whether the source appeared in the list.

The **Source connected** result confirms that the source is saved and has passed the implemented connection prerequisites; select **Done** to return to the inventory. It has not been fully inventoried or proven safe at production volume. Registration does not start a scan, approve retention, enable evidence capture or authorize a full scan. Review those settings and begin with the bounded defaults below. Existing sources can be checked again from the source list.

### Updating saved source credentials

An administrator can choose **Sources → Update credentials**, enter only the fields to replace and select **Check and save**. Blank fields in this form keep their saved values; the S3 form has a separate **Clear the saved session token** option. Complete or cancel queued, running and paused scans for that source first. The application checks replacement credentials before saving their encrypted configuration; a failed check keeps the previous credentials and safety state. A successful update preserves the source ID, history, scope and existing full-scan workload approval. Updating credentials does not authorize a broader location or resource.

| Source | Replaceable fields |
|---|---|
| PostgreSQL, MySQL, SQL Server | `username`, `password` |
| SMB | `username`, `password`, `domain` |
| S3 with access-key authentication | `access_key_id`, `secret_access_key`, `session_token`; send an explicit empty token to clear an old session token |
| Azure Blob / Azure Table | `sas_token` |

The API equivalent is `POST /api/sources/{id}/credentials`, with a JSON body containing a `credentials` object; only supplied fields are replaced. S3 EC2 instance-role credentials refresh through the role provider and have no manually replaceable fields in this endpoint. Mounted folders and SQLite fixtures have no stored credentials to rotate. Changes and failed attempts audit the source identifier, without credential values. This is source-account credential replacement, not application-encryption-key rotation.

## Scanning and reviewing

1. Connect the approved source and inventory its objects during the first bounded scan. A successful connection check does not establish complete coverage or an acceptable production workload.
2. For each database, record its grant checks, applicable transaction controls, timeout/cancellation/recovery exercise and lock limits. MySQL uses server execution limits/read-only transactions; SQL Server uses effective permission checks, TDS attention and a bounded database-call budget. These adapters cap statement time at five seconds and lock wait at one second; PostgreSQL applies its configured server-side limits. API checks and worker scans share a per-configured-database lock, excluding credentials/schema/table selection from its identity. Keep one worker deployment and observe source metrics before/during/after the bounded pass; the lock does not control other hospital workloads.
3. Start with default sampling. Review findings alongside coverage. A sampled object with zero matches is "no matches in sampled content," not sensitive-data-free.
4. Use pause/resume/cancel controls. These operate at scanner checkpoints; in-flight database operations remain bounded by timeouts, and parser requests may take up to their timeout. Verify restart recovery with synthetic data before live use.
5. Enable full relational database scans only after the source-specific workload gate and authorization. Azure Table stays sampled-only and cannot be expanded through this setting. Full database scans also require an explicit table selection; an empty table list cannot trigger a full database read. Full reads may require a replica/export. Never ignore partial/inaccessible statuses to obtain an attractive completion figure.
6. Review as confirmed, false-positive or needs-review. Feedback is audited; it does not silently retrain recognizers. Export only to approved local encrypted storage.
7. Compare scans with the same source and meaningful scope. Lost access or reduced sampling cannot prove removal. Detector-version changes are reported separately. Never interpret "no longer observed" as deletion or successful remediation.

### Reading comparisons and processing-runtime changes

Choose two completed scans of the same source. The summary cards count **objects** by their comparison state. Each object also shows changes in detected types or **Finding changes unknown** with the reason. Finding groups are keyed by detected type, classification, detection reason and segment. Their baseline/current numbers count recognizer matches; the API's `finding_summary` counts groups, not matches. Neither measure counts unique values or patients. A value can change without changing its finding group's type/count; comparison does not reveal or compare captured patient values/excerpts.

Finding-group deltas require full reads of the current object and its baseline object, matching detector/scan policy, and known processing-runtime identities. A newly inventoried object's findings also require a baseline without coverage gaps; otherwise they may previously have been outside inspected content. Sampled/partial/failed/inaccessible/excluded/unsupported objects, missing objects, changed policy/runtime or unknown provenance produce no attributed finding deltas. Object-level coverage reporting remains visible. Changing evidence capture alone does not change comparison eligibility. A **No longer observed** group means it was absent from a comparable complete read, not that source data was deleted or remediated.

The detector version includes local pipeline/model information and processing-runtime identity. Legacy scans without an identity, or standalone external-parser runs without a valid supplied identity, remain non-comparable for finding attribution even if their old detector strings match. Run a new baseline under the approved deployment. A standalone local run with no `TIKA_URL` or bundle identity records a deterministic hash of installed package names/versions for its native-processing runtime; that inventory is not attestation of an external parser. Invalid configured identities remain unverified. Treat runtime changes separately from source changes and use a new baseline after an approved runtime change.

Native JSON/JSONL/XML and structured database cells preserve independent object/record boundaries. The detector does not carry an outer patient identifier into nested records. CSV/TSV keeps scalar cells together within their row but parses standalone JSON/XML cells as independent records; malformed nested cells remain partial with patient linkage disabled. This deliberately avoids assuming a relationship where the document does not supply one; legitimate parent/child associations can consequently remain unlinked. Malformed, duplicate-key, unsafe XML and depth/text-limited structured input is reported partial. Tika pages/table rows and explicit Patient Name/ID/MRN/UHID text headers with `:`, `#` or `=` also separate detection segments across LF, CRLF and CR line endings without rewriting source offsets. These rules do not validate clinical record semantics on arbitrary layouts or add CSV/TSV mappings to the version-3 evaluator.

### Reading OCR coverage

The supplied deployment configures the private `PAGE_OCR_URL` in the same isolated parser container as Tika. It inventories original PDF pages or supported image frames, then renders and OCRs every permitted unit with English Tesseract. Review original-unit count, completed-unit count, omitted units and each render/OCR status. Empty OCR text can be a successfully processed blank unit; it never proves legibility or absence of missed text. Unit limits, timeouts, decoding failures and text truncation remain visible.

Raster files use one canonical OCR channel. They are full only when every original frame completes without limits and the helper finds no uninspected nonvisual metadata. Metadata-bearing images remain partial even if their visible text was recognized. Validated original-frame word geometry can produce candidate records in supported compact forms, stacked forms and columns; patient linkage additionally requires an explicit unique patient reference within the candidate. Ambiguous regions, unverified geometry and unmapped text remain unlinked while PII and clinical-content detection remain available. These layout heuristics require hospital validation and do not promote processing coverage or establish OCR accuracy. Keep frame boundaries when reviewing multi-patient TIFFs. A disabled or unavailable accounted endpoint cannot silently turn the legacy Tika image path into full coverage.

Tika's embedded-image OCR uses English hOCR output so returned `ocr_page` markers preserve frame boundaries, including embedded multipage TIFFs. Its parser-specific OCR timeout is 45 seconds inside the 60-second Tika task deadline. Original synthetic DOCX checks through the packaged parser detected native identifiers, embedded scan text and both frames of an embedded TIFF in distinct segments, with partial coverage and linkage disabled. They prove those exercised OCR routes, not an independent inventory of every image/frame, other Office formats or hospital scan quality. Preserve partial status and parser limits even when all returned text was inspected.

The PDF path reconciles connected groups of overlapping native/OCR lines on the same original page only when every participating word has a mutually unique counterpart with equal NFC-normalized text and verified spatial agreement. Native and OCR views may group columns into different lines; only whole OCR lines from a fully matched group are removed. Distinct repeated positions remain distinct. Missing or conflicting words, competing overlaps and unsupported geometry retain unresolved observations and disable patient linkage for the affected page channels. Source blocks remain separate, including residual OCR fragments on either side of a removed line. Initial geometry eligibility requires rotation zero, matching zero-origin MediaBox/CropBox, default UserUnit and consistent native/render dimensions. Reconciliation does not make native-bearing PDF coverage full.

Tika remains a native/embedded safety supplement because Poppler can silently omit off-page text. Its page text is omitted only when reliable original-page boundaries and the complete ordered token sequence, including repetitions, match the helper's native text for that same page. Unmatched or unmapped content is retained with duplicate uncertainty. This comparison is not source-text completeness proof. Unverified PDF/raster/Tika record layout disables patient linkage while retaining PII and clinical-content detection.

Native-bearing PDFs remain partial: off-page/overprinted text is not independently accounted for. Only blank or simple raw/lossless-pixel image-only PDFs can be full, requiring zero original native text-show operations, no unexpected native text, strict absence of ancillary/unaccounted features, verified geometry/reconciliation, and complete original-page rendering/OCR without limits. Annotations, attachments, forms/layers, metadata, unknown resources, hidden images and uninspected encoded-image metadata block full coverage. JPEG/DCT, JPX and JBIG2 image streams remain partial because their internal metadata is not inventoried by rasterization. All pages completing OCR, or a clean feature manifest alone, is insufficient. Preserve these limits in reports and comparisons. Office embedded-content inventory also remains partial.

## Matching values and document excerpts

The per-scan `capture_evidence` option defaults to `false`. Leave it off for classification-only discovery. Enable it when starting a new scan if reviewers need examples of the actual matches and their immediate context. Operators and administrators can request capture; only administrators and reviewers can use the on-demand evidence reveal. A reveal is recorded in the audit log using identifiers and counts, without copying patient values into the audit record.

Captured examples are held in a separate encrypted evidence table linked to their findings. Each finding retains at most three examples. Each example contains a matching value limited to 256 characters, an excerpt limited to 400 characters, and offsets within the detector segment. These are selected examples, not an exhaustive list of every match. Values and excerpts can be truncated. Aggregate match counts remain recognizer observations and must not be presented as evidence-example counts or unique patients.

The displayed value comes from extracted text. For scanned content it may contain OCR mistakes. Segment labels and offsets describe the scanner's extracted-text segmentation; they are not guaranteed PDF page numbers, original-document coordinates, or stable database primary keys. Context- or schema-based classifications may have no exact match text and therefore no examples. Do not manufacture a value from a column label to fill that gap.

Evidence is not returned with ordinary finding lists or CSV/JSON exports. Revealing it uses an authenticated, audited request and a response marked `no-store`. Treat the reviewer screen and any manually copied content as patient data. Original source-file bytes are not retained. Only bounded example fields are saved, although an excerpt can contain the entire text of a short segment.

Evidence capture cannot recover values from older metadata-only scans. Start a new scan with capture enabled; the source must still be accessible, and examples reflect that new read. Changing the setting does not retrospectively add evidence to previous findings.

## Retention, backup and recovery

Set retention and audit retention before the first production scan. After policy approval, the worker purges at startup before scanning and runs a separate housekeeping task approximately every 30 seconds, including during source reads and pauses. Expiry is measured from scan creation using the current approved findings-retention period. Each pass selects up to 100 scans, sessions and audit rows per category; a backlog triggers another pass after approximately 0.1 seconds. PostgreSQL housekeeping queries use one-second lock and five-second statement limits. These are bounded cleanup passes, not a strict real-time deletion guarantee. With the worker stopped, background cleanup resumes at its next startup; an unapproved policy does not purge records.

Expired queued, idle and terminal scans are deleted. For an expired scan still owned by a worker, housekeeping removes findings, coverage objects and associated evidence, clears coverage, and marks the run cancelled; a minimal scan marker remains until the worker releases its operation. Checkpoints and write/commit guards prevent expired results from being persisted again. Housekeeping failure stops new worker writes. An in-flight source/parser operation still needs to reach cancellation or its timeout; do not interpret catalog deletion as immediate memory zeroization, physical database erasure or deletion from backups.

This cleanup never changes source files or source database rows. An administrator can also run the bounded purge command below. Back up the PostgreSQL catalog with `pg_dump` to encrypted hospital storage and escrow encryption/session secrets separately. Reports and backups contain sensitive metadata. Include them in the hospital's retention policy; in-app purge cannot delete copies exported elsewhere.

Captured matching values and excerpts follow the finding's retention period and are deleted with the parent finding, including replacement of an interrupted scan's findings on restart. Evidence-reveal audit events contain no values or excerpts and retain access history under the audit policy. Manually entered review notes remain subject to audit retention, so avoid copying patient values into them. Backups taken while capture is enabled include encrypted evidence; their independent retention must account for that patient data.

Apply the configured application retention policy from the deployed bundle's `deploy/` directory:

```sh
docker compose -f compose.yaml -f compose.images.yaml exec api python -m app.cli purge-expired
```

This runs one bounded cleanup pass under the approved policy, never deleting source files or hospital database rows. For a large backlog while the worker is stopped, repeat the command until no eligible records remain, or start the worker to drain the backlog. Align backup/export retention before approving the policy; no extra host scheduler is required while the worker is running.

Before an upgrade, take a catalog backup, preserve the approved image bundle and test a restore on an isolated host. Restore a supported matching release/schema with **both original secrets**, `APP_SECRET_KEY` and `SESSION_SECRET`; do not regenerate deployment secrets. No automated cross-version migration/rollback guarantee is supplied in this pilot. Review schema changes before upgrading, and do not use `docker compose down -v` on a deployment you intend to retain.

Keep API, worker, web and ingress stopped and all discovery-source routes blocked throughout restoration and preparation. Start only the isolated catalog, restore the backup, then use a bundle containing `prepare-restored-catalog`. Do not expose the API to inspect restored data first: API startup does not purge expired findings, and ordinary worker startup can run restored queued scans. The confirmation flag records the operator's confirmation; the command cannot verify host isolation.

From the restored bundle's `deploy/` directory, replace `N` and `M` with the current hospital-approved findings and audit retention periods, each **1–3650 days**. These values become the approved application policy; do not blindly reuse a stale backup's policy.

```sh
docker compose -f compose.yaml -f compose.images.yaml run --rm --no-deps api python -m app.cli prepare-restored-catalog --retention-days N --audit-retention-days M --confirm-isolated-restore
```

The one-off command validates encrypted catalog fields and available comparison identities, disables restored users and sources, revokes source safety/full-scan workload approvals, clears sessions and stale heartbeats, cancels old nonterminal scan work, and drains retention before reporting `offline_preparation_completed`. This status is not production readiness. It preserves surviving findings/reviews and their identities and does not contact discovery sources. If preparation fails, keep services stopped and source routes blocked; a failure after quarantine may leave quarantine committed. Resolve the fixed diagnostic reason before retrying. If no comparison objects exist, `session_secret_verification` is `not_verifiable_no_stored_objects`; verify the escrowed original independently.

After successful preparation, create a **new, currently authorized administrator with a fresh username** while services remain stopped:

```sh
docker compose -f compose.yaml -f compose.images.yaml run --rm --no-deps api python -m app.cli init-admin --username hospital-recovery-admin
```

Choose another fresh username if it already exists: `init-admin` does not reactivate or replace a disabled account. Review current authorization before creating other replacement accounts. Re-running restore preparation disables accounts created since its previous run, so bootstrap only after the final successful preparation. Verify retained source decryption, findings/evidence, review/audit history and sample comparisons through an authorized isolated check. Then restore API/ingress access under the hospital network policy while keeping the worker stopped. After approving source scopes, grants and network rules, open only the private routes needed for administrator connection/safety checks. Revalidate credentials and safety, reapprove full-scan workload limits explicitly, and only then start the worker and new scans; cancelled restored work is not resumed. Independent backup/export expiry still requires the hospital's separate procedure.

The [synthetic PostgreSQL recovery drill](../fixtures/evaluation/recovery-integration.json) records 30 passing checks for its identified release, using actual custom-format `pg_dump`/`pg_restore` on an isolated disposable catalog. It verified rejected mismatched secrets and truncated dumps, quarantine and three retention passes, retained evidence/reviews/comparison identities, rejection of old sessions/accounts, fresh CLI administrator login, and an actual worker that did not resume restored jobs. The original catalog was unchanged. API checks used in-process ASGI with an HTTPS base URL; ingress/TLS was not exercised. This proves same-release recovery behavior only, not cross-version migration, hospital disk/backup encryption, key escrow, site isolation or hospital recovery acceptance.

The evidence feature adds a separate `finding_evidence` table with an encrypted payload and a cascading foreign key to the existing finding. Application initialization creates the new table without changing existing finding columns. Existing findings remain valid and have no captured evidence. Test the upgrade against a restored older catalog before rollout, including evidence deletion with its parent finding; retain the same encryption key. Rollback compatibility beyond this additive table has not been established.

## Go-live evidence

- Held-out hospital reference set separated from calibration; declare hospital-approved `priority_classes` for database, digital and OCR categories. Use exhaustive matching-value occurrence annotations and, for clinical priorities, version-3 original-record clinical/reference annotations. Use the production Presidio detector, retain the minimum 95% target and at least 30 positive/30 negative source objects per required category/measure, and inspect every `acceptance_blockers` entry. Repeated IDs or many records within one object cannot inflate independent sample counts. Include Indian names/initials and patient/clinician distinctions.
- Digital, database and OCR results separated. Mixed PDFs, multiple patients, poor scans, handwritten/regional content and encrypted files exercised; limitations visible.
- Read-only grants, cancellation, restart recovery, production workload budget and source-coverage reconciliation demonstrated on each actual engine. Synthetic/local-service tests do not establish hospital database compatibility.
- For cloud scope, demonstrate actual private provider routing, IAM/SAS restrictions/expiry, bounded pagination, changing-object handling, request-cost approval and Azure Table sample limits. Local MinIO/Azurite tests are implementation evidence, not AWS/Azure or hospital acceptance.
- Complete install/start/scan with public internet blocked and only approved private source routes enabled; raw values absent from normal reports/logs; all source locations and exports treated as sensitive. Verify evidence capture is off by default, bounded and encrypted when enabled, visible only to administrators/reviewers, audited on reveal, and removed with the associated findings.
- Repeat runs distinguish new findings, detector changes, source changes and coverage loss. Independent hospital reviewers accept the result.

The evaluator's version-2 PII metric matches exact NFC-normalized values and class one-to-one within each source object; legacy object-label presence is diagnostic only. Version 3 separately matches clinical presence by original record and patient association by original record plus exact patient-reference class/value. It supports native JSON pointers, reviewed original text spans and typed-primary-key SQLite reference exports; it does not score diagnoses or support arbitrary PDF/OCR/Office record mappings. Clinical priorities require their applicable v3 measures, and schema-only PII occurrence classes remain unsupported. Private gold locators/values stay local and are omitted from reports. Partial required content and unsupported mappings leave accuracy unvalidated even if recognized values are correct. A candidate flag never replaces hospital acceptance.
