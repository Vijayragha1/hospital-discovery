# S3 and Azure Storage discovery

The application can scan an explicitly selected S3 bucket/prefix, Azure Blob container/prefix (including ADLS Gen2 content through its Blob endpoint), or Azure Storage Table/optional partition. It does not enumerate cloud accounts, subscriptions, buckets, containers or tables. These adapters do not add FHIR, HIMS, SaaS, PACS/DICOM, Azure SQL or Cosmos DB support.

| Source kind | Approved scope | Access | Content coverage |
|---|---|---|---|
| `s3` | One bucket and optional key prefix | Dedicated access key, optional session token; or the scanner's EC2 instance profile | Current objects only; supported document formats use the existing extraction/OCR pipeline |
| `azure_blob` | One container and optional blob-name prefix | Container-scoped read/list service SAS | Current blobs; ADLS Gen2 through the Blob API; snapshots, deleted objects, previous versions and ACL analysis are not enumerated |
| `azure_table` | One table and optional exact PartitionKey | Table-scoped read service SAS | At most 1,000 entities per scan; property detection and clinical linkage stay inside each entity |

Do not interpret match counts as distinct patient counts. A connection check proves that the attempted read/list request succeeded, not that an identity is incapable of writing. Hospital acceptance must inspect the actual IAM policy or SAS scope and test a dedicated identity separately. Empty scopes can pass the listing check without proving that every later object can be read.

## Network and identity setup

`CLOUD_HOST_ALLOWLIST` is a comma-separated list of exact endpoint hostnames. Every endpoint must be an HTTPS **origin**: no path, query, embedded credentials or fragment. Explicit ports are permitted, but the hospital firewall must approve only the exact endpoint addresses and ports. TLS verification cannot be disabled. For a private CA, mount its PEM bundle read-only and set deployment-only `SOURCE_CLOUD_CA_FILE` to its absolute container path; this is not a source form field.

All DNS addresses must be RFC1918 IPv4, private IPv6 ULA or loopback. Public endpoints, link-local addresses and mixed public/private DNS answers are rejected in every environment. Use a private S3/VPC endpoint and Azure private endpoint DNS over the hospital's approved private route. The actual canonical account hostname can remain in the URL when private DNS resolves it to the private endpoint. S3 uses path-style bucket addressing to keep requests on the configured origin. A regional redirect to a different endpoint fails closed; correct the approved endpoint/region instead.

SDK-generated requests are restricted to GET/HEAD on the configured origin, and endpoint approval/DNS checks repeat for every request. Ambient HTTP proxies are disabled. These checks are defense in depth: DNS resolution and connection are separate operations. The existing hospital egress-deny firewall remains mandatory, with explicit private storage/DNS/Tika/database exceptions as applicable. Do not enable unrestricted internet egress to make a connection check pass.

For S3 `iam_role`, only the scanner's EC2 instance profile is used. The connector does not consult shared credential profiles, `credential_process`, arbitrary ECS credential URLs or STS assume-role endpoints. IMDSv2 uses the fixed EC2 metadata address `169.254.169.254`, without a proxy or IMDSv1 fallback. This is an explicit authentication-only exception to the storage endpoint rule and needs its own deployment route/firewall approval on an EC2 host. Credentials refresh through that fixed provider. Outside EC2, use a dedicated access key or short-lived access key plus session token. Source configuration cannot choose an alternative metadata address.

An S3 read-only policy normally grants `s3:ListBucket` on the selected bucket, constrained with the approved prefix, and `s3:GetObject` on the selected object ARN prefix. HEAD requires the corresponding object read permission. KMS-encrypted objects may need a separately reviewed `kms:Decrypt` permission on the specific key. Neither the app nor its connection check edits IAM policies. Reject administrative, wildcard write and delete permissions during acceptance.

Azure SAS requirements are deliberately narrow:

- Blob: container service SAS, `sr=c`, permissions `sp=rl`, HTTPS-only `spr=https`, explicit future expiry `se`.
- Table: table service SAS naming the selected table (`tn`), permission `sp=r`, HTTPS-only `spr=https`, explicit future expiry `se`.
- Account SAS, stored access policy references (`si`), write/delete/add/create/update permissions, and SAS embedded in an account URL are rejected. Supply the token in its separate secret field. SAS expiry during a scan produces visible access gaps.

Container SAS is sufficient for prefix-scoped scanning but is not itself prefix-scoped authorization. Where hospital policy requires narrower authorization, choose an isolated container or approved identity architecture rather than claiming the form prefix limits the credential's server-side authority.

## Boundaries and coverage

Object listings request at most 100 entries per page. Object scans obey the existing maximum objects, file bytes and extracted text limits. Listing pagination has a hard continuation-page ceiling; reaching a limit, losing access or cancellation creates an explicit coverage object. Unsupported extensions, archives and oversized files are recorded without downloading their content. Archives remain excluded rather than expanded.

Downloads have five-second connection/read timeouts, single concurrent requests and a 60-second download budget checked between requests/chunks. An in-flight SDK request ends under its own timeout; this is not a hard process-kill deadline. Azure may retry incomplete chunk decoding a bounded number of times internally. The separate Tika parser timeout/resource limits still apply to extraction/OCR. Cancellation closes S3 streaming bodies and all clients; Azure chunks are bounded and consumed with concurrency one, and the shared transport closes when the scan ends.

S3 and Blob reads use the listed ETag as a conditional read precondition. A second ETag/size check after extraction catches observed changes; failures are partial coverage, never successful removal. Azure Table entities are read with their service ETag and rechecked after detection; missing or changed versions produce partial coverage. ETags are persisted only as hashes. Content fingerprints contain hashes of downloaded bytes/entity properties, not raw content. Pagination is **not** a point-in-time snapshot, so concurrent additions/deletions can still change the listing between pages. This limitation is recorded in listing coverage.

Azure Table uses a bounded key-ordered prefix sample, not a random or representative sample. An exact partition filter is parameterized. Every entity has its own hashed PartitionKey/RowKey location, and property/record boundaries are preserved. Original keys and property values are not written into metadata. Full table mode is rejected. Binary properties or text truncation make the entity partial. The scan reports the number of examined entities and any sample cap; it does not issue a table count.

Cloud paths and table/property names can themselves identify patients. They receive the same encrypted catalogue storage, access controls, audited views and retention as existing source locations. Credentials remain encrypted with other source configuration and are redacted from API projections. SDK HTTP/signing diagnostics are suppressed. Error results use fixed reason codes, never SDK exception strings or signed URLs.

Raw values/excerpts remain off by default. Explicit per-scan evidence capture uses the existing bounded encrypted evidence store, administrator/reviewer reveal endpoint, audited access and retention cascade. Context-only classifications can have no examples. Table evidence identifies the property and local record segment; it does not promise a stable clinical patient identifier or database primary key in the UI.

## Validation and limitations

`backend/tests/test_cloud_connectors.py` exercises strict endpoint/SAS rules, safe request methods, source limits, ETag change handling, conditional reads, cancellation/cleanup, Table entity boundaries, parameterized partition filtering and opt-in evidence with synthetic SDK fixtures. All 43 cloud connector unit cases passed during implementation.

`scripts/integration_cloud.py` provisions only synthetic data using separate administrator clients in isolated local TLS MinIO/Azurite services. It then exercises the actual SDK connectors, including 1,002 Table fixtures to verify the 1,000-entity limit. The runner accepts a local credentials file and writes only safe check results. It uses a test-only DNS mapping for `fixture.blob.localhost` and `fixture.table.localhost`; production connector DNS behavior is unchanged. Example from the project root:

```sh
python scripts/integration_cloud.py --credentials /secure/local/fixture-credentials.json --output /secure/local/cloud-integration.json --with-presidio
```

The credentials file provides `minio_access`, `minio_secret`, `azure_key` and `ca_file`; optional `minio_reader_access`/`minio_reader_secret` let the runner scan with a separately provisioned S3 read-only identity. Fixture admin provisioning is confined to loopback TLS endpoints and never part of the production scanner. The test leaves its uniquely named synthetic fixtures available for inspection in the disposable emulator.

The optional `--with-presidio` step scans just one named synthetic record per connector through the actual local Presidio/spaCy pipeline, checking name, email and UHID findings. The larger Table boundary test uses the explicit rule detector so it can exercise 1,000 records without conflating NLP throughput with protocol validation. All 20 local TLS emulator checks passed, including three Presidio smoke checks and write denial for Blob/Table SAS. These checks are functional tests, not accuracy evaluation or evidence of the 95% acceptance target. See `fixtures/evaluation/cloud-integration.json` for the recorded executed checks. The S3 fixture used its local administrator identity; restrictive S3 grants were not verified, and the report records that explicitly.

Local emulators and synthetic rule-detector tests do not establish AWS/Azure production compatibility, hospital-specific precision/recall, IAM grant correctness or successful private routing in the client's environment. Confirm actual provider endpoints, account encryption, policy grants, request costs, allowed windows, workload impact and representative extraction/OCR accuracy in hospital acceptance before production use.

Pinned SDKs used for this implementation are `boto3==1.43.98`, `azure-storage-blob==12.30.2` and `azure-data-tables==12.7.0`; the application dependency manifest pins their transitive dependencies. API behavior is based on the official [S3 object listing](https://docs.aws.amazon.com/boto3/latest/reference/services/s3/client/list_objects_v2.html), [S3 conditional GET](https://docs.aws.amazon.com/boto3/latest/reference/services/s3/client/get_object.html), [Azure Blob client](https://learn.microsoft.com/en-us/python/api/azure-storage-blob/azure.storage.blob.blobclient), and [Azure Table client](https://learn.microsoft.com/en-us/python/api/azure-data-tables/azure.data.tables.tableclient) references, checked 2026-09-21.
