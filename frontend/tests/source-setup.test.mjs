import test from "node:test";
import assert from "node:assert/strict";
import {
  newSourceDraft,
  updateSourceDraft,
  parseNetworkPath,
  validateSourceDraft,
  sourcePayload,
  isDatabaseKind,
  isCloudKind,
  isTabularKind,
} from "../src/source-setup.ts";

const setup = {
  environment: "development",
  allowed_roots: ["/sources"],
  database_hosts: ["db.hospital.local"],
  smb_hosts: ["files.hospital.local"],
  cloud_hosts: [
    "storage.hospital.local",
    "hospital.blob.core.windows.net",
    "hospital.table.core.windows.net",
  ],
  supported_kinds: [
    "filesystem",
    "smb",
    "postgresql",
    "mysql",
    "mssql",
    "s3",
    "azure_blob",
    "azure_table",
    "sqlite",
  ],
};

test("separator-only table scope cannot silently widen to the whole schema", () => {
  const draft = {
    ...newSourceDraft(setup, "Test database"),
    database: "records",
    username: "reader",
    password: "synthetic-test-value",
    tables: ",\n,",
  };
  assert.ok(validateSourceDraft("postgresql", draft, setup).tables);
  assert.equal(
    validateSourceDraft("postgresql", { ...draft, tables: "  " }, setup).tables,
    undefined,
  );
});

test("approved network paths are parsed without accepting another host or parent traversal", () => {
  assert.deepEqual(
    parseNetworkPath(
      "\\\\FILES.HOSPITAL.LOCAL\\Records\\Pilot",
      setup.smb_hosts,
    ),
    { server: "files.hospital.local", share: "Records", subpath: "Pilot" },
  );
  assert.throws(() =>
    parseNetworkPath("\\\\unknown.local\\Records", setup.smb_hosts),
  );
  assert.throws(() =>
    parseNetworkPath(
      "\\\\files.hospital.local\\Records\\..\\Other",
      setup.smb_hosts,
    ),
  );
});

test("folder payload contains only its approved location and never remote credentials", () => {
  const draft = {
    ...newSourceDraft(setup, "Test folder"),
    folder: "Records/Pilot",
    username: "reader",
    password: "synthetic-test-value",
  };
  assert.deepEqual(sourcePayload("filesystem", draft).config, {
    root: "/sources/Records/Pilot",
  });
  assert.ok(
    validateSourceDraft("filesystem", { ...draft, folder: "../outside" }, setup)
      .folder,
  );
});

test("changing source kind can preserve its name while clearing credentials and scope", () => {
  const old = {
    ...newSourceDraft(setup, "Pilot source"),
    password: "synthetic-test-value",
    tables: "patients",
    networkPath: "\\\\files.hospital.local\\Records",
  };
  const reset = newSourceDraft(setup, old.name);
  assert.equal(reset.name, old.name);
  assert.equal(reset.password, "");
  assert.equal(reset.tables, "");
  assert.equal(reset.networkPath, "");
});

test("database defaults stay bounded and table selection is explicit", () => {
  const draft = {
    ...newSourceDraft(setup, "Test database"),
    database: "records",
    username: "reader",
    password: "synthetic-test-value",
    tables: "patients,\nclinical_notes,patients",
  };
  assert.deepEqual(validateSourceDraft("postgresql", draft, setup), {});
  const config = sourcePayload("postgresql", draft).config;
  assert.equal(config.port, 5432);
  assert.equal(config.schema, "public");
  assert.deepEqual(config.tables, ["patients", "clinical_notes"]);
  assert.ok(
    validateSourceDraft("postgresql", { ...draft, port: "0" }, setup).port,
  );
});

test("database engines use their own defaults and MySQL schema follows the database", () => {
  for (const [kind, port, schema] of [
    ["postgresql", "5432", "public"],
    ["mysql", "3306", ""],
    ["mssql", "1433", "dbo"],
  ]) {
    let draft = newSourceDraft(setup, "Database fixture", kind);
    assert.equal(draft.port, port);
    assert.equal(draft.schema, schema);
    draft = updateSourceDraft(draft, "database", "hospital_records", kind);
    draft = { ...draft, username: "reader", password: "synthetic-test-value" };
    assert.deepEqual(validateSourceDraft(kind, draft, setup), {});
    assert.equal(
      sourcePayload(kind, draft).config.schema,
      kind === "mysql" ? "hospital_records" : schema,
    );
  }
  const draft = {
    ...newSourceDraft(setup, "MySQL fixture", "mysql"),
    database: "next_database",
    schema: "stale_schema",
  };
  assert.equal(sourcePayload("mysql", draft).config.schema, "next_database");
  assert.equal(
    updateSourceDraft(draft, "database", "changed", "mysql").schema,
    "changed",
  );
});

test("switching source type discards every prior secret and selected resource", () => {
  const old = {
    ...newSourceDraft(setup, "Pilot source", "s3"),
    password: "db-secret",
    accessKeyId: "key-id",
    secretAccessKey: "key-secret",
    sessionToken: "session-secret",
    sasToken: "sas-secret",
    bucket: "previous-bucket",
    table: "PreviousTable",
    tables: "patients",
  };
  for (const kind of setup.supported_kinds) {
    const reset = newSourceDraft(setup, old.name, kind);
    assert.equal(reset.name, old.name);
    for (const field of [
      "password",
      "accessKeyId",
      "secretAccessKey",
      "sessionToken",
      "sasToken",
      "bucket",
      "table",
      "tables",
    ])
      assert.equal(reset[field], "", `${kind} clears ${field}`);
  }
});

function s3Draft() {
  return {
    ...newSourceDraft(setup, "S3 fixture", "s3"),
    endpointUrl: "https://storage.hospital.local/",
    bucket: "hospital-records",
    accessKeyId: "synthetic-key-id",
    secretAccessKey: "synthetic-secret",
  };
}

test("cloud endpoints require an approved HTTPS origin without embedded credentials or SAS query", () => {
  assert.deepEqual(validateSourceDraft("s3", s3Draft(), setup), {});
  assert.deepEqual(
    validateSourceDraft(
      "s3",
      { ...s3Draft(), endpointUrl: "https://STORAGE.HOSPITAL.LOCAL" },
      setup,
    ),
    {},
  );
  for (const endpointUrl of [
    "http://storage.hospital.local",
    "https://unapproved.local",
    "https://user:secret@storage.hospital.local",
    "https://storage.hospital.local/bucket",
    "https://storage.hospital.local?sig=secret",
    "https://storage.hospital.local#fragment",
    "invalid endpoint",
  ])
    assert.ok(
      validateSourceDraft("s3", { ...s3Draft(), endpointUrl }, setup)
        .endpointUrl,
      endpointUrl,
    );
  assert.ok(
    validateSourceDraft("s3", s3Draft(), { ...setup, cloud_hosts: [] })
      .endpointUrl,
  );
});

test("S3 access-key and instance-role payloads cannot leak another connector's credentials", () => {
  const draft = {
    ...s3Draft(),
    prefix: "discharge/ ",
    sessionToken: "synthetic-session",
    password: "db-secret",
    sasToken: "azure-secret",
  };
  assert.deepEqual(sourcePayload("s3", draft).config, {
    endpoint_url: "https://storage.hospital.local",
    region: "ap-south-1",
    bucket: "hospital-records",
    prefix: "discharge/ ",
    auth_mode: "access_key",
    access_key_id: "synthetic-key-id",
    secret_access_key: "synthetic-secret",
    session_token: "synthetic-session",
  });
  const role = updateSourceDraft(draft, "authMode", "iam_role", "s3");
  assert.equal(role.accessKeyId, "");
  assert.equal(role.secretAccessKey, "");
  assert.equal(role.sessionToken, "");
  assert.deepEqual(validateSourceDraft("s3", role, setup), {});
  const payload = sourcePayload("s3", {
    ...draft,
    authMode: "iam_role",
  }).config;
  for (const field of [
    "access_key_id",
    "secret_access_key",
    "session_token",
    "password",
    "sas_token",
  ])
    assert.equal(field in payload, false, field);
  assert.ok(
    validateSourceDraft("s3", { ...draft, secretAccessKey: "" }, setup)
      .secretAccessKey,
  );
});

test("cloud resource names are explicit and unsafe names do not reach review", () => {
  for (const bucket of [
    "",
    "ab",
    "UPPERCASE",
    "s3://bucket",
    "bucket/path",
    "a".repeat(64),
  ])
    assert.ok(
      validateSourceDraft("s3", { ...s3Draft(), bucket }, setup).bucket,
      bucket,
    );
  assert.ok(
    validateSourceDraft("s3", { ...s3Draft(), prefix: "a".repeat(1025) }, setup)
      .prefix,
  );
  const base = {
    ...newSourceDraft(setup, "Azure fixture", "azure_blob"),
    accountUrl: "https://hospital.blob.core.windows.net",
    container: "hospital-records",
    sasToken: "synthetic-token",
  };
  assert.deepEqual(validateSourceDraft("azure_blob", base, setup), {});
  for (const container of ["", "ab", "Uppercase", "bad--name", "bad/path"])
    assert.ok(
      validateSourceDraft("azure_blob", { ...base, container }, setup)
        .container,
      container,
    );
  assert.ok(
    validateSourceDraft("azure_blob", { ...base, sasToken: "" }, setup)
      .sasToken,
  );
  const table = {
    ...base,
    accountUrl: "https://hospital.table.core.windows.net",
    table: "PatientRecords",
  };
  assert.deepEqual(validateSourceDraft("azure_table", table, setup), {});
  for (const name of ["", "ab", "1Table", "Table_Name", "a".repeat(64)])
    assert.ok(
      validateSourceDraft("azure_table", { ...table, table: name }, setup)
        .table,
      name,
    );
});

test("Azure payloads keep scope exact, omit unrelated secrets and never enumerate resources", () => {
  const draft = {
    ...newSourceDraft(setup, "Azure fixture", "azure_blob"),
    accountUrl: "https://hospital.blob.core.windows.net/",
    container: "hospital-records",
    prefix: " discharge/",
    sasToken: "synthetic-sas",
    password: "db-secret",
    secretAccessKey: "s3-secret",
    table: "PatientRecords",
    partitionKey: " ward-A ",
  };
  assert.deepEqual(sourcePayload("azure_blob", draft).config, {
    account_url: "https://hospital.blob.core.windows.net",
    container: "hospital-records",
    prefix: " discharge/",
    sas_token: "synthetic-sas",
  });
  const tableDraft = {
    ...draft,
    accountUrl: "https://hospital.table.core.windows.net",
  };
  assert.deepEqual(sourcePayload("azure_table", tableDraft).config, {
    account_url: "https://hospital.table.core.windows.net",
    table: "PatientRecords",
    partition_key: " ward-A ",
    sas_token: "synthetic-sas",
  });
  assert.equal(
    "partition_key" in
      sourcePayload("azure_table", { ...tableDraft, partitionKey: "" }).config,
    false,
  );
});

test("connector families distinguish sampled cloud tables from relational engines", () => {
  assert.equal(isDatabaseKind("mysql"), true);
  assert.equal(isDatabaseKind("mssql"), true);
  assert.equal(isDatabaseKind("azure_table"), false);
  assert.equal(isTabularKind("azure_table"), true);
  assert.equal(isCloudKind("azure_table"), true);
  assert.equal(isDatabaseKind(null), false);
});
