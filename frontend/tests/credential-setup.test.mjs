import test from "node:test";
import assert from "node:assert/strict";
import {
  credentialInputs,
  credentialUpdate,
  newCredentialDraft,
} from "../src/credential-setup.ts";

const source = (kind, config = {}) => ({ kind, config });

test("credential forms always start empty, even when source API contains redacted secrets", () => {
  const example = source("postgresql", {
    username: "existing-account",
    password: "[redacted]",
    dsn: "[redacted]",
  });
  assert.deepEqual(
    credentialInputs(example).map((input) => input.field),
    ["username", "password"],
  );
  assert.ok(Object.values(newCredentialDraft()).every((value) => value === ""));
});

test("only supported connector credential fields are offered", () => {
  for (const kind of ["postgresql", "mysql", "mssql"])
    assert.deepEqual(
      credentialInputs(source(kind)).map((input) => input.field),
      ["username", "password"],
    );
  assert.deepEqual(
    credentialInputs(source("smb")).map((input) => input.field),
    ["username", "password", "domain"],
  );
  assert.deepEqual(
    credentialInputs(source("s3", { auth_mode: "access_key" })).map(
      (input) => input.field,
    ),
    ["access_key_id", "secret_access_key", "session_token"],
  );
  for (const kind of ["azure_blob", "azure_table"])
    assert.deepEqual(credentialInputs(source(kind)), [
      { field: "sas_token", label: "Read-only SAS token", secret: true },
    ]);
  for (const item of [
    source("filesystem"),
    source("sqlite"),
    source("s3", { auth_mode: "iam_role" }),
  ]) {
    assert.deepEqual(credentialInputs(item), []);
    assert.throws(
      () =>
        credentialUpdate(item, {
          ...newCredentialDraft(),
          password: "synthetic",
        }),
      /does not use editable/,
    );
  }
});

test("partial replacements omit blanks and every unrelated connector secret", () => {
  const draft = {
    ...newCredentialDraft(),
    password: " synthetic password ",
    sas_token: "other-secret",
    access_key_id: "other-key",
    domain: "other-domain",
  };
  assert.deepEqual(credentialUpdate(source("mysql"), draft), {
    credentials: { password: " synthetic password " },
  });
  assert.deepEqual(credentialUpdate(source("azure_blob"), draft), {
    credentials: { sas_token: "other-secret" },
  });
  assert.throws(
    () => credentialUpdate(source("mysql"), newCredentialDraft()),
    /at least one/,
  );
  assert.throws(
    () =>
      credentialUpdate(source("mysql"), {
        ...newCredentialDraft(),
        username: "   ",
      }),
    /at least one/,
  );
});

test("S3 session token is removed only by an explicit clear selection", () => {
  const item = source("s3", { auth_mode: "access_key" });
  const draft = {
    ...newCredentialDraft(),
    access_key_id: " fixture-key ",
    secret_access_key: "fixture-secret",
  };
  assert.deepEqual(credentialUpdate(item, draft), {
    credentials: {
      access_key_id: "fixture-key",
      secret_access_key: "fixture-secret",
    },
  });
  assert.deepEqual(credentialUpdate(item, newCredentialDraft(), true), {
    credentials: { session_token: "" },
  });
  assert.deepEqual(
    credentialUpdate(
      item,
      { ...newCredentialDraft(), session_token: "ignored-token" },
      true,
    ),
    { credentials: { session_token: "" } },
  );
  assert.throws(
    () => credentialUpdate(source("smb"), draft, true),
    /does not use an S3 session token/,
  );
});

test("credential updates preserve identity and scope by never including configuration fields", () => {
  const item = source("smb", {
    server: "private.invalid",
    share: "Records",
    username: "old",
    password: "[redacted]",
    full_scan_allowed: true,
  });
  const result = credentialUpdate(item, {
    ...newCredentialDraft(),
    username: " new-reader ",
    password: "synthetic-password",
    domain: " TEST ",
  });
  assert.deepEqual(result, {
    credentials: {
      username: "new-reader",
      password: "synthetic-password",
      domain: "TEST",
    },
  });
  assert.equal(JSON.stringify(result).includes("Records"), false);
  assert.equal(JSON.stringify(result).includes("[redacted]"), false);
  assert.equal(item.config.username, "old");
});

test("oversized secrets are rejected before submitting", () => {
  assert.throws(
    () =>
      credentialUpdate(source("azure_table"), {
        ...newCredentialDraft(),
        sas_token: "x".repeat(16385),
      }),
    /16,384/,
  );
});
