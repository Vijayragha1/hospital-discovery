import type { Source } from "./api";

export type CredentialField =
  | "username"
  | "password"
  | "domain"
  | "access_key_id"
  | "secret_access_key"
  | "session_token"
  | "sas_token";
export type CredentialDraft = Record<CredentialField, string>;
export type CredentialInput = {
  field: CredentialField;
  label: string;
  secret: boolean;
};

export function newCredentialDraft(): CredentialDraft {
  return {
    username: "",
    password: "",
    domain: "",
    access_key_id: "",
    secret_access_key: "",
    session_token: "",
    sas_token: "",
  };
}

export function credentialInputs(
  source: Pick<Source, "kind" | "config">,
): CredentialInput[] {
  if (["postgresql", "mysql", "mssql", "smb"].includes(source.kind)) {
    return [
      { field: "username", label: "Account name", secret: false },
      { field: "password", label: "Password", secret: true },
      ...(source.kind === "smb"
        ? [{ field: "domain" as const, label: "Windows domain", secret: false }]
        : []),
    ];
  }
  if (source.kind === "s3" && source.config?.auth_mode === "access_key") {
    return [
      { field: "access_key_id", label: "Access key ID", secret: false },
      { field: "secret_access_key", label: "Secret access key", secret: true },
      { field: "session_token", label: "Session token", secret: true },
    ];
  }
  if (["azure_blob", "azure_table"].includes(source.kind)) {
    return [{ field: "sas_token", label: "Read-only SAS token", secret: true }];
  }
  return [];
}

export function credentialUpdate(
  source: Pick<Source, "kind" | "config">,
  draft: CredentialDraft,
  clearSessionToken = false,
) {
  const inputs = credentialInputs(source);
  if (!inputs.length)
    throw new Error("This source does not use editable credentials.");
  const credentials: Partial<Record<CredentialField, string>> = {};
  for (const input of inputs) {
    const value = input.secret ? draft[input.field] : draft[input.field].trim();
    if (value) credentials[input.field] = value;
  }
  if (clearSessionToken) {
    if (!inputs.some((input) => input.field === "session_token")) {
      throw new Error("This source does not use an S3 session token.");
    }
    credentials.session_token = "";
  }
  if (!Object.keys(credentials).length)
    throw new Error("Enter at least one replacement credential.");
  if (Object.values(credentials).some((value) => value.length > 16384)) {
    throw new Error("Each credential must be 16,384 characters or fewer.");
  }
  return { credentials };
}
