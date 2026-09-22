import type { Source, SourceKind } from "./api";

export type SourceSetup = {
  environment: string;
  allowed_roots: string[];
  database_hosts: string[];
  smb_hosts: string[];
  cloud_hosts: string[];
  supported_kinds: SourceKind[];
};

export type SourceDraft = {
  name: string;
  root: string;
  folder: string;
  fixtureFile: string;
  networkPath: string;
  server: string;
  share: string;
  subpath: string;
  host: string;
  database: string;
  port: string;
  schema: string;
  tables: string;
  username: string;
  password: string;
  domain: string;
  endpointUrl: string;
  region: string;
  bucket: string;
  prefix: string;
  authMode: string;
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken: string;
  accountUrl: string;
  container: string;
  table: string;
  partitionKey: string;
  sasToken: string;
};

export type SourceErrors = Partial<Record<keyof SourceDraft, string>>;
export type ConnectedSource = {
  source: Source;
  check: {
    ok: boolean;
    read_only?: boolean;
    read_only_operations?: boolean;
    cancellation_verified?: boolean;
    safety_validated: boolean;
    note?: string;
  };
};

export const isDatabaseKind = (kind: SourceKind | null) =>
  kind !== null && ["postgresql", "mysql", "mssql"].includes(kind);
export const isCloudKind = (kind: SourceKind | null) =>
  kind !== null && ["s3", "azure_blob", "azure_table"].includes(kind);
export const isTabularKind = (kind: SourceKind) =>
  isDatabaseKind(kind) || kind === "sqlite" || kind === "azure_table";

export function newSourceDraft(
  setup?: SourceSetup,
  name = "",
  kind: SourceKind = "postgresql",
): SourceDraft {
  return {
    name,
    root: setup?.allowed_roots[0] || "",
    folder: "",
    fixtureFile: "",
    networkPath: "",
    server: setup?.smb_hosts[0] || "",
    share: "",
    subpath: "",
    host: setup?.database_hosts[0] || "",
    database: "",
    port: kind === "mysql" ? "3306" : kind === "mssql" ? "1433" : "5432",
    schema: kind === "mysql" ? "" : kind === "mssql" ? "dbo" : "public",
    tables: "",
    username: "",
    password: "",
    domain: "",
    endpointUrl: "",
    region: "ap-south-1",
    bucket: "",
    prefix: "",
    authMode: "access_key",
    accessKeyId: "",
    secretAccessKey: "",
    sessionToken: "",
    accountUrl: "",
    container: "",
    table: "",
    partitionKey: "",
    sasToken: "",
  };
}

export function updateSourceDraft(
  draft: SourceDraft,
  field: keyof SourceDraft,
  value: string,
  kind: SourceKind | null,
): SourceDraft {
  return {
    ...draft,
    [field]: value,
    ...(["server", "share", "subpath"].includes(field)
      ? { networkPath: "" }
      : {}),
    ...(kind === "mysql" && field === "database" ? { schema: value } : {}),
    ...(field === "authMode" && draft.authMode !== value
      ? { accessKeyId: "", secretAccessKey: "", sessionToken: "" }
      : {}),
  };
}

function endpointError(value: string, hosts: string[]) {
  try {
    const url = new URL(value.trim());
    if (
      url.protocol !== "https:" ||
      url.username ||
      url.password ||
      url.search ||
      url.hash ||
      !["", "/"].includes(url.pathname)
    )
      return "Use an HTTPS service endpoint without a resource path, query, or credentials.";
    if (
      !hosts.some((host) => host.toLowerCase() === url.hostname.toLowerCase())
    )
      return "Choose a host approved for this scanner. Ask your administrator to approve additional cloud endpoints.";
  } catch {
    return "Enter the full HTTPS service endpoint, for example https://storage.example.com.";
  }
  return undefined;
}

function relativePath(value: string) {
  return (
    !value ||
    (!/^(?:[\\/]|[a-z]:)/i.test(value) &&
      !value.includes("\0") &&
      !value
        .replaceAll("\\", "/")
        .split("/")
        .some((part) => part === ".." || part === "."))
  );
}

export function joinApprovedPath(root: string, child: string) {
  const normalized = child.trim().replaceAll("\\", "/");
  return normalized ? `${root.replace(/\/$/, "")}/${normalized}` : root;
}

export function parseNetworkPath(value: string, approvedHosts: string[]) {
  const normalized = value.trim().replaceAll("\\", "/");
  if (!normalized.startsWith("//"))
    throw new Error(
      "Use a network path such as \\\\files.hospital.local\\Records\\Pilot.",
    );
  const [host, share, ...folders] = normalized
    .slice(2)
    .replace(/\/$/, "")
    .split("/");
  if (
    !host ||
    !share ||
    !relativePath(folders.join("/")) ||
    [host, share].some((part) => /[\0@:/]/.test(part))
  )
    throw new Error(
      "Include both the server and share name, followed by an optional subfolder. Parent folders (..) are not allowed.",
    );
  const server = approvedHosts.find(
    (approved) => approved.toLowerCase() === host.toLowerCase(),
  );
  if (!server)
    throw new Error(
      "This server is not approved for this scanner. Choose an approved server below or ask your administrator to add it.",
    );
  return { server, share, subpath: folders.join("/") };
}

export function selectedTables(value: string) {
  return [
    ...new Set(
      value
        .split(/[,\n]/)
        .map((table) => table.trim())
        .filter(Boolean),
    ),
  ];
}

export function validateSourceDraft(
  kind: SourceKind,
  draft: SourceDraft,
  setup: SourceSetup,
): SourceErrors {
  const errors: SourceErrors = {};
  if (!draft.name.trim())
    errors.name = "Give this source a name your team will recognize.";
  else if (draft.name.trim().length > 120)
    errors.name = "Use a name of 120 characters or fewer.";
  if (kind === "filesystem" || kind === "sqlite") {
    if (!setup.allowed_roots.includes(draft.root))
      errors.root =
        "Choose an approved folder. Your administrator can add folders to this scanner.";
    const field = kind === "sqlite" ? "fixtureFile" : "folder";
    if (kind === "sqlite" && !draft.fixtureFile.trim())
      errors.fixtureFile =
        "Enter the fixture filename inside the approved folder.";
    if (!relativePath(draft[field].trim()))
      errors[field] =
        "Use a path inside the selected folder, without a leading slash or parent folders (..).";
  }
  if (kind === "smb") {
    if (!setup.smb_hosts.includes(draft.server))
      errors.server = "Choose an approved file server.";
    if (!draft.share.trim())
      errors.share = "Enter the shared folder name, for example Records.";
    else if (
      /[\\/\0]/.test(draft.share) ||
      [".", ".."].includes(draft.share.trim())
    )
      errors.share =
        "Enter only the share name. Put any subfolders in the field below.";
    if (!relativePath(draft.subpath.trim()))
      errors.subpath =
        "Use a subfolder inside this share, without a leading slash or parent folders (..).";
  }
  if (isDatabaseKind(kind)) {
    if (!setup.database_hosts.includes(draft.host))
      errors.host = "Choose an approved database server.";
    if (!draft.database.trim())
      errors.database = "Enter the database name supplied by hospital IT.";
    else if (draft.database.trim().length > 128)
      errors.database = "Use a database name of 128 characters or fewer.";
    if (
      !/^\d+$/.test(draft.port) ||
      Number(draft.port) < 1 ||
      Number(draft.port) > 65535
    )
      errors.port = "Enter a port from 1 to 65535.";
    if (kind !== "mysql" && !draft.schema.trim())
      errors.schema = "Enter the schema name for the approved table scope.";
    else if (kind !== "mysql" && draft.schema.trim().length > 128)
      errors.schema = "Use a schema name of 128 characters or fewer.";
    const tables = selectedTables(draft.tables);
    if (draft.tables.trim() && tables.length === 0)
      errors.tables =
        "Enter at least one table name, or clear this field to use all tables in the schema.";
    else if (tables.length > 1000 || tables.some((table) => table.length > 128))
      errors.tables =
        "Use up to 1,000 table names, each no longer than 128 characters.";
  }
  if (kind === "smb" || isDatabaseKind(kind)) {
    if (!draft.username.trim())
      errors.username = "Enter the dedicated read-only account name.";
    if (!draft.password)
      errors.password = "Enter the password for this read-only account.";
  }
  if (isCloudKind(kind)) {
    const field = kind === "s3" ? "endpointUrl" : "accountUrl";
    const endpoint = endpointError(draft[field], setup.cloud_hosts || []);
    if (endpoint) errors[field] = endpoint;
    if (kind === "s3") {
      if (!draft.region.trim()) errors.region = "Enter the bucket’s region.";
      if (!draft.bucket.trim())
        errors.bucket = "Enter the approved bucket name.";
      else if (!/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(draft.bucket.trim()))
        errors.bucket =
          "Use a bucket name of 3–63 lowercase letters, numbers, dots, or hyphens, without a path.";
      if (!["access_key", "iam_role"].includes(draft.authMode))
        errors.authMode = "Choose access keys or the scanner’s IAM role.";
      if (draft.authMode === "access_key") {
        if (!draft.accessKeyId.trim())
          errors.accessKeyId = "Enter the read-only access key ID.";
        if (!draft.secretAccessKey)
          errors.secretAccessKey = "Enter the secret access key.";
      }
    } else {
      if (!draft.sasToken.trim())
        errors.sasToken =
          "Enter the read-only SAS token provided for this resource.";
      if (kind === "azure_blob") {
        if (!draft.container.trim())
          errors.container = "Enter the approved container name.";
        else if (
          !/^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/.test(draft.container.trim()) ||
          draft.container.includes("--")
        )
          errors.container =
            "Use 3–63 lowercase letters, numbers, or single hyphens, beginning and ending with a letter or number.";
      }
      if (kind === "azure_table") {
        if (!draft.table.trim())
          errors.table = "Enter the approved table name.";
        else if (!/^[a-zA-Z][a-zA-Z0-9]{2,62}$/.test(draft.table.trim()))
          errors.table =
            "Use 3–63 letters or numbers, beginning with a letter.";
      }
    }
    if (
      kind !== "azure_table" &&
      (draft.prefix.includes("\0") || draft.prefix.length > 1024)
    )
      errors.prefix =
        "Use a prefix of at most 1,024 characters without null characters.";
    if (kind === "azure_table" && draft.partitionKey.includes("\0"))
      errors.partitionKey = "The partition key contains an invalid character.";
  }
  return errors;
}

export function sourcePayload(kind: SourceKind, draft: SourceDraft) {
  let config: Record<string, unknown>;
  if (kind === "filesystem")
    config = { root: joinApprovedPath(draft.root, draft.folder) };
  else if (kind === "sqlite")
    config = { path: joinApprovedPath(draft.root, draft.fixtureFile) };
  else if (kind === "smb")
    config = {
      server: draft.server,
      share: draft.share.trim(),
      subpath: draft.subpath.trim().replaceAll("\\", "/"),
      username: draft.username.trim(),
      password: draft.password,
      domain: draft.domain.trim(),
    };
  else if (isDatabaseKind(kind))
    config = {
      host: draft.host,
      port: Number(draft.port),
      database: draft.database.trim(),
      schema: kind === "mysql" ? draft.database.trim() : draft.schema.trim(),
      tables: selectedTables(draft.tables),
      username: draft.username.trim(),
      password: draft.password,
    };
  else if (kind === "s3")
    config = {
      endpoint_url: draft.endpointUrl.trim().replace(/\/$/, ""),
      region: draft.region.trim(),
      bucket: draft.bucket.trim(),
      prefix: draft.prefix,
      auth_mode: draft.authMode,
      ...(draft.authMode === "access_key"
        ? {
            access_key_id: draft.accessKeyId.trim(),
            secret_access_key: draft.secretAccessKey,
            ...(draft.sessionToken
              ? { session_token: draft.sessionToken }
              : {}),
          }
        : {}),
    };
  else if (kind === "azure_blob")
    config = {
      account_url: draft.accountUrl.trim().replace(/\/$/, ""),
      container: draft.container.trim(),
      prefix: draft.prefix,
      sas_token: draft.sasToken.trim(),
    };
  else
    config = {
      account_url: draft.accountUrl.trim().replace(/\/$/, ""),
      table: draft.table.trim(),
      ...(draft.partitionKey ? { partition_key: draft.partitionKey } : {}),
      sas_token: draft.sasToken.trim(),
    };
  return { name: draft.name.trim(), kind, config, safety_validated: false };
}
