export type User = {
  id: string;
  username: string;
  role: "admin" | "operator" | "reviewer";
};
export type SourceKind =
  | "filesystem"
  | "smb"
  | "postgresql"
  | "mysql"
  | "mssql"
  | "s3"
  | "azure_blob"
  | "azure_table"
  | "sqlite";
export type Source = {
  id: string;
  name: string;
  kind: SourceKind;
  config?: Record<string, unknown>;
  enabled: boolean;
  safety_validated: boolean;
  created_at: string;
};
export type Scan = {
  id: string;
  source_id: string;
  source_name?: string;
  status: string;
  started_at?: string;
  finished_at?: string;
  created_at?: string;
  detector_version?: string;
  coverage: Record<string, number>;
  object_count: number;
  finding_count: number;
  error?: string;
  options?: { capture_evidence?: boolean; full_scan?: boolean };
};
export type ScanObject = {
  id: string;
  location: string;
  status: string;
  reason?: string;
  examined: number;
  unit: string;
  findings?: number;
  metadata?: Record<string, unknown> | string;
};
export type Finding = {
  id: string;
  scan_id: string;
  source_name?: string;
  location: string;
  entity_type: string;
  classification: string;
  confidence: number;
  match_count: number;
  reason: string;
  segment?: string;
  review_status: string;
  detector_version: string;
  coverage_status: string;
};
export type FindingEvidence = {
  finding_id: string;
  captured: boolean;
  available: boolean;
  examples: {
    value: string;
    excerpt: string;
    start?: number | null;
    end?: number | null;
    segment?: string;
  }[];
  truncated?: boolean;
  notice?: string;
};
export type Settings = {
  retention_days: number;
  audit_retention_days: number;
  retention_approved: boolean;
  environment: string;
  detector_mode: string;
  capabilities: Record<string, unknown>;
};
export type Overview = {
  sources: number;
  scans: number;
  findings: number;
  coverage: Record<string, number>;
  recent_scans: Scan[];
  capabilities: Record<string, unknown>;
};
export type FindingDelta = {
  entity_type: string;
  classification: string;
  reason: string;
  segment: string;
  before_count: number;
  after_count: number;
  change: "new" | "changed" | "no_longer_observed" | "unchanged";
};
export type ObjectChange = {
  location: string;
  change: string;
  reason: string;
  finding_comparison?: "comparable" | "not_comparable";
  finding_comparison_reason?: string;
  finding_deltas?: FindingDelta[];
};
export type Comparison = {
  baseline: string;
  current: string;
  detector_changed: boolean;
  options_changed?: boolean;
  summary: Record<string, number>;
  finding_summary?: Record<string, number>;
  finding_count_unit?: "recognizer_matches_not_unique_values_or_patients";
  changes: ObjectChange[];
};
export type Audit = {
  id: string;
  at?: string;
  created_at?: string;
  timestamp?: string;
  action: string;
  username?: string;
  actor?: string;
  detail?: unknown;
  details?: unknown;
};

export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(`/api${path}`, {
    ...init,
    credentials: "same-origin",
    headers: {
      "Content-Type": "application/json",
      "X-Requested-With": "SentryDiscovery",
      ...init.headers,
    },
  });
  if (!response.ok) {
    let message = `Request failed (${response.status}).`;
    try {
      const body = await response.json();
      if (typeof body.detail === "string") message = body.detail;
      else if (Array.isArray(body.detail))
        message = body.detail
          .map(
            (item: { msg: string; loc?: string[] }) =>
              `${item.loc?.slice(1).join(".") || "Input"}: ${item.msg}`,
          )
          .join("; ");
    } catch {
      /* Keep the status when an intermediary returns non-JSON. */
    }
    if (
      response.status === 401 &&
      path !== "/auth/login" &&
      path !== "/auth/me"
    )
      window.dispatchEvent(new Event("session-expired"));
    throw new ApiError(message, response.status);
  }
  if (response.status === 204) return undefined as T;
  return response.json();
}

export const json = (method: string, body?: unknown): RequestInit => ({
  method,
  ...(body === undefined ? {} : { body: JSON.stringify(body) }),
});
export const human = (value?: string) =>
  (value || "Unknown")
    .replace(/_/g, " ")
    .replace(/^./, (value) => value.toUpperCase());
export const number = (value: number | undefined) =>
  new Intl.NumberFormat("en-IN").format(value || 0);
export const date = (value?: string) =>
  value
    ? new Date(
        /(?:Z|[+-]\d{2}:\d{2})$/i.test(value) ? value : `${value}Z`,
      ).toLocaleString(undefined, {
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      })
    : "—";
export const active = (scan: Scan) =>
  ["queued", "running"].includes(scan.status);
