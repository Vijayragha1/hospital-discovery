import React, {
  useState,
  useEffect,
  useCallback,
  useRef,
  type ReactNode,
  type FormEvent,
} from "react";
import { createRoot } from "react-dom/client";
import {
  api,
  json,
  human,
  number,
  date,
  active,
  type User,
  type Source,
  type SourceKind,
  type Scan,
  type ScanObject,
  type Finding,
  type FindingEvidence,
  type Settings,
  type Overview,
  type Comparison,
  type ObjectChange,
  type FindingDelta,
  type Audit,
} from "./api";
import "./styles.css";
import { findingComparisonView, findingDeltaKey } from "./comparison-view";
import { ocrCoverage } from "./ocr-coverage";
import {
  newSourceDraft,
  updateSourceDraft,
  isDatabaseKind,
  isCloudKind,
  isTabularKind,
  joinApprovedPath,
  parseNetworkPath,
  selectedTables,
  validateSourceDraft,
  sourcePayload,
  type SourceSetup,
  type SourceDraft,
  type SourceErrors,
  type ConnectedSource,
} from "./source-setup";
import {
  credentialInputs,
  credentialUpdate,
  newCredentialDraft,
} from "./credential-setup";

type Page =
  | "Overview"
  | "Sources"
  | "Scans"
  | "Findings"
  | "Compare"
  | "Settings";
type IconName =
  | "shield"
  | "overview"
  | "sources"
  | "scans"
  | "findings"
  | "compare"
  | "settings"
  | "arrow"
  | "plus"
  | "check"
  | "lock"
  | "refresh"
  | "close"
  | "file"
  | "database"
  | "alert"
  | "logout"
  | "download"
  | "search";
const paths: Record<IconName, ReactNode> = {
  shield: (
    <>
      <path d="M12 3 4 6v6c0 5 8 9 8 9s8-4 8-9V6l-8-3Z" />
      <path d="m8 12 3 3 5-6" />
    </>
  ),
  overview: (
    <>
      <rect x="3" y="3" width="7" height="7" rx="1" />
      <rect x="14" y="3" width="7" height="7" rx="1" />
      <rect x="3" y="14" width="7" height="7" rx="1" />
      <rect x="14" y="14" width="7" height="7" rx="1" />
    </>
  ),
  sources: (
    <>
      <rect x="3" y="3" width="18" height="7" rx="2" />
      <rect x="3" y="14" width="18" height="7" rx="2" />
      <path d="M7 6.5h.01M7 17.5h.01M11 6.5h6M11 17.5h6" />
    </>
  ),
  scans: (
    <>
      <path d="M8 3H3v5m13-5h5v5M3 16v5h5m13-5v5h-5M3 12h18" />
      <rect x="8" y="7" width="8" height="10" rx="1" />
    </>
  ),
  findings: (
    <>
      <path d="M14 3H5v18h14V8zM14 3v5h5M8 12h8M8 16h5" />
    </>
  ),
  compare: (
    <>
      <path d="M3 7h17m-4-4 4 4-4 4M21 17H4m4-4-4 4 4 4" />
    </>
  ),
  settings: (
    <>
      <path d="M12 3v3m0 12v3M3 12h3m12 0h3M5.6 5.6l2.1 2.1m8.6 8.6 2.1 2.1M5.6 18.4l2.1-2.1m8.6-8.6 2.1-2.1" />
      <circle cx="12" cy="12" r="6" />
      <circle cx="12" cy="12" r="2" />
    </>
  ),
  arrow: <path d="M4 12h16m-6-6 6 6-6 6" />,
  plus: <path d="M12 5v14M5 12h14" />,
  check: <path d="m5 12 4 4L19 6" />,
  lock: (
    <>
      <rect x="5" y="10" width="14" height="11" rx="2" />
      <path d="M8 10V7a4 4 0 0 1 8 0v3M12 14v3" />
    </>
  ),
  refresh: (
    <>
      <path d="M20 7v5h-5M4 17v-5h5" />
      <path d="M6 6a8 8 0 0 1 14 6M4 12a8 8 0 0 0 14 6" />
    </>
  ),
  close: <path d="m6 6 12 12M6 18 18 6" />,
  file: (
    <>
      <path d="M14 3H5v18h14V8zM14 3v5h5" />
      <path d="M8 12h8M8 16h6" />
    </>
  ),
  database: (
    <>
      <ellipse cx="12" cy="5" rx="8" ry="3" />
      <path d="M4 5v14c0 4 16 4 16 0V5M4 12c0 4 16 4 16 0" />
    </>
  ),
  alert: (
    <>
      <path d="m12 3 10 18H2L12 3Z" />
      <path d="M12 9v5M12 17h.01" />
    </>
  ),
  logout: (
    <>
      <path d="M9 3H3v18h6m5-14 5 5-5 5M8 12h11" />
    </>
  ),
  download: (
    <>
      <path d="M12 3v12m-5-5 5 5 5-5M4 17v4h16v-4" />
    </>
  ),
  search: (
    <>
      <circle cx="10.5" cy="10.5" r="6.5" />
      <path d="m16 16 5 5" />
    </>
  ),
};
function Icon({ name, size = 20 }: { name: IconName; size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.7"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {paths[name]}
    </svg>
  );
}
function Badge({
  children,
  tone = "",
}: {
  children: ReactNode;
  tone?: string;
}) {
  return <span className={`badge ${tone}`}>{children}</span>;
}
function Status({ value }: { value: string }) {
  return (
    <Badge
      tone={
        ["completed", "full", "fully_scanned", "confirmed"].includes(value)
          ? "green"
          : ["failed", "inaccessible", "coverage_lost"].includes(value)
            ? "red"
            : ["running", "queued"].includes(value)
              ? "blue"
              : [
                    "sampled",
                    "partial",
                    "interrupted",
                    "needs_review",
                    "not_comparable",
                  ].includes(value)
                ? "amber"
                : ""
      }
    >
      <span className="status-dot" />
      {value === "full" ? "Fully scanned" : human(value)}
    </Badge>
  );
}
function Notice({
  children,
  kind = "info",
}: {
  children: ReactNode;
  kind?: "error" | "info" | "success";
}) {
  return (
    <div
      className={`notice ${kind}`}
      role={kind === "error" ? "alert" : "status"}
    >
      <Icon name={kind === "success" ? "check" : "alert"} size={18} />
      <div>{children}</div>
    </div>
  );
}
function Empty({
  title,
  children,
  icon = "file",
}: {
  title: string;
  children?: ReactNode;
  icon?: IconName;
}) {
  return (
    <div className="empty">
      <span className="empty-icon">
        <Icon name={icon} size={28} />
      </span>
      <h3>{title}</h3>
      <p>{children}</p>
    </div>
  );
}
function Loading() {
  return (
    <div className="loading" role="status">
      <span className="spinner" />
      Loading local data…
    </div>
  );
}
function Panel({
  title,
  subtitle,
  action,
  children,
  className = "",
}: {
  title: string;
  subtitle?: string;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`panel ${className}`}>
      <div className="panel-heading">
        <div>
          <h2>{title}</h2>
          {subtitle && <p>{subtitle}</p>}
        </div>
        {action}
      </div>
      {children}
    </section>
  );
}
function useData<T>(path: string | null, initial: T, refresh: number) {
  const [data, setData] = useState<T>(initial),
    [loading, setLoading] = useState(true),
    [error, setError] = useState("");
  useEffect(() => {
    if (!path) {
      setLoading(false);
      return;
    }
    let live = true;
    setLoading(true);
    setError("");
    api<T>(path)
      .then((result) => {
        if (live) setData(result);
      })
      .catch((error) => {
        if (live) setError(error.message);
      })
      .finally(() => {
        if (live) setLoading(false);
      });
    return () => {
      live = false;
    };
  }, [path, refresh]);
  return { data, loading, error };
}
function Modal({
  title,
  children,
  onClose,
  closeDisabled = false,
}: {
  title: string;
  children: ReactNode;
  onClose: () => void;
  closeDisabled?: boolean;
}) {
  const dialog = useRef<HTMLElement>(null),
    close = useRef(onClose);
  close.current = onClose;
  useEffect(() => {
    const previousFocus = document.activeElement as HTMLElement | null;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    const elements = () =>
      Array.from(
        dialog.current?.querySelectorAll<HTMLElement>(
          "button:not(:disabled),input:not(:disabled),select:not(:disabled),textarea:not(:disabled),a[href]",
        ) || [],
      );
    elements()[0]?.focus();
    const listener = (event: KeyboardEvent) => {
      if (event.key === "Escape") close.current();
      if (event.key !== "Tab") return;
      const targets = elements(),
        first = targets[0],
        last = targets[targets.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last?.focus();
      }
      if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first?.focus();
      }
    };
    document.addEventListener("keydown", listener);
    return () => {
      document.removeEventListener("keydown", listener);
      document.body.style.overflow = previousOverflow;
      previousFocus?.focus();
    };
  }, []);
  return (
    <div
      className="modal-backdrop"
      onClick={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <section
        ref={dialog}
        className="modal"
        role="dialog"
        aria-modal="true"
        aria-label={title}
      >
        <div className="modal-heading">
          <h2>{title}</h2>
          <button
            type="button"
            className="icon-button"
            aria-label="Close"
            onClick={onClose}
            disabled={closeDisabled}
          >
            <Icon name="close" />
          </button>
        </div>
        {children}
      </section>
    </div>
  );
}

function Login({ onLogin }: { onLogin: (user: User) => void }) {
  const [error, setError] = useState(""),
    [busy, setBusy] = useState(false);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError("");
    const values = new FormData(event.currentTarget);
    try {
      onLogin(
        await api<User>(
          "/auth/login",
          json("POST", Object.fromEntries(values)),
        ),
      );
    } catch (error) {
      setError((error as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <main className="login-layout">
      <section className="login-story">
        <div className="brand">
          <span className="brand-icon">
            <Icon name="shield" size={27} />
          </span>
          <div>
            Sentry<span>DISCOVERY</span>
          </div>
        </div>
        <div className="login-intro">
          <span className="eyebrow light">
            SENSITIVE DATA. VISIBLE COVERAGE.
          </span>
          <h1>
            Know where
            <br />
            patient data lives.
          </h1>
          <p>
            Discover sensitive information across your hospital’s databases and
            file servers. Every finding, every scan, entirely local.
          </p>
          <div className="login-features">
            <div>
              <Icon name="database" />
              <span>Structured & unstructured discovery</span>
            </div>
            <div>
              <Icon name="scans" />
              <span>Transparent scanning coverage</span>
            </div>
            <div>
              <Icon name="lock" />
              <span>Local processing. Read-only access.</span>
            </div>
          </div>
        </div>
        <span className="login-foot">HOSPITAL DISCOVERY PILOT · ENGLISH</span>
      </section>
      <section className="login-main">
        <div className="login-form">
          <Badge tone="green">
            <span className="status-dot" />
            Hospital-local workspace
          </Badge>
          <h2>Welcome back</h2>
          <p>Sign in to your discovery workspace.</p>
          {error && <Notice kind="error">{error}</Notice>}
          <form onSubmit={submit}>
            <label>
              Username
              <input
                name="username"
                autoComplete="username"
                required
                autoFocus
                placeholder="Your username"
              />
            </label>
            <label>
              Password
              <input
                name="password"
                type="password"
                autoComplete="current-password"
                required
                placeholder="Your password"
              />
            </label>
            <button className="button primary full" disabled={busy}>
              {busy ? "Signing in…" : "Sign in"}
              <Icon name="arrow" size={18} />
            </button>
          </form>
          <p className="login-help">
            <Icon name="lock" size={15} />
            Accounts are provisioned by your local administrator.
          </p>
        </div>
        <p className="login-caption">
          Discovery supports review. It does not certify compliance.
        </p>
      </section>
    </main>
  );
}

function Coverage({ coverage }: { coverage: Record<string, number> }) {
  const total = Object.values(coverage || {}).reduce(
    (sum, value) => sum + value,
    0,
  );
  const known = [
    "full",
    "sampled",
    "partial",
    "inaccessible",
    "unsupported",
    "excluded",
    "failed",
  ];
  const entries = [
    ...known,
    ...Object.keys(coverage || {}).filter((key) => !known.includes(key)),
  ];
  return (
    <div className="coverage">
      <div className="coverage-intro">
        <strong>{number(total)}</strong>
        <span>objects accounted for</span>
        <Badge>Coverage, not accuracy</Badge>
      </div>
      <div
        className="coverage-track"
        aria-label={`${total} objects by coverage status`}
      >
        {entries
          .filter((key) => coverage?.[key])
          .map((key) => (
            <div
              key={key}
              className={`coverage-piece ${key}`}
              style={{ width: `${(coverage[key] / total) * 100}%` }}
              title={`${human(key)}: ${coverage[key]}`}
            />
          ))}
      </div>
      <div className="coverage-legend">
        {entries.map((key) => (
          <div key={key}>
            <span className={`legend-dot ${key}`} />
            <span>{key === "full" ? "Fully scanned" : human(key)}</span>
            <strong>{number(coverage?.[key])}</strong>
          </div>
        ))}
      </div>
    </div>
  );
}
function ScanTable({
  scans,
  onSelect,
}: {
  scans: Scan[];
  onSelect: (scan: Scan) => void;
}) {
  return (
    <div className="table-scroll">
      <table>
        <thead>
          <tr>
            <th>Source / scan</th>
            <th>Status</th>
            <th>Objects</th>
            <th>Findings</th>
            <th>Started</th>
            <th>
              <span className="sr-only">Open</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {scans.map((scan) => (
            <tr key={scan.id}>
              <td>
                <button className="table-link" onClick={() => onSelect(scan)}>
                  {scan.source_name || scan.source_id}
                  <span className="subtext mono">{scan.id.slice(0, 12)}</span>
                </button>
              </td>
              <td>
                <Status value={scan.status} />
              </td>
              <td>{number(scan.object_count)}</td>
              <td>{number(scan.finding_count)}</td>
              <td className="nowrap muted">
                {date(scan.started_at || scan.created_at)}
              </td>
              <td>
                <button
                  className="icon-button"
                  aria-label={`View scan ${scan.id}`}
                  onClick={() => onSelect(scan)}
                >
                  <Icon name="arrow" size={17} />
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
function OverviewPage({
  refresh,
  navigate,
  onScan,
}: {
  refresh: number;
  navigate: (page: Page) => void;
  onScan: (scan: Scan) => void;
}) {
  const { data, loading, error } = useData<Overview | null>(
    "/overview",
    null,
    refresh,
  );
  if (loading && !data) return <Loading />;
  if (error) return <Notice kind="error">{error}</Notice>;
  if (!data) return null;
  const gaps = Object.entries(data.coverage || {})
    .filter(([key]) => !["full", "fully_scanned"].includes(key))
    .reduce((sum, [, value]) => sum + value, 0);
  return (
    <>
      <div className="overview-banner">
        <div>
          <span className="eyebrow">YOUR HOSPITAL’S DATA FOOTPRINT</span>
          <h2>Clarity starts with coverage.</h2>
          <p>
            Find sensitive data. Understand what was examined.
            <br />
            Keep the evidence inside your environment.
          </p>
        </div>
        <div className="banner-mark">
          <Icon name="shield" size={70} />
          <span>
            LOCAL
            <br />
            BY DESIGN
          </span>
        </div>
      </div>
      <div className="metrics">
        {(
          [
            {
              label: "Registered sources",
              value: data.sources,
              icon: "sources",
              note: "Databases & shared files",
            },
            {
              label: "Discovery scans",
              value: data.scans,
              icon: "scans",
              note: "All scan states",
            },
            {
              label: "Finding records",
              value: data.findings,
              icon: "findings",
              note: "Not unique patient counts",
            },
            {
              label: "Coverage gaps",
              value: gaps,
              icon: "alert",
              note: "Includes sampled & excluded",
            },
          ] as { label: string; value: number; icon: IconName; note: string }[]
        ).map((metric) => (
          <div className="metric" key={metric.label}>
            <div className="metric-top">
              <span>{metric.label}</span>
              <Icon name={metric.icon} />
            </div>
            <strong>{number(metric.value)}</strong>
            <span className="metric-note">{metric.note}</span>
          </div>
        ))}
      </div>
      <div className="overview-grid">
        <Panel
          title="Coverage at a glance"
          subtitle="Scope examined across recorded scans"
        >
          <Coverage coverage={data.coverage || {}} />
        </Panel>
        <Panel
          title="Pilot boundaries"
          subtitle="Know what the results mean"
          className="boundaries"
        >
          <div className="boundary-item">
            <span className="boundary-check">
              <Icon name="check" size={16} />
            </span>
            <div>
              <strong>English typed & printed text</strong>
              <p>
                Digital documents, database fields, and OCR where available.
              </p>
            </div>
          </div>
          <div className="boundary-item">
            <span className="boundary-check">
              <Icon name="lock" size={16} />
            </span>
            <div>
              <strong>Discovery only</strong>
              <p>No source modification, deletion, or automatic masking.</p>
            </div>
          </div>
          <div className="boundary-note">
            No matches does not mean no sensitive data. Always review coverage
            and detector limitations.
          </div>
        </Panel>
      </div>
      <Panel
        title="Recent scans"
        subtitle="Review findings alongside what was actually scanned"
        action={
          <button className="text-button" onClick={() => navigate("Scans")}>
            All scans <Icon name="arrow" size={16} />
          </button>
        }
      >
        {data.recent_scans?.length ? (
          <ScanTable scans={data.recent_scans} onSelect={onScan} />
        ) : (
          <Empty title="Your discovery workspace is ready" icon="scans">
            Register an approved source, validate access, and start your first
            scan.
          </Empty>
        )}
      </Panel>
    </>
  );
}

const sourceLabels: Record<SourceKind, string> = {
  filesystem: "Mounted folder",
  smb: "SMB / Windows share",
  postgresql: "PostgreSQL",
  mysql: "MySQL",
  mssql: "Microsoft SQL Server",
  s3: "S3 / compatible storage",
  azure_blob: "Azure Blob Storage",
  azure_table: "Azure Table Storage",
  sqlite: "SQLite · development fixture",
};
function SourceWizardField({
  field,
  label,
  hint,
  error,
  children,
}: {
  field: keyof SourceDraft;
  label: string;
  hint?: string;
  error?: string;
  children: ReactNode;
}) {
  return (
    <div className="wizard-field">
      <label htmlFor={`source-${field}`}>{label}</label>
      {children}
      {hint && (
        <p id={`source-${field}-hint`} className="fine-print">
          {hint}
        </p>
      )}
      {error && (
        <p id={`source-${field}-error`} className="field-error">
          {error}
        </p>
      )}
    </div>
  );
}

function SourceForm({
  onClose,
  onSaved,
}: {
  onClose: () => void;
  onSaved: () => void;
}) {
  const [setup, setSetup] = useState<SourceSetup | null>(null);
  const [setupError, setSetupError] = useState("");
  const [loading, setLoading] = useState(true);
  const [attempt, setAttempt] = useState(0);
  const [step, setStep] = useState(1);
  const [kind, setKind] = useState<SourceKind | null>(null);
  const [draft, setDraft] = useState<SourceDraft>(() => newSourceDraft());
  const [errors, setErrors] = useState<SourceErrors>({});
  const [advanced, setAdvanced] = useState(false);
  const [busy, setBusy] = useState(false);
  const [connectError, setConnectError] = useState("");
  const [connected, setConnected] = useState<ConnectedSource | null>(null);
  const inFlight = useRef(false);
  const form = useRef<HTMLFormElement>(null);
  const heading = useRef<HTMLHeadingElement>(null);
  const wizardLabels: Record<SourceKind, string> = {
    filesystem: "Folder on scanner",
    smb: "Windows / network share",
    postgresql: "PostgreSQL",
    mysql: "MySQL",
    mssql: "Microsoft SQL Server",
    s3: "S3 / compatible storage",
    azure_blob: "Azure Blob Storage",
    azure_table: "Azure Table Storage",
    sqlite: "SQLite development fixture",
  };

  useEffect(() => {
    const request = new AbortController();
    setLoading(true);
    setSetupError("");
    api<SourceSetup>("/source-setup", { signal: request.signal })
      .then((result) => {
        if (request.signal.aborted) return;
        setSetup(result);
        setDraft(newSourceDraft(result));
      })
      .catch((error) => {
        if (!request.signal.aborted) setSetupError(error.message);
      })
      .finally(() => {
        if (!request.signal.aborted) setLoading(false);
      });
    return () => request.abort();
  }, [attempt]);
  useEffect(() => {
    heading.current?.focus();
  }, [step, connected]);

  function closeWizard() {
    if (!inFlight.current) onClose();
  }
  function chooseKind(next: SourceKind) {
    if (!setup || inFlight.current) return;
    if (kind !== next) {
      setDraft(newSourceDraft(setup, draft.name, next));
      setAdvanced(false);
    }
    setKind(next);
    setErrors({});
    setConnectError("");
  }
  function update(field: keyof SourceDraft, value: string) {
    setDraft((previous) => updateSourceDraft(previous, field, value, kind));
    setErrors((previous) => ({ ...previous, [field]: undefined }));
    setConnectError("");
  }
  function props(field: keyof SourceDraft) {
    return {
      id: `source-${field}`,
      name: field,
      value: draft[field],
      onChange: (
        event: React.ChangeEvent<
          HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement
        >,
      ) => update(field, event.target.value),
      "aria-invalid": !!errors[field],
      "aria-describedby":
        [
          [
            "root",
            "folder",
            "fixtureFile",
            "networkPath",
            "database",
            "domain",
            "tables",
            "endpointUrl",
            "accountUrl",
            "prefix",
            "partitionKey",
            "sasToken",
          ].includes(field)
            ? `source-${field}-hint`
            : "",
          errors[field] ? `source-${field}-error` : "",
        ]
          .filter(Boolean)
          .join(" ") || undefined,
    };
  }
  function focusError() {
    requestAnimationFrame(() =>
      form.current
        ?.querySelector<HTMLElement>('[aria-invalid="true"]')
        ?.focus(),
    );
  }
  function applyNetworkPath(): SourceDraft | null {
    if (!setup || !draft.networkPath.trim()) return draft;
    try {
      const parsed = {
        ...draft,
        ...parseNetworkPath(draft.networkPath, setup.smb_hosts),
      };
      setDraft(parsed);
      setErrors((previous) => ({
        ...previous,
        networkPath: undefined,
        server: undefined,
        share: undefined,
        subpath: undefined,
      }));
      return parsed;
    } catch (error) {
      setErrors((previous) => ({
        ...previous,
        networkPath: (error as Error).message,
      }));
      focusError();
      return null;
    }
  }
  function next() {
    if (!setup || !kind || inFlight.current) return;
    if (step === 1) {
      setStep(2);
      return;
    }
    const candidate = kind === "smb" ? applyNetworkPath() : draft;
    if (!candidate) return;
    const validation = validateSourceDraft(kind, candidate, setup);
    setErrors(validation);
    if (Object.keys(validation).length) {
      if (validation.port || validation.schema || validation.tables)
        setAdvanced(true);
      focusError();
      return;
    }
    setConnectError("");
    setStep(3);
  }
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (inFlight.current) return;
    if (step !== 3) {
      next();
      return;
    }
    if (!setup || !kind) return;
    const validation = validateSourceDraft(kind, draft, setup);
    if (Object.keys(validation).length) {
      setErrors(validation);
      setStep(2);
      focusError();
      return;
    }
    inFlight.current = true;
    setBusy(true);
    setConnectError("");
    try {
      const result = await api<ConnectedSource>(
        "/sources/connect",
        json("POST", sourcePayload(kind, draft)),
      );
      setDraft((previous) => ({
        ...previous,
        password: "",
        accessKeyId: "",
        secretAccessKey: "",
        sessionToken: "",
        sasToken: "",
      }));
      setConnected(result);
      onSaved();
    } catch (error) {
      setConnectError((error as Error).message);
    } finally {
      inFlight.current = false;
      setBusy(false);
    }
  }
  const supports = (value: SourceKind) =>
    !!setup?.supported_kinds.includes(value);
  const hasRoots = !!setup?.allowed_roots.length;
  const hasServers = !!setup?.smb_hosts.length;
  const hasDatabases = !!setup?.database_hosts.length;
  const remote = kind === "smb" || isDatabaseKind(kind);
  const cloudHosts = setup?.cloud_hosts || [];
  const tableList = selectedTables(draft.tables);
  const approvalHint =
    "Ask your scanner administrator to approve a location, then reopen this guide.";

  return (
    <Modal title="Register a source" onClose={closeWizard} closeDisabled={busy}>
      {loading ? (
        <div className="modal-body">
          <Loading />
        </div>
      ) : setupError || !setup ? (
        <div className="modal-body">
          <Notice kind="error">
            {setupError || "Source setup is unavailable."}
          </Notice>
          <p className="fine-print">
            Check the local service connection and try again.
          </p>
          <div className="form-actions">
            <button type="button" className="button" onClick={closeWizard}>
              Close
            </button>
            <button
              type="button"
              className="button primary"
              onClick={() => setAttempt((value) => value + 1)}
            >
              Try again
            </button>
          </div>
        </div>
      ) : connected ? (
        <div className="modal-body wizard-success">
          <span className="success-mark">
            <Icon name="check" size={30} />
          </span>
          <h3 ref={heading} tabIndex={-1}>
            Source connected
          </h3>
          <p>
            <strong>{connected.source.name}</strong> is now in your source
            inventory.
          </p>
          <div className="connection-result">
            <Icon name="check" size={17} />
            <span>Connection checked</span>
          </div>
          {connected.check.cancellation_verified && (
            <div className="connection-result">
              <Icon name="check" size={17} />
              <span>Database query cancellation verified</span>
            </div>
          )}
          {connected.check.note && (
            <p className="fine-print">{connected.check.note}</p>
          )}
          <p className="fine-print">
            No discovery scan has started. Review the hospital’s scan window,
            workload limits, and retention settings before scanning.
          </p>
          <div className="form-actions">
            <button
              type="button"
              className="button primary"
              onClick={closeWizard}
            >
              Done
              <Icon name="arrow" size={16} />
            </button>
          </div>
        </div>
      ) : (
        <form
          ref={form}
          className="modal-body source-wizard"
          onSubmit={submit}
          noValidate
          aria-busy={busy}
        >
          <ol className="wizard-progress" aria-label="Registration progress">
            {["Choose source", "Connection details", "Review & connect"].map(
              (label, index) => (
                <li
                  key={label}
                  className={
                    step === index + 1
                      ? "current"
                      : step > index + 1
                        ? "done"
                        : ""
                  }
                  aria-current={step === index + 1 ? "step" : undefined}
                >
                  <span>
                    {step > index + 1 ? (
                      <Icon name="check" size={12} />
                    ) : (
                      index + 1
                    )}
                  </span>
                  <div>{label}</div>
                </li>
              ),
            )}
          </ol>
          <div className="wizard-step-heading">
            <span className="eyebrow">STEP {step} OF 3</span>
            <h3 ref={heading} tabIndex={-1}>
              {step === 1
                ? "Where is the data?"
                : step === 2
                  ? "Tell us how to connect"
                  : "Check the details"}
            </h3>
            <p>
              {step === 1
                ? "Choose the place you want to discover sensitive data."
                : step === 2
                  ? "Use a name your team will recognize and an approved location."
                  : "We’ll check access before adding this source. No scan starts here."}
            </p>
          </div>
          {step === 1 && (
            <>
              <fieldset className="source-kind-options">
                <legend className="sr-only">Source type</legend>
                {(
                  [
                    {
                      label: "Databases",
                      options: [
                        {
                          kind: "postgresql",
                          icon: "database",
                          description: "PostgreSQL tables and clinical text.",
                        },
                        {
                          kind: "mysql",
                          icon: "database",
                          description: "MySQL tables and clinical text.",
                        },
                        {
                          kind: "mssql",
                          icon: "database",
                          description:
                            "Microsoft SQL Server tables and clinical text.",
                        },
                      ],
                    },
                    {
                      label: "File shares",
                      options: [
                        {
                          kind: "filesystem",
                          icon: "file",
                          description:
                            "An approved folder mounted on this scanner.",
                        },
                        {
                          kind: "smb",
                          icon: "sources",
                          description: "A Windows shared folder or NAS.",
                        },
                      ],
                    },
                    {
                      label: "Cloud storage",
                      options: [
                        {
                          kind: "s3",
                          icon: "sources",
                          description:
                            "Objects in one bucket and optional prefix.",
                        },
                        {
                          kind: "azure_blob",
                          icon: "file",
                          description: "Documents in one storage container.",
                        },
                        {
                          kind: "azure_table",
                          icon: "database",
                          description:
                            "Sample entities from one selected table.",
                        },
                      ],
                    },
                  ] as {
                    label: string;
                    options: {
                      kind: SourceKind;
                      icon: IconName;
                      description: string;
                    }[];
                  }[]
                ).map((group) => (
                  <div className="source-kind-group" key={group.label}>
                    <h4>{group.label}</h4>
                    <div className="source-kind-grid">
                      {group.options.map((option) => (
                        <label
                          className={`source-kind-card ${kind === option.kind ? "chosen" : ""} ${!supports(option.kind) ? "unavailable" : ""}`}
                          key={option.kind}
                        >
                          <input
                            className="sr-only"
                            type="radio"
                            name="source-kind"
                            value={option.kind}
                            checked={kind === option.kind}
                            onChange={() => chooseKind(option.kind)}
                            disabled={!supports(option.kind)}
                          />
                          <span className="source-kind-icon">
                            <Icon name={option.icon} size={22} />
                          </span>
                          <span className="source-kind-text">
                            <strong>{wizardLabels[option.kind]}</strong>
                            <span>
                              {supports(option.kind)
                                ? option.description
                                : "Unavailable in this installation."}
                            </span>
                          </span>
                          <span
                            className="source-kind-radio"
                            aria-hidden="true"
                          >
                            {kind === option.kind && <span />}
                          </span>
                        </label>
                      ))}
                    </div>
                  </div>
                ))}
              </fieldset>
              {setup.environment === "development" && supports("sqlite") && (
                <details className="wizard-advanced">
                  <summary>Development fixtures</summary>
                  <label
                    className={`source-kind-card ${kind === "sqlite" ? "chosen" : ""}`}
                  >
                    <input
                      className="sr-only"
                      type="radio"
                      name="source-kind"
                      value="sqlite"
                      checked={kind === "sqlite"}
                      onChange={() => chooseKind("sqlite")}
                    />
                    <span className="source-kind-icon">
                      <Icon name="database" size={21} />
                    </span>
                    <span className="source-kind-text">
                      <strong>SQLite fixture file</strong>
                      <span>
                        Local testing only. This does not connect to the
                        hospital’s live system.
                      </span>
                    </span>
                    <span className="source-kind-radio" aria-hidden="true">
                      {kind === "sqlite" && <span />}
                    </span>
                  </label>
                </details>
              )}
              <p className="fine-print">
                Choose only a location approved for this pilot. Access is
                checked with your connection details in the next steps.
              </p>
            </>
          )}
          {step === 2 && kind && (
            <>
              <SourceWizardField
                field="name"
                label="Source name"
                error={errors.name}
              >
                <input
                  {...props("name")}
                  maxLength={120}
                  placeholder={
                    isDatabaseKind(kind)
                      ? "e.g. Hospital patient records"
                      : "e.g. Discharge summaries"
                  }
                />
              </SourceWizardField>
              {(kind === "filesystem" || kind === "sqlite") && (
                <>
                  <SourceWizardField
                    field="root"
                    label="Approved folder on this scanner"
                    error={errors.root}
                    hint="This is a folder inside the scanner environment, not a folder picker on your laptop."
                  >
                    <select {...props("root")} disabled={!hasRoots}>
                      <option value="" disabled>
                        {hasRoots
                          ? "Choose a folder"
                          : "No approved folders configured"}
                      </option>
                      {setup.allowed_roots.map((root) => (
                        <option key={root} value={root}>
                          {root}
                        </option>
                      ))}
                    </select>
                  </SourceWizardField>
                  {!hasRoots && (
                    <p className="wizard-setup-gap">{approvalHint}</p>
                  )}
                  {kind === "filesystem" ? (
                    <SourceWizardField
                      field="folder"
                      label="Subfolder (optional)"
                      error={errors.folder}
                      hint="Leave blank to include the selected folder. Use a subfolder to narrow the pilot."
                    >
                      <input
                        {...props("folder")}
                        placeholder="e.g. Records/Discharge"
                      />
                    </SourceWizardField>
                  ) : (
                    <SourceWizardField
                      field="fixtureFile"
                      label="SQLite fixture filename"
                      error={errors.fixtureFile}
                      hint="Enter the filename or relative path inside the selected folder."
                    >
                      <input
                        {...props("fixtureFile")}
                        placeholder="e.g. fixtures/hospital.db"
                      />
                    </SourceWizardField>
                  )}
                  {hasRoots && (
                    <p className="wizard-path-preview">
                      <span>Location to check</span>
                      <code>
                        {joinApprovedPath(
                          draft.root,
                          kind === "sqlite" ? draft.fixtureFile : draft.folder,
                        )}
                      </code>
                    </p>
                  )}
                </>
              )}
              {kind === "smb" && (
                <>
                  <SourceWizardField
                    field="networkPath"
                    label="Have a network path? Paste it here (optional)"
                    error={errors.networkPath}
                    hint="We’ll fill in the server, share, and subfolder from a Windows network path."
                  >
                    <div className="network-path-input">
                      <input
                        {...props("networkPath")}
                        placeholder="\\files.hospital.local\Records\Pilot"
                      />
                      <button
                        className="button small"
                        type="button"
                        disabled={!draft.networkPath.trim()}
                        onClick={() => applyNetworkPath()}
                      >
                        Use path
                      </button>
                    </div>
                  </SourceWizardField>
                  <SourceWizardField
                    field="server"
                    label="Approved file server"
                    error={errors.server}
                  >
                    <select {...props("server")} disabled={!hasServers}>
                      <option value="" disabled>
                        {hasServers
                          ? "Choose a server"
                          : "No approved file servers configured"}
                      </option>
                      {setup.smb_hosts.map((host) => (
                        <option key={host} value={host}>
                          {host}
                        </option>
                      ))}
                    </select>
                  </SourceWizardField>
                  {!hasServers && (
                    <p className="wizard-setup-gap">{approvalHint}</p>
                  )}
                  <div className="form-grid">
                    <SourceWizardField
                      field="share"
                      label="Shared folder name"
                      error={errors.share}
                    >
                      <input {...props("share")} placeholder="e.g. Records" />
                    </SourceWizardField>
                    <SourceWizardField
                      field="subpath"
                      label="Subfolder (optional)"
                      error={errors.subpath}
                    >
                      <input
                        {...props("subpath")}
                        placeholder="e.g. Discharge/Pilot"
                      />
                    </SourceWizardField>
                  </div>
                </>
              )}
              {isDatabaseKind(kind) && (
                <>
                  <SourceWizardField
                    field="host"
                    label="Approved database server"
                    error={errors.host}
                  >
                    <select {...props("host")} disabled={!hasDatabases}>
                      <option value="" disabled>
                        {hasDatabases
                          ? "Choose a server"
                          : "No approved database servers configured"}
                      </option>
                      {setup.database_hosts.map((host) => (
                        <option key={host} value={host}>
                          {host}
                        </option>
                      ))}
                    </select>
                  </SourceWizardField>
                  {!hasDatabases && (
                    <p className="wizard-setup-gap">{approvalHint}</p>
                  )}
                  <SourceWizardField
                    field="database"
                    label="Database name"
                    error={errors.database}
                    hint="Hospital IT can provide the database name and a dedicated read-only account."
                  >
                    <input
                      {...props("database")}
                      placeholder="e.g. hospital_records"
                    />
                  </SourceWizardField>
                  <p className="fine-print">
                    The scanner verifies the server’s TLS certificate. Hospital
                    IT configures the trusted certificate authority on the
                    scanner.
                  </p>
                </>
              )}
              {isCloudKind(kind) && (
                <>
                  <SourceWizardField
                    field={kind === "s3" ? "endpointUrl" : "accountUrl"}
                    label={
                      kind === "s3"
                        ? "Approved S3 service endpoint"
                        : "Approved storage account endpoint"
                    }
                    error={errors[kind === "s3" ? "endpointUrl" : "accountUrl"]}
                    hint="Use the HTTPS service address approved for this scanner, without a resource path or token."
                  >
                    <input
                      {...props(kind === "s3" ? "endpointUrl" : "accountUrl")}
                      type="url"
                      list="approved-cloud-endpoints"
                      placeholder={
                        kind === "s3"
                          ? "https://s3.ap-south-1.amazonaws.com"
                          : kind === "azure_blob"
                            ? "https://hospital.blob.core.windows.net"
                            : "https://hospital.table.core.windows.net"
                      }
                    />
                    <datalist id="approved-cloud-endpoints">
                      {cloudHosts.map((host) => (
                        <option key={host} value={`https://${host}`} />
                      ))}
                    </datalist>
                  </SourceWizardField>
                  {!cloudHosts.length && (
                    <p className="wizard-setup-gap">
                      No cloud endpoints are approved yet. {approvalHint}
                    </p>
                  )}
                  {kind === "s3" ? (
                    <>
                      <div className="form-grid">
                        <SourceWizardField
                          field="bucket"
                          label="Bucket name"
                          error={errors.bucket}
                        >
                          <input
                            {...props("bucket")}
                            placeholder="e.g. hospital-records"
                            maxLength={63}
                          />
                        </SourceWizardField>
                        <SourceWizardField
                          field="region"
                          label="Region"
                          error={errors.region}
                        >
                          <input
                            {...props("region")}
                            placeholder="ap-south-1"
                          />
                        </SourceWizardField>
                      </div>
                      <SourceWizardField
                        field="prefix"
                        label="Object prefix (optional)"
                        error={errors.prefix}
                        hint="Leave blank for all objects in this bucket. A prefix narrows the approved scope; it is matched exactly."
                      >
                        <input
                          {...props("prefix")}
                          placeholder="e.g. discharge/"
                          maxLength={1024}
                        />
                      </SourceWizardField>
                      <fieldset className="wizard-account">
                        <legend>Read-only access</legend>
                        <SourceWizardField
                          field="authMode"
                          label="How should the scanner sign in?"
                          error={errors.authMode}
                        >
                          <select {...props("authMode")}>
                            <option value="access_key">
                              Dedicated access key
                            </option>
                            <option value="iam_role">
                              Scanner’s EC2 instance role
                            </option>
                          </select>
                        </SourceWizardField>
                        {draft.authMode === "access_key" ? (
                          <>
                            <p className="fine-print">
                              Use credentials restricted to listing this bucket
                              and reading the approved objects.
                            </p>
                            <SourceWizardField
                              field="accessKeyId"
                              label="Access key ID"
                              error={errors.accessKeyId}
                            >
                              <input
                                {...props("accessKeyId")}
                                autoComplete="off"
                                spellCheck={false}
                              />
                            </SourceWizardField>
                            <SourceWizardField
                              field="secretAccessKey"
                              label="Secret access key"
                              error={errors.secretAccessKey}
                            >
                              <input
                                {...props("secretAccessKey")}
                                type="password"
                                autoComplete="new-password"
                              />
                            </SourceWizardField>
                            <SourceWizardField
                              field="sessionToken"
                              label="Session token (optional)"
                              error={errors.sessionToken}
                            >
                              <input
                                {...props("sessionToken")}
                                type="password"
                                autoComplete="new-password"
                              />
                            </SourceWizardField>
                          </>
                        ) : (
                          <p className="fine-print">
                            Hospital IT must attach a read-only instance profile
                            to this scanner’s EC2 host and configure access to
                            IMDSv2. No access keys are saved for this option.
                          </p>
                        )}
                      </fieldset>
                    </>
                  ) : (
                    <>
                      {kind === "azure_blob" ? (
                        <>
                          <SourceWizardField
                            field="container"
                            label="Container name"
                            error={errors.container}
                          >
                            <input
                              {...props("container")}
                              placeholder="e.g. hospital-records"
                              maxLength={63}
                            />
                          </SourceWizardField>
                          <SourceWizardField
                            field="prefix"
                            label="Blob prefix (optional)"
                            error={errors.prefix}
                            hint="Leave blank for all blobs in this container. A prefix narrows the approved scope; it is matched exactly."
                          >
                            <input
                              {...props("prefix")}
                              placeholder="e.g. discharge/"
                              maxLength={1024}
                            />
                          </SourceWizardField>
                        </>
                      ) : (
                        <>
                          <SourceWizardField
                            field="table"
                            label="Table name"
                            error={errors.table}
                          >
                            <input
                              {...props("table")}
                              placeholder="e.g. PatientRecords"
                              maxLength={63}
                            />
                          </SourceWizardField>
                          <SourceWizardField
                            field="partitionKey"
                            label="Partition key (optional)"
                            error={errors.partitionKey}
                            hint="Leave blank to sample across this table. Otherwise, only the exact partition is included. Each scan samples at most 1,000 entities."
                          >
                            <input
                              {...props("partitionKey")}
                              placeholder="Exact approved partition key"
                            />
                          </SourceWizardField>
                        </>
                      )}
                      <SourceWizardField
                        field="sasToken"
                        label="Read-only SAS token"
                        error={errors.sasToken}
                        hint={
                          kind === "azure_blob"
                            ? "Use a container-scoped token with read and list permissions, HTTPS only, and an explicit expiry."
                            : "Use a token for this named table with read permission, HTTPS only, and an explicit expiry."
                        }
                      >
                        <input
                          {...props("sasToken")}
                          type="password"
                          autoComplete="new-password"
                        />
                      </SourceWizardField>
                    </>
                  )}
                  <p className="fine-print">
                    Enter the resource name supplied by hospital IT. We do not
                    browse other buckets, containers, or tables. Processing and
                    findings remain on this scanner.
                  </p>
                </>
              )}
              {remote && (
                <fieldset className="wizard-account">
                  <legend>Read-only account</legend>
                  <p className="fine-print">
                    Use an account supplied by hospital IT that cannot create,
                    change, or delete source data.
                  </p>
                  <div className="form-grid">
                    <SourceWizardField
                      field="username"
                      label="Account name"
                      error={errors.username}
                    >
                      <input
                        {...props("username")}
                        autoComplete="off"
                        placeholder={
                          kind === "smb"
                            ? "e.g. discovery_reader"
                            : "e.g. discovery_ro"
                        }
                      />
                    </SourceWizardField>
                    <SourceWizardField
                      field="password"
                      label="Password"
                      error={errors.password}
                    >
                      <input
                        {...props("password")}
                        type="password"
                        autoComplete="new-password"
                      />
                    </SourceWizardField>
                  </div>
                  {kind === "smb" && (
                    <SourceWizardField
                      field="domain"
                      label="Windows domain (optional)"
                      hint="Leave blank if the account name already includes the domain or uses a local account."
                    >
                      <input
                        {...props("domain")}
                        placeholder="e.g. HOSPITAL"
                        autoComplete="off"
                      />
                    </SourceWizardField>
                  )}
                </fieldset>
              )}
              {isDatabaseKind(kind) && (
                <details
                  className="wizard-advanced"
                  open={advanced}
                  onToggle={(event) => setAdvanced(event.currentTarget.open)}
                >
                  <summary>
                    {kind === "mysql"
                      ? "Advanced: port and table scope"
                      : "Advanced: port, schema, and table scope"}
                  </summary>
                  <div className="advanced-fields">
                    <div className="form-grid">
                      <SourceWizardField
                        field="port"
                        label="Port"
                        error={errors.port}
                      >
                        <input
                          {...props("port")}
                          type="number"
                          min={1}
                          max={65535}
                        />
                      </SourceWizardField>
                      {kind !== "mysql" && (
                        <SourceWizardField
                          field="schema"
                          label="Schema"
                          error={errors.schema}
                        >
                          <input
                            {...props("schema")}
                            placeholder={kind === "mssql" ? "dbo" : "public"}
                          />
                        </SourceWizardField>
                      )}
                    </div>
                    {kind === "mysql" && (
                      <p className="fine-print">
                        The schema follows the database name.
                      </p>
                    )}
                    <SourceWizardField
                      field="tables"
                      label="Selected tables (optional)"
                      error={errors.tables}
                      hint="Separate names with commas. Leave blank for all tables in this schema; initial scans remain sampled."
                    >
                      <textarea
                        {...props("tables")}
                        rows={2}
                        placeholder="patients, clinical_notes"
                      />
                    </SourceWizardField>
                  </div>
                </details>
              )}
            </>
          )}
          {step === 3 && kind && (
            <>
              <dl className="source-review">
                <dt>Source name</dt>
                <dd>{draft.name.trim()}</dd>
                <dt>Source type</dt>
                <dd>{wizardLabels[kind]}</dd>
                {kind === "filesystem" || kind === "sqlite" ? (
                  <>
                    <dt>Scanner location</dt>
                    <dd>
                      <code>
                        {joinApprovedPath(
                          draft.root,
                          kind === "sqlite" ? draft.fixtureFile : draft.folder,
                        )}
                      </code>
                    </dd>
                  </>
                ) : kind === "smb" ? (
                  <>
                    <dt>Network location</dt>
                    <dd>
                      <code>{`\\\\${draft.server}\\${draft.share}${draft.subpath ? "\\" + draft.subpath.replaceAll("/", "\\") : ""}`}</code>
                    </dd>
                  </>
                ) : isDatabaseKind(kind) ? (
                  <>
                    <dt>Database server</dt>
                    <dd>
                      {draft.host}:{draft.port}
                    </dd>
                    <dt>Database</dt>
                    <dd>{draft.database.trim()}</dd>
                    <dt>Table scope</dt>
                    <dd>
                      {tableList.length
                        ? `${tableList.length} selected table${tableList.length === 1 ? "" : "s"} in ${draft.schema}: ${tableList.join(", ")} (sampled)`
                        : `All tables in ${draft.schema} (sampled)`}
                    </dd>
                  </>
                ) : null}
                {isCloudKind(kind) && (
                  <>
                    <dt>Service endpoint</dt>
                    <dd>
                      <code>
                        {kind === "s3"
                          ? draft.endpointUrl.trim()
                          : draft.accountUrl.trim()}
                      </code>
                    </dd>
                    <dt>
                      {kind === "s3"
                        ? "Bucket"
                        : kind === "azure_blob"
                          ? "Container"
                          : "Table"}
                    </dt>
                    <dd>
                      {kind === "s3"
                        ? draft.bucket.trim()
                        : kind === "azure_blob"
                          ? draft.container.trim()
                          : draft.table.trim()}
                    </dd>
                    {kind === "s3" && (
                      <>
                        <dt>Region</dt>
                        <dd>{draft.region.trim()}</dd>
                      </>
                    )}
                    <dt>Discovery scope</dt>
                    <dd>
                      {kind === "azure_table"
                        ? `${draft.partitionKey ? `Exact partition: ${draft.partitionKey}` : "All partitions in this table"} (sampled, up to 1,000 entities)`
                        : draft.prefix
                          ? `Objects starting with “${draft.prefix}”`
                          : `All objects in this ${kind === "s3" ? "bucket" : "container"}`}
                    </dd>
                    <dt>Authentication</dt>
                    <dd>
                      {kind === "s3"
                        ? draft.authMode === "iam_role"
                          ? "Scanner’s EC2 instance role"
                          : "Dedicated access key"
                        : "Read-only SAS token"}
                    </dd>
                    {(kind !== "s3" || draft.authMode === "access_key") && (
                      <>
                        <dt>
                          {kind === "s3" ? "Access credentials" : "SAS token"}
                        </dt>
                        <dd aria-label="Credentials entered">
                          •••••••• <span className="muted">Entered</span>
                        </dd>
                      </>
                    )}
                  </>
                )}
                {remote && (
                  <>
                    <dt>Read-only account</dt>
                    <dd>
                      {draft.domain && kind === "smb"
                        ? `${draft.domain}\\`
                        : ""}
                      {draft.username}
                    </dd>
                    <dt>Password</dt>
                    <dd aria-label="Password entered">
                      •••••••• <span className="muted">Entered</span>
                    </dd>
                  </>
                )}
              </dl>
              <div className="wizard-check-summary">
                <Icon name="shield" size={20} />
                <div>
                  <strong>What happens when you connect</strong>
                  <p>
                    {isDatabaseKind(kind)
                      ? "We check encrypted access, read-only database permissions, and query cancellation."
                      : kind === "smb"
                        ? "We check encrypted access to the shared folder using this account."
                        : isCloudKind(kind)
                          ? "We check HTTPS access to the selected resource using read and list operations. Your administrator must separately confirm that these credentials cannot change source data."
                          : "We check that the scanner can access this approved location."}{" "}
                    The source is added only if the check passes. This does not
                    start a scan or validate production workload limits.
                  </p>
                </div>
              </div>
              {connectError && (
                <div className="wizard-connect-error" role="alert">
                  <strong>Connection could not be completed</strong>
                  <p>{connectError}</p>
                  <p>
                    Go back to check the location and account details, or ask
                    hospital IT to confirm access. If the connection was
                    interrupted, check the source inventory before retrying.
                  </p>
                </div>
              )}
              {busy && (
                <div className="wizard-connecting" role="status">
                  <span className="spinner" />
                  <div>
                    <strong>Checking the connection…</strong>
                    <p>
                      Please keep this window open. We’ll add the source when
                      the check passes.
                    </p>
                  </div>
                </div>
              )}
            </>
          )}
          <div className="wizard-actions">
            <button
              className="button"
              type="button"
              disabled={busy}
              onClick={
                step === 1
                  ? closeWizard
                  : () => {
                      setConnectError("");
                      setStep((value) => value - 1);
                    }
              }
            >
              {step === 1 ? "Cancel" : "Back"}
            </button>
            <button
              className="button primary"
              type="submit"
              disabled={busy || !kind}
            >
              {busy
                ? "Connecting…"
                : step === 3
                  ? "Connect source"
                  : "Continue"}
              {!busy && <Icon name="arrow" size={16} />}
            </button>
          </div>
        </form>
      )}
    </Modal>
  );
}

function SourceSettings({
  source,
  onClose,
  onSaved,
}: {
  source: Source;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [error, setError] = useState(""),
    [busy, setBusy] = useState(false);
  const [fullScan, setFullScan] = useState(
    source.config?.full_scan_allowed === true,
  );
  const database = isDatabaseKind(source.kind) || source.kind === "sqlite";
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError("");
    const form = new FormData(event.currentTarget);
    try {
      await api(
        `/sources/${source.id}`,
        json("PATCH", {
          enabled: form.get("enabled") === "on",
          ...(database
            ? {
                full_scan_allowed: fullScan,
                workload_validation_note:
                  form.get("workload_validation_note") || "",
              }
            : {}),
        }),
      );
      onSaved();
      onClose();
    } catch (error) {
      setError((error as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <Modal title={`Configure ${source.name}`} onClose={onClose}>
      <form className="modal-body" onSubmit={submit}>
        {error && <Notice kind="error">{error}</Notice>}
        <label className="checkbox-label">
          <input
            type="checkbox"
            name="enabled"
            defaultChecked={source.enabled}
          />
          <span>Enable this source for new scans.</span>
        </label>
        {source.kind === "azure_table" && (
          <p className="fine-print">
            Azure Table scans are limited to 1,000 entities in the registered
            table and partition scope. Full scans are unavailable.
          </p>
        )}
        {database && (
          <>
            <label className="checkbox-label">
              <input
                type="checkbox"
                checked={fullScan}
                onChange={(event) => setFullScan(event.target.checked)}
              />
              <span>
                Allow full table scans after hospital workload validation.
              </span>
            </label>
            <label>
              Workload validation evidence
              <textarea
                name="workload_validation_note"
                rows={4}
                maxLength={1000}
                required={fullScan}
                defaultValue={String(
                  source.config?.workload_validation_note || "",
                )}
                placeholder="Record the approved scope, workload limits, scan window, and validation reference. Do not enter patient data."
              />
            </label>
            <Notice>
              Full scanning can increase production load. Enable it only after
              the hospital has validated the approved scope and operating
              limits.
            </Notice>
          </>
        )}
        <div className="form-actions">
          <button type="button" className="button" onClick={onClose}>
            Cancel
          </button>
          <button className="button primary" disabled={busy}>
            {busy ? "Saving…" : "Save configuration"}
          </button>
        </div>
      </form>
    </Modal>
  );
}
function SourceCredentials({
  source,
  onClose,
  onSaved,
}: {
  source: Source;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [draft, setDraft] = useState(newCredentialDraft);
  const [clearSessionToken, setClearSessionToken] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [saved, setSaved] = useState(false);
  const inFlight = useRef(false);
  const inputs = credentialInputs(source);
  const hasSessionToken = inputs.some(
    (input) => input.field === "session_token",
  );
  function close() {
    if (inFlight.current) return;
    setDraft(newCredentialDraft());
    setClearSessionToken(false);
    onClose();
  }
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (inFlight.current) return;
    setError("");
    let payload;
    try {
      payload = credentialUpdate(source, draft, clearSessionToken);
    } catch (failure) {
      setError((failure as Error).message);
      return;
    }
    inFlight.current = true;
    setBusy(true);
    try {
      await api<ConnectedSource>(
        `/sources/${source.id}/credentials`,
        json("POST", payload),
      );
      setDraft(newCredentialDraft());
      setClearSessionToken(false);
      setSaved(true);
      onSaved();
    } catch (failure) {
      setError((failure as Error).message);
    } finally {
      inFlight.current = false;
      setBusy(false);
    }
  }
  return (
    <Modal title="Update credentials" onClose={close} closeDisabled={busy}>
      {saved ? (
        <div className="modal-body wizard-success">
          <span className="success-mark">
            <Icon name="check" size={30} />
          </span>
          <h3>Credentials updated</h3>
          <p>
            The connection to <strong>{source.name}</strong> passed its check.
            Replacement credentials are saved in the encrypted local catalog.
          </p>
          <div className="form-actions">
            <button className="button primary" onClick={close}>
              Done
            </button>
          </div>
        </div>
      ) : (
        <form className="modal-body" onSubmit={submit} aria-busy={busy}>
          <div>
            <h3>{source.name}</h3>
            <p className="fine-print">
              Enter only the fields you want to replace. Leave other fields
              blank to keep their saved values. Use dedicated read-only access.
            </p>
          </div>
          {error && <Notice kind="error">{error}</Notice>}
          {inputs.map((input) => (
            <label key={input.field} htmlFor={`credential-${input.field}`}>
              {input.label}
              <input
                id={`credential-${input.field}`}
                name={input.field}
                type={input.secret ? "password" : "text"}
                value={draft[input.field]}
                autoComplete={input.secret ? "new-password" : "off"}
                spellCheck={false}
                maxLength={16384}
                placeholder="Leave blank to keep saved value"
                disabled={
                  busy || (input.field === "session_token" && clearSessionToken)
                }
                onChange={(event) => {
                  setDraft((previous) => ({
                    ...previous,
                    [input.field]: event.target.value,
                  }));
                  setError("");
                }}
              />
            </label>
          ))}
          {hasSessionToken && (
            <label className="checkbox-label">
              <input
                type="checkbox"
                checked={clearSessionToken}
                disabled={busy}
                onChange={(event) => {
                  setClearSessionToken(event.target.checked);
                  setDraft((previous) => ({ ...previous, session_token: "" }));
                  setError("");
                }}
              />
              <span>Clear the saved session token</span>
            </label>
          )}
          <p className="fine-print">
            The source must have no active scan. We check the replacement
            credentials before saving them; the source scope and scan approvals
            are preserved.
          </p>
          <div className="form-actions">
            <button
              className="button"
              type="button"
              disabled={busy}
              onClick={close}
            >
              Cancel
            </button>
            <button className="button primary" type="submit" disabled={busy}>
              {busy ? "Checking…" : "Check and save"}
              {!busy && <Icon name="check" size={16} />}
            </button>
          </div>
        </form>
      )}
    </Modal>
  );
}

function SourcesPage({
  refresh,
  reload,
  user,
  startScan,
}: {
  refresh: number;
  reload: () => void;
  user: User;
  startScan: (source?: string) => void;
}) {
  const { data, loading, error } = useData<Source[]>("/sources", [], refresh);
  const [adding, setAdding] = useState(false),
    [managing, setManaging] = useState<Source | null>(null),
    [updatingCredentials, setUpdatingCredentials] = useState<Source | null>(
      null,
    ),
    [testing, setTesting] = useState(""),
    [notice, setNotice] = useState<{
      text: string;
      kind: "success" | "error" | "info";
    } | null>(null);
  async function test(source: Source) {
    setTesting(source.id);
    setNotice(null);
    try {
      const result = await api<Record<string, unknown>>(
        `/sources/${source.id}/test`,
        json("POST"),
      );
      setNotice({
        kind: result.ok === false ? "error" : "success",
        text:
          typeof result.message === "string"
            ? result.message
            : `${source.name}: ${result.ok === false ? "connection check failed. Check the location and account details." : "connection check passed."}${typeof result.note === "string" ? ` ${result.note}` : ""}`,
      });
    } catch (error) {
      setNotice({ kind: "error", text: (error as Error).message });
    } finally {
      setTesting("");
      reload();
    }
  }
  return (
    <>
      {notice && <Notice kind={notice.kind}>{notice.text}</Notice>}
      {error && <Notice kind="error">{error}</Notice>}
      <Panel
        title="Source inventory"
        subtitle="Approved databases, file shares, and cloud storage"
        action={
          user.role === "admin" && (
            <button className="button primary" onClick={() => setAdding(true)}>
              <Icon name="plus" size={17} />
              Register source
            </button>
          )
        }
      >
        {loading && !data.length ? (
          <Loading />
        ) : data.length ? (
          <div className="source-list">
            {data.map((source) => (
              <article className="source-card" key={source.id}>
                <span className="source-icon">
                  <Icon
                    name={isTabularKind(source.kind) ? "database" : "sources"}
                    size={23}
                  />
                </span>
                <div className="source-content">
                  <div className="source-title">
                    <h3>{source.name}</h3>
                    <Badge>{sourceLabels[source.kind]}</Badge>
                    {!source.enabled && <Badge tone="amber">Disabled</Badge>}
                  </div>
                  <p>
                    {source.config && Object.keys(source.config).length
                      ? String(
                          source.config.root ||
                            source.config.path ||
                            source.config.server ||
                            source.config.host ||
                            source.config.endpoint_url ||
                            source.config.account_url ||
                            "Source configuration",
                        )
                      : "Connection details restricted to administrators"}
                  </p>
                  <div className="source-foot">
                    <Badge tone={source.safety_validated ? "green" : "amber"}>
                      {source.safety_validated
                        ? "Connection checked"
                        : "Connection check needed"}
                    </Badge>
                    <span>Registered {date(source.created_at)}</span>
                  </div>
                </div>
                {user.role !== "reviewer" && (
                  <div className="source-actions">
                    {user.role === "admin" && (
                      <button
                        className="icon-button"
                        aria-label={`Configure ${source.name}`}
                        onClick={() => setManaging(source)}
                      >
                        <Icon name="settings" size={17} />
                      </button>
                    )}
                    {user.role === "admin" &&
                      credentialInputs(source).length > 0 && (
                        <button
                          className="button small"
                          onClick={() => setUpdatingCredentials(source)}
                        >
                          Update credentials
                        </button>
                      )}
                    <button
                      className="button small"
                      disabled={testing === source.id}
                      onClick={() => test(source)}
                    >
                      {testing === source.id ? "Checking…" : "Test connection"}
                    </button>
                    <button
                      className="button small primary"
                      disabled={!source.enabled}
                      onClick={() => startScan(source.id)}
                    >
                      Start scan
                    </button>
                  </div>
                )}
              </article>
            ))}
          </div>
        ) : (
          <Empty title="No sources registered" icon="sources">
            {user.role === "admin"
              ? "Register an approved database, file share, or cloud resource to begin."
              : "An administrator can register sources for this workspace."}
          </Empty>
        )}
      </Panel>
      <Notice>
        Access uses dedicated read-only credentials. A successful connection
        test confirms reachability; it does not certify load impact or detection
        accuracy.
      </Notice>
      {adding && (
        <SourceForm onClose={() => setAdding(false)} onSaved={reload} />
      )}{" "}
      {updatingCredentials && (
        <SourceCredentials
          source={updatingCredentials}
          onClose={() => setUpdatingCredentials(null)}
          onSaved={reload}
        />
      )}
      {managing && (
        <SourceSettings
          source={managing}
          onClose={() => setManaging(null)}
          onSaved={reload}
        />
      )}
    </>
  );
}

function StartScan({
  sourceId,
  sources,
  onClose,
  onStarted,
}: {
  sourceId: string;
  sources: Source[];
  onClose: () => void;
  onStarted: (scan: Scan) => void;
}) {
  const [selected, setSelected] = useState(
      sourceId || sources.find((source) => source.enabled)?.id || "",
    ),
    [fullScan, setFullScan] = useState(false),
    [captureEvidence, setCaptureEvidence] = useState(false),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false);
  const source = sources.find((source) => source.id === selected);
  const database = source && isTabularKind(source.kind);
  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const scan = await api<Scan>(
        "/scans",
        json("POST", {
          source_id: selected,
          options: { full_scan: fullScan, capture_evidence: captureEvidence },
        }),
      );
      onStarted(scan);
      onClose();
    } catch (error) {
      setError((error as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <Modal title="Start discovery scan" onClose={onClose}>
      <form className="modal-body" onSubmit={submit}>
        {error && <Notice kind="error">{error}</Notice>}
        <label>
          Approved source
          <select
            value={selected}
            onChange={(event) => {
              setSelected(event.target.value);
              setFullScan(false);
              setCaptureEvidence(false);
            }}
            required
          >
            <option value="" disabled>
              Select a source
            </option>
            {sources
              .filter((source) => source.enabled)
              .map((source) => (
                <option key={source.id} value={source.id}>
                  {source.name} · {sourceLabels[source.kind]}
                </option>
              ))}
          </select>
        </label>
        {source &&
          (isDatabaseKind(source.kind) || source.kind === "sqlite") &&
          source.config?.full_scan_allowed === true && (
            <label className="checkbox-label">
              <input
                type="checkbox"
                checked={fullScan}
                onChange={(event) => setFullScan(event.target.checked)}
              />
              <span>
                Read complete tables in this source. Hospital workload
                validation has been recorded.
              </span>
            </label>
          )}
        <div className="evidence-option">
          <label className="checkbox-label">
            <input
              type="checkbox"
              checked={captureEvidence}
              onChange={(event) => setCaptureEvidence(event.target.checked)}
              aria-describedby="capture-evidence-description"
            />
            <span>Capture matching values and excerpts</span>
          </label>
          <p id="capture-evidence-description" className="fine-print">
            Save a bounded set of actual matches with this scan, encrypted in
            the local catalog under the scan retention policy. Administrators
            and reviewers can reveal them on demand; each access is audited.
            Standard CSV/JSON exports do not include these values.
          </p>
        </div>
        <div className="scan-config">
          {database ? (
            <>
              <div>
                <span>
                  {source?.kind === "azure_table"
                    ? "Table mode"
                    : "Database mode"}
                </span>
                <strong>
                  {source?.kind === "azure_table"
                    ? "Sampled · up to 1,000 entities in the selected table scope"
                    : fullScan
                      ? "Complete tables · validated workload"
                      : "Sampled · up to 1,000 rows / table"}
                </strong>
              </div>
              <div>
                <span>
                  {source?.kind === "azure_table"
                    ? "Table reads"
                    : "Database batches"}
                </span>
                <strong>
                  {source?.kind === "azure_table"
                    ? "Paged reads · full scans unavailable"
                    : "100 rows · one query at a time"}
                </strong>
              </div>
            </>
          ) : (
            <div>
              <span>File mode</span>
              <strong>Approved scope · bounded extraction</strong>
            </div>
          )}
          <div>
            <span>Data handling</span>
            <strong>Read-only · local processing</strong>
          </div>
        </div>
        {source && !source.safety_validated && (
          <Notice>
            This source needs a connection check before production scanning.
          </Notice>
        )}
        <p className="fine-print">
          Coverage gaps, parser failures, and truncated content will be
          recorded. No-match results apply only to content actually examined.
        </p>
        <div className="form-actions">
          <button className="button" type="button" onClick={onClose}>
            Cancel
          </button>
          <button className="button primary" disabled={busy || !selected}>
            {busy ? "Starting…" : "Start scan"}
            <Icon name="arrow" size={17} />
          </button>
        </div>
      </form>
    </Modal>
  );
}
function ScanDetail({
  scan,
  refresh,
  onBack,
  action,
  onFindings,
  user,
}: {
  scan: Scan;
  refresh: number;
  onBack: () => void;
  action: (scan: Scan, action: string) => Promise<void>;
  onFindings: (scan: Scan) => void;
  user: User;
}) {
  const {
    data: objects,
    loading,
    error,
  } = useData<ScanObject[]>(`/scans/${scan.id}/objects`, [], refresh);
  const [busy, setBusy] = useState("");
  async function control(command: string) {
    setBusy(command);
    try {
      await action(scan, command);
    } finally {
      setBusy("");
    }
  }
  return (
    <>
      <button className="text-button back-button" onClick={onBack}>
        ← All scans
      </button>
      <Panel
        title={scan.source_name || scan.source_id}
        subtitle={`Scan ${scan.id}`}
        action={<Status value={scan.status} />}
      >
        <div className="scan-detail-body">
          <div className="detail-meta">
            <div>
              <span>Started</span>
              <strong>{date(scan.started_at)}</strong>
            </div>
            <div>
              <span>Finished</span>
              <strong>{date(scan.finished_at)}</strong>
            </div>
            <div>
              <span>Detector version</span>
              <strong className="mono">
                {scan.detector_version || "Pending"}
              </strong>
            </div>
          </div>
          <p className="fine-print scan-evidence-status">
            Matching-value capture:{" "}
            {scan.options?.capture_evidence ? "enabled" : "not enabled"} for
            this scan.
            {scan.options?.capture_evidence &&
              " Reveal available matches from finding details."}
          </p>
          {scan.error && <Notice kind="error">{scan.error}</Notice>}
          <Coverage coverage={scan.coverage || {}} />
          <div className="scan-actions">
            <button className="button primary" onClick={() => onFindings(scan)}>
              Review {number(scan.finding_count)} findings
              <Icon name="arrow" size={17} />
            </button>
            <a
              className="button"
              href={`/api/scans/${scan.id}/export?format=csv`}
            >
              <Icon name="download" size={16} />
              CSV
            </a>
            <a
              className="button"
              href={`/api/scans/${scan.id}/export?format=json`}
            >
              <Icon name="download" size={16} />
              JSON
            </a>
            {user.role !== "reviewer" && (
              <div className="scan-control">
                {active(scan) && (
                  <button
                    className="button"
                    disabled={!!busy}
                    onClick={() => control("pause")}
                  >
                    {busy === "pause" ? "Pausing…" : "Pause"}
                  </button>
                )}
                {["paused", "interrupted"].includes(scan.status) && (
                  <button
                    className="button"
                    disabled={!!busy}
                    onClick={() => control("resume")}
                  >
                    {busy === "resume" ? "Resuming…" : "Resume"}
                  </button>
                )}
                {["queued", "running", "paused", "interrupted"].includes(
                  scan.status,
                ) && (
                  <button
                    className="button danger"
                    disabled={!!busy}
                    onClick={() => control("cancel")}
                  >
                    {busy === "cancel" ? "Cancelling…" : "Cancel scan"}
                  </button>
                )}
              </div>
            )}
          </div>
        </div>
      </Panel>
      <Panel
        title="Object-level coverage"
        subtitle="A completed scan may contain unreadable or only partially examined objects"
      >
        {error ? (
          <Notice kind="error">{error}</Notice>
        ) : loading && !objects.length ? (
          <Loading />
        ) : objects.length ? (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Location</th>
                  <th>Coverage</th>
                  <th>Examined</th>
                  <th>Reason / limitations</th>
                </tr>
              </thead>
              <tbody>
                {objects.map((object) => (
                  <tr key={object.id}>
                    <td className="location-cell">{object.location}</td>
                    <td>
                      <Status value={object.status} />
                    </td>
                    <td className="nowrap">
                      {number(object.examined)} {object.unit}
                    </td>
                    <td className="reason-cell">
                      {object.reason || "—"}
                      <OcrCoverageDetails object={object} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty title="No objects recorded yet">
            Object coverage appears as the scanner progresses.
          </Empty>
        )}
      </Panel>
    </>
  );
}
function OcrCoverageDetails({ object }: { object: ScanObject }) {
  const coverage = ocrCoverage(object.metadata);
  if (!coverage) return null;
  if (!coverage.valid) return <p className="fine-print">OCR accounting could not be read. Coverage remains unverified.</p>;
  const noun = object.unit === "frames" ? "frame" : "page";
  return (
    <details className="ocr-coverage">
      <summary>OCR details · {number(coverage.completed)} / {coverage.total === null ? "unknown" : number(coverage.total)} {noun}s completed</summary>
      <div className="ocr-coverage-body">
        {!coverage.complete && <p>Processing is incomplete or could not be verified.</p>}
        {!!coverage.omitted && <p>{number(coverage.omitted)} original {noun}{coverage.omitted === 1 ? " was" : "s were"} not processed.</p>}
        {coverage.units.length > 0 && <div className="table-scroll"><table aria-label={`OCR processing by ${noun}`}>
          <thead><tr><th>{human(noun)}</th><th>Rendered</th><th>English OCR</th><th>Text</th></tr></thead>
          <tbody>{coverage.units.map(unit => <tr key={unit.ordinal}>
            <td>{unit.ordinal}</td><td>{human(unit.renderStatus)}</td><td>{human(unit.ocrStatus)}</td>
            <td>{unit.truncated ? "Truncated" : unit.characters === null ? "—" : `${number(unit.characters)} characters`}</td>
          </tr>)}</tbody>
        </table></div>}
        {coverage.metadataUninspected && <p>Nonvisual metadata was not inspected.</p>}
        {coverage.ancillaryUnverified && <p>Embedded content and annotation coverage remains unverified.</p>}
        <p className="fine-print">Processing completion does not verify legibility or detection accuracy. Empty OCR output can still be a completed attempt.</p>
      </div>
    </details>
  );
}

function ScansPage({
  refresh,
  reload,
  user,
  selected,
  select,
  startScan,
  onFindings,
}: {
  refresh: number;
  reload: () => void;
  user: User;
  selected: string;
  select: (id: string) => void;
  startScan: () => void;
  onFindings: (scan: Scan) => void;
}) {
  const { data, loading, error } = useData<Scan[]>("/scans", [], refresh),
    [actionError, setActionError] = useState("");
  const scan = data.find((scan) => scan.id === selected);
  async function action(scan: Scan, command: string) {
    setActionError("");
    try {
      await api(`/scans/${scan.id}/${command}`, json("POST"));
      reload();
    } catch (error) {
      setActionError((error as Error).message);
    }
  }
  return (
    <>
      {error && <Notice kind="error">{error}</Notice>}
      {actionError && <Notice kind="error">{actionError}</Notice>}
      {scan ? (
        <ScanDetail
          scan={scan}
          refresh={refresh}
          onBack={() => select("")}
          action={action}
          onFindings={onFindings}
          user={user}
        />
      ) : (
        <Panel
          title="Discovery scans"
          subtitle="Track progress, inspect coverage, and export results"
          action={
            user.role !== "reviewer" && (
              <button className="button primary" onClick={() => startScan()}>
                <Icon name="plus" size={17} />
                Start scan
              </button>
            )
          }
        >
          {loading && !data.length ? (
            <Loading />
          ) : data.length ? (
            <ScanTable scans={data} onSelect={(scan) => select(scan.id)} />
          ) : (
            <Empty title="No scans yet" icon="scans">
              Run a discovery scan against an approved source to build your
              coverage baseline.
            </Empty>
          )}
        </Panel>
      )}
    </>
  );
}

function MatchingEvidence({
  findingId,
  user,
}: {
  findingId: string;
  user: User;
}) {
  const [evidence, setEvidence] = useState<FindingEvidence | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const pending = useRef<AbortController | null>(null);
  const allowed = user.role === "admin" || user.role === "reviewer";

  useEffect(() => () => pending.current?.abort(), []);

  function hide() {
    pending.current?.abort();
    pending.current = null;
    setEvidence(null);
    setError("");
    setLoading(false);
  }

  async function reveal() {
    if (!allowed || loading) return;
    const request = new AbortController();
    pending.current = request;
    setLoading(true);
    setError("");
    setEvidence(null);
    try {
      const result = await api<FindingEvidence>(
        `/findings/${encodeURIComponent(findingId)}/evidence`,
        { signal: request.signal, cache: "no-store" },
      );
      if (!request.signal.aborted && pending.current === request)
        setEvidence(result);
    } catch (error) {
      if (!request.signal.aborted && pending.current === request)
        setError((error as Error).message);
    } finally {
      if (pending.current === request) {
        pending.current = null;
        setLoading(false);
      }
    }
  }

  return (
    <section
      className="matching-evidence"
      aria-label="Matching values and excerpts"
    >
      <div className="evidence-heading">
        <div>
          <h3>Matching values and excerpts</h3>
          <p className="fine-print">
            Actual source content, when captured for this scan.
          </p>
        </div>
        <Icon name="lock" size={18} />
      </div>
      {!allowed ? (
        <p className="fine-print">
          Only administrators and reviewers can reveal matching values.
          Operators can review classification details and coverage.
        </p>
      ) : (
        <>
          <div className="evidence-controls">
            {!evidence && !loading && (
              <button type="button" className="button" onClick={reveal}>
                <Icon name="lock" size={15} />
                {error ? "Retry reveal" : "Reveal matching values"}
              </button>
            )}
            {(evidence || loading) && (
              <button type="button" className="button" onClick={hide}>
                {loading ? "Cancel reveal" : "Hide matching values"}
              </button>
            )}
            <span className="fine-print">
              Revealing is recorded in audit history.
            </span>
          </div>
          {loading && (
            <div className="evidence-loading" role="status">
              <span className="spinner" />
              Loading captured evidence…
            </div>
          )}
          {error && <Notice kind="error">{error}</Notice>}
          {evidence && (
            <div aria-live="polite" className="evidence-content">
              {!evidence.captured ? (
                <p className="fine-print">
                  Matching values were not captured for this scan. Start a new
                  scan with “Capture matching values and excerpts” enabled to
                  collect them.
                </p>
              ) : !evidence.available || evidence.examples.length === 0 ? (
                <p className="fine-print">
                  {evidence.notice ||
                    "No exact matching values were retained for this finding. Schema or context classifications may not have a matching text span."}
                </p>
              ) : (
                <ol className="evidence-examples">
                  {evidence.examples.map((example, index) => (
                    <li key={index}>
                      <div className="evidence-label">Match {index + 1}</div>
                      <pre className="evidence-value">{example.value}</pre>
                      {example.excerpt && (
                        <>
                          <div className="evidence-label">Source excerpt</div>
                          <p className="evidence-excerpt">{example.excerpt}</p>
                        </>
                      )}
                      {(example.segment ||
                        (typeof example.start === "number" &&
                          typeof example.end === "number")) && (
                        <p className="evidence-position">
                          {example.segment && <span>{example.segment}</span>}
                          {typeof example.start === "number" &&
                            typeof example.end === "number" && (
                              <span>
                                Text offsets {example.start}–{example.end}
                              </span>
                            )}
                        </p>
                      )}
                    </li>
                  ))}
                </ol>
              )}
              {evidence.captured &&
                evidence.available &&
                evidence.examples.length > 0 &&
                evidence.truncated && (
                  <p className="fine-print">
                    Only a bounded sample is retained. Additional matches or
                    excerpt content may be omitted.
                  </p>
                )}
              {evidence.captured &&
                evidence.available &&
                evidence.examples.length > 0 &&
                evidence.notice && (
                  <p className="fine-print">{evidence.notice}</p>
                )}
            </div>
          )}
        </>
      )}
    </section>
  );
}

function FindingsPage({
  refresh,
  reload,
  scanFilter,
  setScanFilter,
  user,
}: {
  refresh: number;
  reload: () => void;
  scanFilter: string;
  setScanFilter: (value: string) => void;
  user: User;
}) {
  const [review, setReview] = useState(""),
    [entity, setEntity] = useState(""),
    [search, setSearch] = useState(""),
    [selected, setSelected] = useState<Finding | null>(null),
    [busy, setBusy] = useState(false),
    [actionError, setActionError] = useState("");
  const query = new URLSearchParams();
  if (scanFilter) query.set("scan_id", scanFilter);
  if (review) query.set("review_status", review);
  if (entity) query.set("entity_type", entity);
  const { data, loading, error } = useData<Finding[]>(
      `/findings?${query}`,
      [],
      refresh,
    ),
    scans = useData<Scan[]>("/scans", [], refresh);
  const rows = data.filter((finding) =>
    `${finding.location} ${finding.entity_type} ${finding.classification}`
      .toLowerCase()
      .includes(search.toLowerCase()),
  );
  async function saveReview(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selected) return;
    const form = new FormData(event.currentTarget);
    setBusy(true);
    setActionError("");
    try {
      await api(
        `/findings/${selected.id}/review`,
        json("PATCH", { status: form.get("status"), note: form.get("note") }),
      );
      setSelected(null);
      reload();
    } catch (error) {
      setActionError((error as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <Notice>
        Findings identify potential sensitive data. Counts are detected matches,
        not unique patients. Captured matching values can be revealed in finding
        details by administrators and reviewers.
      </Notice>
      <Panel
        title="Findings register"
        subtitle="Review classifications and the evidence behind each result"
      >
        <div className="filters">
          <label className="search-field">
            <Icon name="search" size={18} />
            <input
              aria-label="Search locations or classifications"
              placeholder="Search location or classification…"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
            />
          </label>
          <select
            aria-label="Filter by scan"
            value={scanFilter}
            onChange={(event) => setScanFilter(event.target.value)}
          >
            <option value="">All scans</option>
            {scans.data.map((scan) => (
              <option key={scan.id} value={scan.id}>
                {scan.source_name || scan.source_id} · {scan.id.slice(0, 8)}
              </option>
            ))}
          </select>
          <select
            aria-label="Filter by review status"
            value={review}
            onChange={(event) => setReview(event.target.value)}
          >
            <option value="">All review states</option>
            <option value="needs_review">Needs review</option>
            <option value="confirmed">Confirmed</option>
            <option value="false_positive">False positive</option>
          </select>
          <input
            className="entity-filter"
            aria-label="Filter by exact entity type"
            placeholder="Entity type (exact)"
            value={entity}
            onChange={(event) => setEntity(event.target.value.toUpperCase())}
          />
        </div>
        {error && <Notice kind="error">{error}</Notice>}
        {loading ? (
          <Loading />
        ) : rows.length ? (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Finding / location</th>
                  <th>Classification</th>
                  <th>Confidence</th>
                  <th>Matches</th>
                  <th>Review</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {rows.map((finding) => (
                  <tr key={finding.id}>
                    <td>
                      <button
                        className="table-link"
                        onClick={() => {
                          setSelected(finding);
                          setActionError("");
                        }}
                      >
                        {human(finding.entity_type)}
                        <span className="subtext location-cell">
                          {finding.location}
                        </span>
                      </button>
                    </td>
                    <td>
                      <Badge
                        tone={
                          finding.classification
                            .toLowerCase()
                            .includes("health")
                            ? "purple"
                            : "blue"
                        }
                      >
                        {human(finding.classification)}
                      </Badge>
                    </td>
                    <td>
                      <div className="confidence">
                        <span>{Math.round(finding.confidence * 100)}%</span>
                        <div>
                          <i
                            style={{
                              width: `${Math.max(0, Math.min(100, finding.confidence * 100))}%`,
                            }}
                          />
                        </div>
                      </div>
                    </td>
                    <td>
                      <button
                        type="button"
                        className="text-button"
                        aria-label={`View ${number(finding.match_count)} matches for ${human(finding.entity_type)}`}
                        onClick={() => {
                          setSelected(finding);
                          setActionError("");
                        }}
                      >
                        {number(finding.match_count)}
                      </button>
                    </td>
                    <td>
                      <Status value={finding.review_status} />
                    </td>
                    <td>
                      <button
                        className="text-button"
                        onClick={() => {
                          setSelected(finding);
                          setActionError("");
                        }}
                      >
                        Review
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty
            title={
              search || review || entity || scanFilter
                ? "No findings match these filters"
                : "No findings recorded"
            }
            icon="findings"
          >
            Review object coverage before drawing conclusions about sensitive
            data.
          </Empty>
        )}
        <div className="table-footer">
          {number(rows.length)} finding records shown · Detector confidence is
          not measured accuracy.
        </div>
      </Panel>
      {selected && (
        <Modal title="Review finding" onClose={() => setSelected(null)}>
          <form className="modal-body" onSubmit={saveReview}>
            {actionError && <Notice kind="error">{actionError}</Notice>}
            <div className="finding-heading">
              <span className="source-icon">
                <Icon name="findings" />
              </span>
              <div>
                <span className="eyebrow">What was detected</span>
                <h3>{human(selected.entity_type)}</h3>
                <Badge tone="blue">{human(selected.classification)}</Badge>
              </div>
            </div>
            <dl className="finding-detail">
              <dt>Source</dt>
              <dd className="break-word">
                {selected.source_name || "Source not provided"}
              </dd>
              <dt>Location</dt>
              <dd className="break-word">{selected.location}</dd>
              <dt>Coverage</dt>
              <dd>
                <Status value={selected.coverage_status || "unknown"} />
              </dd>
              <dt>Segment</dt>
              <dd>{selected.segment || "—"}</dd>
              <dt>Detection reason</dt>
              <dd>{selected.reason}</dd>
              <dt>Matches / confidence</dt>
              <dd>
                {number(selected.match_count)} matches ·{" "}
                {Math.round(selected.confidence * 100)}% detector confidence
              </dd>
              <dt>Detector version</dt>
              <dd className="mono">{selected.detector_version}</dd>
            </dl>
            <MatchingEvidence
              key={`${selected.id}:${user.role}`}
              findingId={selected.id}
              user={user}
            />
            <label>
              Review decision
              <select name="status" defaultValue={selected.review_status}>
                <option value="needs_review">Needs review</option>
                <option value="confirmed">Confirmed</option>
                <option value="false_positive">False positive</option>
              </select>
            </label>
            <label>
              Review note
              <textarea
                name="note"
                rows={3}
                maxLength={2000}
                placeholder="Record your rationale. Do not enter patient values."
                aria-describedby="review-note-help"
              />
            </label>
            <p className="fine-print field-help" id="review-note-help">
              Do not paste patient values here; review notes follow audit
              retention.
            </p>
            <div className="form-actions">
              <button
                type="button"
                className="button"
                onClick={() => setSelected(null)}
              >
                Close
              </button>
              <button className="button primary" disabled={busy}>
                {busy ? "Saving…" : "Save review"}
              </button>
            </div>
          </form>
        </Modal>
      )}
    </>
  );
}

function FindingDeltaRows({ deltas }: { deltas: FindingDelta[] }) {
  return (
    <dl className="finding-detail">
      {deltas.map((delta) => (
        <React.Fragment key={findingDeltaKey(delta)}>
          <dt>{human(delta.entity_type)}</dt>
          <dd>
            <Status value={delta.change} />
            <p>
              <strong>
                {number(delta.before_count)} → {number(delta.after_count)}{" "}
                matches
              </strong>{" "}
              · {human(delta.classification)}
            </p>
            <span className="fine-print">
              {human(delta.reason)} · {delta.segment || "Document"}
            </span>
          </dd>
        </React.Fragment>
      ))}
    </dl>
  );
}

function ObjectFindingChanges({
  object,
  comparison,
}: {
  object: ObjectChange;
  comparison: Comparison;
}) {
  const view = findingComparisonView(object, comparison);
  if (!view.comparable)
    return (
      <p className="fine-print">
        <Badge tone="amber">Finding changes unknown</Badge> {view.reason}
      </p>
    );
  if (!view.changed.length && !view.unchanged.length)
    return (
      <p className="fine-print">
        No detection groups were reported for this comparison. This does not
        establish absence of sensitive data.
      </p>
    );
  return (
    <div>
      {view.changed.length > 0 && (
        <>
          <span className="eyebrow">Changes in detected types</span>
          <p className="fine-print">
            Baseline → current recognizer matches. “No longer observed” is not
            proof of removal.
          </p>
          <FindingDeltaRows deltas={view.changed} />
        </>
      )}
      {view.unchanged.length > 0 && (
        <details className="wizard-advanced">
          <summary>
            {number(view.unchanged.length)} unchanged detection{" "}
            {view.unchanged.length === 1 ? "group" : "groups"}
          </summary>
          <div className="advanced-fields">
            <FindingDeltaRows deltas={view.unchanged} />
          </div>
        </details>
      )}
    </div>
  );
}

function ComparePage({ refresh }: { refresh: number }) {
  const { data: scans, error } = useData<Scan[]>("/scans", [], refresh);
  const [baseline, setBaseline] = useState(""),
    [current, setCurrent] = useState(""),
    [result, setResult] = useState<Comparison | null>(null),
    [busy, setBusy] = useState(false),
    [compareError, setCompareError] = useState("");
  const baselineScan = scans.find((scan) => scan.id === baseline);
  const candidates = scans.filter(
    (scan) =>
      scan.id !== baseline &&
      (!baselineScan || scan.source_id === baselineScan.source_id),
  );
  async function compare(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setResult(null);
    setCompareError("");
    try {
      setResult(
        await api<Comparison>(
          `/compare?baseline=${encodeURIComponent(baseline)}&current=${encodeURIComponent(current)}`,
        ),
      );
    } catch (error) {
      setCompareError((error as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <Panel
        title="Compare successive scans"
        subtitle="Separate changes in findings from changes in visibility"
      >
        <form className="compare-form" onSubmit={compare}>
          <label>
            Baseline scan
            <select
              required
              value={baseline}
              onChange={(event) => {
                setBaseline(event.target.value);
                setCurrent("");
                setResult(null);
              }}
            >
              <option value="">Select baseline</option>
              {scans.map((scan) => (
                <option key={scan.id} value={scan.id}>
                  {scan.source_name || scan.source_id} ·{" "}
                  {date(scan.started_at || scan.created_at)} ·{" "}
                  {scan.id.slice(0, 8)}
                </option>
              ))}
            </select>
          </label>
          <span className="compare-arrow">
            <Icon name="arrow" />
          </span>
          <label>
            Current scan
            <select
              required
              value={current}
              onChange={(event) => {
                setCurrent(event.target.value);
                setResult(null);
              }}
              disabled={!baseline}
            >
              <option value="">Select comparison scan</option>
              {candidates.map((scan) => (
                <option key={scan.id} value={scan.id}>
                  {scan.source_name || scan.source_id} ·{" "}
                  {date(scan.started_at || scan.created_at)} ·{" "}
                  {scan.id.slice(0, 8)}
                </option>
              ))}
            </select>
          </label>
          <button
            className="button primary"
            disabled={busy || !baseline || !current}
          >
            {busy ? "Comparing…" : "Compare scans"}
          </button>
        </form>
      </Panel>
      {(error || compareError) && (
        <Notice kind="error">{error || compareError}</Notice>
      )}
      <Notice>
        Lost access or reduced coverage is a visibility gap. “No longer
        observed” is not proof of removal. Comparisons use scans of the same
        source. Finding counts are recognizer matches, never unique values or
        patients.
      </Notice>
      {result ? (
        <>
          {result.detector_changed && (
            <Notice>
              Detector versions changed between these scans. Differences may
              reflect detector changes and must be reviewed separately from
              source changes.
            </Notice>
          )}
          {result.options_changed && (
            <Notice>
              Scan policies changed between these runs. Finding changes are
              unknown where the observations are not comparable.
            </Notice>
          )}
          <div className="comparison-metrics">
            {Object.entries(result.summary || {}).map(([key, value]) => (
              <div className="comparison-metric" key={key}>
                <strong>{number(value)}</strong>
                <span className="fine-print">objects</span>
                <Status value={key} />
              </div>
            ))}
          </div>
          <Panel
            title="Comparison results"
            subtitle="Location coverage and changes in detected types"
          >
            {result.changes.length ? (
              <div className="table-scroll">
                <table>
                  <thead>
                    <tr>
                      <th>Location</th>
                      <th>Change</th>
                      <th>Reason</th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.changes.map((change, index) => (
                      <React.Fragment key={`${change.location}-${index}`}>
                        <tr>
                          <td className="location-cell">{change.location}</td>
                          <td>
                            <Status value={change.change} />
                          </td>
                          <td className="reason-cell">{change.reason}</td>
                        </tr>
                        <tr>
                          <td colSpan={3}>
                            <ObjectFindingChanges
                              object={change}
                              comparison={result}
                            />
                          </td>
                        </tr>
                      </React.Fragment>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <Empty title="No comparable objects">
                Check coverage and scan scope for both runs.
              </Empty>
            )}
          </Panel>
        </>
      ) : (
        <Panel
          title="Make changes explainable"
          subtitle="Choose two runs to inspect differences"
        >
          <Empty title="Build a repeatable baseline" icon="compare">
            New findings, changed detections, and lost coverage are reported
            separately.
          </Empty>
        </Panel>
      )}
    </>
  );
}

function CapabilityList({
  capabilities,
}: {
  capabilities: Record<string, unknown>;
}) {
  return (
    <div className="capability-list">
      {Object.entries(capabilities || {}).map(([key, value]) => (
        <div key={key}>
          <span>{human(key)}</span>
          {typeof value === "boolean" ? (
            <Badge tone={value ? "green" : "amber"}>
              {key === "accuracy_validated"
                ? value
                  ? "Validated"
                  : "Not validated"
                : value
                  ? "Available"
                  : "Unavailable"}
            </Badge>
          ) : (
            <span className="capability-value">
              {typeof value === "object"
                ? JSON.stringify(value)
                : String(value)}
            </span>
          )}
        </div>
      ))}
    </div>
  );
}
function SettingsPage({
  refresh,
  reload,
  user,
}: {
  refresh: number;
  reload: () => void;
  user: User;
}) {
  const { data, loading, error } = useData<Settings | null>(
    "/settings",
    null,
    refresh,
  );
  const [busy, setBusy] = useState(false),
    [message, setMessage] = useState(""),
    [saveError, setSaveError] = useState("");
  const audits = useData<Audit[]>(
    user.role === "admin" ? "/audit" : null,
    [],
    refresh,
  );
  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    setBusy(true);
    setSaveError("");
    setMessage("");
    try {
      await api(
        "/settings",
        json("PATCH", {
          retention_days: Number(form.get("retention_days")),
          audit_retention_days: Number(form.get("audit_retention_days")),
          retention_approved: form.get("retention_approved") === "on",
        }),
      );
      setMessage("Retention settings saved.");
      reload();
    } catch (error) {
      setSaveError((error as Error).message);
    } finally {
      setBusy(false);
    }
  }
  if (loading && !data) return <Loading />;
  if (error) return <Notice kind="error">{error}</Notice>;
  if (!data) return null;
  return (
    <>
      {message && <Notice kind="success">{message}</Notice>}
      {saveError && <Notice kind="error">{saveError}</Notice>}
      <div className="settings-grid">
        <Panel
          title="Runtime & capabilities"
          subtitle="Readiness reported by this installation"
        >
          <div className="settings-body">
            <div className="runtime-tags">
              <Badge tone="blue">{human(data.environment)}</Badge>
              <Badge
                tone={data.detector_mode?.includes("rule") ? "amber" : "green"}
              >
                {human(data.detector_mode)} detector
              </Badge>
            </div>
            <CapabilityList capabilities={data.capabilities} />
            <p className="fine-print">
              Available components do not establish validated accuracy.
              Hospital-specific acceptance testing is required.
            </p>
          </div>
        </Panel>
        <Panel
          title="Data retention"
          subtitle="Use hospital-approved retention periods"
        >
          <form
            className="settings-body"
            onSubmit={save}
            key={`${data.retention_days}-${data.audit_retention_days}-${data.retention_approved}`}
          >
            <div className="form-grid">
              <label>
                Findings & scans (days)
                <input
                  name="retention_days"
                  type="number"
                  min={1}
                  max={3650}
                  defaultValue={data.retention_days}
                  required
                  disabled={user.role !== "admin"}
                />
              </label>
              <label>
                Audit records (days)
                <input
                  name="audit_retention_days"
                  type="number"
                  min={1}
                  max={3650}
                  defaultValue={data.audit_retention_days}
                  required
                  disabled={user.role !== "admin"}
                />
              </label>
            </div>
            <label className="checkbox-label">
              <input
                name="retention_approved"
                type="checkbox"
                defaultChecked={data.retention_approved}
                disabled={user.role !== "admin"}
              />
              <span>The hospital has approved these retention settings.</span>
            </label>
            <Notice>
              Source locations and filenames can contain sensitive information.
              Restrict access to reports and encrypted backups.
            </Notice>
            {user.role === "admin" ? (
              <button className="button primary" disabled={busy}>
                {busy ? "Saving…" : "Save settings"}
              </button>
            ) : (
              <p className="fine-print">
                Administrators manage retention settings.
              </p>
            )}
          </form>
        </Panel>
      </div>
      {user.role === "admin" && (
        <Panel
          title="Audit trail"
          subtitle="Recent access and administrative actions"
        >
          {audits.error ? (
            <Notice kind="error">{audits.error}</Notice>
          ) : audits.loading && !audits.data.length ? (
            <Loading />
          ) : audits.data.length ? (
            <div className="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Actor</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {audits.data.map((audit, index) => (
                    <tr key={audit.id || index}>
                      <td className="nowrap">
                        {date(audit.at || audit.created_at || audit.timestamp)}
                      </td>
                      <td>{audit.username || audit.actor || "System"}</td>
                      <td>{human(audit.action)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <Empty title="No audit entries yet" icon="lock">
              Audited actions will appear here.
            </Empty>
          )}
        </Panel>
      )}
    </>
  );
}

const pageDescriptions: Record<Page, string> = {
  Overview: "Your sensitive data discovery workspace.",
  Sources: "Define where discovery is permitted to run.",
  Scans: "Understand every scan and its coverage.",
  Findings: "Review sensitive data classifications with context.",
  Compare: "See what changed between discovery runs.",
  Settings: "Manage local operation and retention.",
};
function App() {
  const [user, setUser] = useState<User | null>(null),
    [booting, setBooting] = useState(true),
    [page, setPage] = useState<Page>("Overview"),
    [refresh, setRefresh] = useState(0),
    [selectedScan, setSelectedScan] = useState(""),
    [findingScan, setFindingScan] = useState(""),
    [scanModal, setScanModal] = useState<string | null>(null),
    [sources, setSources] = useState<Source[]>([]),
    [appError, setAppError] = useState(""),
    [settings, setSettings] = useState<Settings | null>(null);
  const reload = useCallback(() => setRefresh((value) => value + 1), []);
  useEffect(() => {
    api<User>("/auth/me")
      .then(setUser)
      .catch(() => {})
      .finally(() => setBooting(false));
    const expire = () => {
      setUser(null);
      setAppError("Your session expired. Sign in again.");
    };
    window.addEventListener("session-expired", expire);
    return () => window.removeEventListener("session-expired", expire);
  }, []);
  useEffect(() => {
    if (!user) return;
    let live = true;
    api<Settings>("/settings")
      .then((value) => {
        if (live) setSettings(value);
      })
      .catch(() => {});
    return () => {
      live = false;
    };
  }, [user, refresh]);
  useEffect(() => {
    if (!user) return;
    let snapshot = "";
    const timer = window.setInterval(() => {
      api<Scan[]>("/scans")
        .then((scans) => {
          const next = JSON.stringify(scans);
          if (next !== snapshot) {
            snapshot = next;
            reload();
          }
        })
        .catch(() => {});
    }, 5000);
    return () => window.clearInterval(timer);
  }, [user, reload]);
  async function startScan(sourceId = "") {
    setAppError("");
    try {
      setSources(await api<Source[]>("/sources"));
      setScanModal(typeof sourceId === "string" ? sourceId : "");
    } catch (error) {
      setAppError((error as Error).message);
    }
  }
  async function logout() {
    try {
      await api("/auth/logout", json("POST"));
      setUser(null);
      setSettings(null);
      setPage("Overview");
    } catch (error) {
      setAppError((error as Error).message);
    }
  }
  function viewScan(scan: Scan) {
    setSelectedScan(scan.id);
    setPage("Scans");
  }
  function navigate(next: Page) {
    setPage(next);
    if (next === "Scans") setSelectedScan("");
    setAppError("");
  }
  if (booting)
    return (
      <div className="boot">
        <Icon name="shield" size={40} />
        <Loading />
      </div>
    );
  if (!user)
    return (
      <Login
        onLogin={(value) => {
          setUser(value);
          setAppError("");
          reload();
        }}
      />
    );
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-icon">
            <Icon name="shield" size={25} />
          </span>
          <div>
            Sentry<span>DISCOVERY</span>
          </div>
        </div>
        <div className="workspace-tag">
          <span className="status-dot" />
          <div>
            Hospital workspace<span>Local deployment</span>
          </div>
          <Icon name="lock" size={15} />
        </div>
        <span className="nav-label">WORKSPACE</span>
        <nav>
          {(
            [
              "Overview",
              "Sources",
              "Scans",
              "Findings",
              "Compare",
              "Settings",
            ] as Page[]
          ).map((item) => (
            <button
              key={item}
              className={`nav-item ${page === item ? "selected" : ""}`}
              onClick={() => navigate(item)}
              aria-current={page === item ? "page" : undefined}
              aria-label={item}
            >
              <Icon name={item.toLowerCase() as IconName} />
              <span>{item}</span>
              {page === item && <span className="nav-dot" />}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="local-card">
            <Icon name="lock" size={18} />
            <div>
              <strong>Inside your environment</strong>
              <p>Data stays hospital-local.</p>
            </div>
          </div>
          <div className="profile">
            <span className="avatar">
              {user.username.slice(0, 2).toUpperCase()}
            </span>
            <div>
              <strong>{user.username}</strong>
              <span>{human(user.role)}</span>
            </div>
            <button
              className="icon-button"
              onClick={logout}
              aria-label="Sign out"
              title="Sign out"
            >
              <Icon name="logout" size={18} />
            </button>
          </div>
        </div>
      </aside>
      <div className="main-shell">
        <header className="topbar">
          <div className="breadcrumb">
            Workspace <span>/</span> <strong>{page}</strong>
          </div>
          <div className="topbar-status">
            <span className="status-dot" />
            Hospital-local
            <span className="topbar-divider" />
            <Icon name="lock" size={14} />
            Read-only discovery
          </div>
        </header>
        <main className="main-content">
          <div className="page-heading">
            <div>
              <span className="eyebrow">DISCOVERY PILOT</span>
              <h1>{page === "Overview" ? "Discovery overview" : page}</h1>
              <p>{pageDescriptions[page]}</p>
            </div>
            <div className="heading-actions">
              <button className="button" onClick={reload}>
                <Icon name="refresh" size={16} />
                Refresh
              </button>
              {page === "Overview" && user.role !== "reviewer" && (
                <button className="button primary" onClick={() => startScan()}>
                  <Icon name="plus" size={17} />
                  Start scan
                </button>
              )}
            </div>
          </div>
          {appError && <Notice kind="error">{appError}</Notice>}
          {settings?.detector_mode?.includes("rule") && (
            <div className="mode-warning">
              <Icon name="alert" size={17} />
              <span>
                <strong>Rules-only detector.</strong> NLP is unavailable or
                disabled. Name detection and contextual coverage are limited;
                results are unvalidated.
              </span>
              <button onClick={() => navigate("Settings")}>
                View capabilities <Icon name="arrow" size={14} />
              </button>
            </div>
          )}
          {page === "Overview" && (
            <OverviewPage
              refresh={refresh}
              navigate={navigate}
              onScan={viewScan}
            />
          )}{" "}
          {page === "Sources" && (
            <SourcesPage
              refresh={refresh}
              reload={reload}
              user={user}
              startScan={startScan}
            />
          )}{" "}
          {page === "Scans" && (
            <ScansPage
              refresh={refresh}
              reload={reload}
              user={user}
              selected={selectedScan}
              select={setSelectedScan}
              startScan={() => startScan()}
              onFindings={(scan) => {
                setFindingScan(scan.id);
                setPage("Findings");
              }}
            />
          )}{" "}
          {page === "Findings" && (
            <FindingsPage
              refresh={refresh}
              reload={reload}
              scanFilter={findingScan}
              setScanFilter={setFindingScan}
              user={user}
            />
          )}{" "}
          {page === "Compare" && <ComparePage refresh={refresh} />}{" "}
          {page === "Settings" && (
            <SettingsPage refresh={refresh} reload={reload} user={user} />
          )}
          <footer className="footer">
            <span>
              Sentry Discovery <span className="footer-dot">·</span> Hospital
              pilot
            </span>
            <span>Coverage is explicit. Accuracy must be validated.</span>
          </footer>
        </main>
      </div>
      {scanModal !== null && (
        <StartScan
          sourceId={scanModal}
          sources={sources}
          onClose={() => setScanModal(null)}
          onStarted={(scan) => {
            reload();
            viewScan(scan);
          }}
        />
      )}
    </div>
  );
}

createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
