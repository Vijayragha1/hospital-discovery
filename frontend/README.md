# Sentry Discovery interface

React + TypeScript + Vite application for the hospital-local discovery API.
Fonts, icons, scripts, and styles require no external network requests. Icons are
inline SVG; typography uses installed system fonts. There are no cloud services,
analytics, embedded third-party resources, or bundled user credentials.

## Build and local development

```sh
npm ci
npm run build
```

The backend serves `dist/`. Production deployment needs the built assets, not an
internet connection or a Node development server. The repository lockfile pins
build dependencies.

```sh
# Run the backend on 127.0.0.1:8765 first.
npm run dev
```

The development server proxies `/api` to the backend. Authentication uses its
HttpOnly, same-origin session cookie. Mutations include
`X-Requested-With: SentryDiscovery`. Provision accounts with the backend CLI;
the interface does not assume default credentials.

## Included workflows

- Overview with counts, coverage states, recent scans, and detector limitations.
- Guided source registration: choose the source, enter connection details, then
  review and connect. Approved locations are supplied by the local API; connection
  checking and registration complete together. Enable/disable and recorded
  workload validation remain available for existing sources.
- Sampled or authorized full scans, pause/resume/cancel, per-object coverage, and
  CSV/JSON exports.
- Finding search, scan/entity/review filters, evidence detail, and audited review.
- Optional per-scan matching-value/excerpt capture, with encrypted local retention
  and an explicit audited reveal for administrators and reviewers. Operators
  cannot reveal evidence. Values are fetched only on demand and cleared when
  hidden or when the finding dialog closes; standard exports remain unchanged.
- Same-source comparison with object coverage states and finding-group deltas.
  Groups show detected type, classification, reason, segment and baseline/current
  recognizer-match counts. Counts are not unique values or patients. Incomplete
  reads, changed policy/runtime and unknown provenance show why finding changes
  cannot be attributed; comparison never loads captured values or excerpts.
- Runtime capabilities, retention approval, and administrator audit history.
- Role-sensitive controls, loading/error/empty states, mobile navigation,
  accessible form labels, and modal keyboard focus handling.

Authorization is always enforced by the API. Hiding a control is not a security
boundary. Reports and source locations may themselves contain sensitive data.

## Validation performed

The current comparison/runtime release passed 24 frontend helper tests and the
TypeScript production build. A browser check against the packaged application used
completed scans of an original synthetic text file. The comparison showed MRN as
no longer observed, UHID as newly observed and email recognizer matches changing
from 1 to 2, with explicit count/coverage wording. The 666-pixel browser panel had
no observed overflow. Backend packaged checks also verify that reduced coverage
suppresses attributed finding disappearance and that responses contain no raw
matching values/excerpts; see the [comparison report](../fixtures/evaluation/comparison-integration.json).
These are synthetic behavior checks, not hospital accuracy or coverage acceptance.

Earlier browser checks against the real local API
and disposable synthetic fixtures verified sign-in, inventory, source connection
checks, a second scan started from the interface, automatic final-state refresh,
object-level coverage, finding confirmation with an audit note, review filtering,
same-source comparison, runtime capabilities, retention state, and audit display.
Desktop layout was visually inspected; mobile layout was checked at 390 CSS
pixels, including a fix for table-header horizontal overflow. The application
document width matched the mobile viewport after the fix.

Source-setup helper regressions cover approved paths, UNC parsing, credential
isolation, defaults, and prevention of accidentally widening a table selection.
Run them with Node.js supporting native TypeScript stripping:

```sh
node --experimental-strip-types --test tests/source-setup.test.mjs
```

These checks establish interface behavior only. They do not validate detector
accuracy, OCR completeness, production load, or hospital-specific acceptance.

Evidence browser verification used synthetic fixtures: capture starts unchecked,
a scan launched from Scans completes with capture enabled, the finding detail
reveals an actual UHID/email and local excerpt, Hide clears it, and reopening
requires another reveal. Old scans show the capture-disabled rescan notice.
Long detector versions wrap inside the detail panel.

Connector browser verification: grouped database/file/cloud cards and narrow-panel layout; MySQL port 3306 and schema guidance; S3 review masks credentials; failed synthetic S3 connection shows fixed diagnostics and creates no source. The isolated updated preview runs at http://127.0.0.1:8766/.

Earlier credential-update verification: 18 frontend helper tests and the production build passed in that release. A temporary, disabled synthetic S3 source was used to inspect the form at a 666-pixel browser width. Fields started empty, an empty update showed an error, selecting explicit session-token removal disabled its input, and cancelling/reopening reset the form. The temporary source was removed. No real credential was entered or changed in this browser check; replacement success/failure, preservation of scope/history, and role restrictions are covered by 45 backend API tests.
