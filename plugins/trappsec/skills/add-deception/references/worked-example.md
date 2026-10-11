# Worked example: obvious vs. convincing

This example shows the reasoning, not names to reuse. Copying its paths, flags or fields into another app creates exactly the cross-app fingerprint the skill warns about.

## The app

"Ledgerly" is a fictional bookkeeping SaaS for accounting firms.
- **Backend:** Express, API under `/api/v3`.
- **Frontend:** React + Vite.

House-style dossier, from recon:

- **Routes:** `/api/v3/books/:bookId/<plural-noun>`. Actions are sub-resources (`/close-periods`). IDs are prefixed (`bk_`, `usr_`). JSON is camelCase.
- **Errors:** `{ "error": { "type": "...", "detail": "..." } }`. Captured from the running app:
  - anonymous: `401 {"error":{"type":"unauthenticated","detail":"Sign in to continue."}}`
  - forbidden: `403 {"error":{"type":"forbidden","detail":"You need the owner role for this."}}`
- **Auth:** cookie sessions via global middleware. Role checks run per route (`requireRole('owner')`). Each book has roles `owner | accountant | viewer`, loaded into `req.session.memberships`.
- **Frontend:**
  - an axios instance `http` in `src/lib/http.ts`;
  - per-domain API objects (`exportsApi`, `booksApi`) in `src/api/`;
  - react-query hooks and i18next;
  - homegrown flags: `useFlag(name)` reads `session.flags`; unknown names return false;
  - the book settings form sends back the fetched book object with edits (`{...book, name}`).
- **History:** per-account CSV exports shipped last year. An issue asks for "full ledger export per book".
- **Source maps:** not deployed. **Repo:** private.

Threat narrative: Ledgerly holds firms' financial records. An attacker with an accountant or viewer seat wants (a) bulk data out of books they can see, and (b) owner rights.

## The obvious design (don't do this)

```js
ts.trap('/admin/config').respond({ status: 200, body: { debug: true } });
ts.watch('/api/v3/me').body('is_admin', { intent: 'PrivEsc' });
```
```js
// src/adminDebug.js
// INTERNAL DEBUG - remove before prod
export const getConfig = () => fetch('/admin/config');
```

Why it fails:
- **Generic path.** `/admin/config` is on every scanner wordlist, so it collects anonymous noise. It also fits nothing in a `/api/v3/books/...` API.
- **Too good to be true.** `200 {"debug": true}` reads as bait.
- **Fingerprint.** The anonymous response is trappsec's default `401 {}`.
- **Foreign field.** Ledgerly models permissions as roles; `is_admin` appears nowhere else in it.
- **The lure undermines itself:**
  - the comment and file name point straight at it;
  - it uses `fetch` where the app uses `http`;
  - nothing imports the standalone export, so tree-shaking removes it and it never ships.
- **No attribution.** No `identify_user`. Even with one reading `req.user`, per-route auth means every hit would be an anonymous signal.

## The convincing design

### 1. Decoy route: ledger exports behind a beta flag

- **Cover story:** full-ledger export, the feature the issue asked for, dark-launched behind a flag that was never enabled.
- **See:** in the `BookSettings-*.js` chunk, a button gated by `useFlag('ledgerExportsBeta')` that calls `exportsApi.createLedgerExport(bookId, 'csv')`, which POSTs to `/api/v3/books/:bookId/ledger-exports`.
- **Think:** "Bulk export exists but is hidden behind a client-side flag; maybe the server only checks the flag."
- **Do:** call the endpoint, or flip the flag. Either sends an authenticated POST → alert (`data_exfiltration`).
- **Response:** anonymous, the real 401. Signed in, the real 403 ("You need the owner role for this."), which feeds the chain below.

### 2. Honey field: `myRole` on the book update

- **Cover story:** none needed. `GET /api/v3/books/:bookId` already returns `myRole`, the UI uses it for gating, and the settings form echoes it back. The server derives roles from memberships and never reads `myRole` on PATCH. The bait already exists; extrapolate from it.
- **Watch:** `PATCH /api/v3/books/:bookId`, field `myRole`, with a callable default equal to the caller's real role from the session. Owners saving settings echo their own role and trigger nothing. An accountant who sends `"myRole": "owner"` triggers an alert (`privilege_escalation`).

### Chain

The decoy's 403 says the owner role is required. The book response shows `myRole`. Setting it trips the honey field. Two alerts with the same identity leave little doubt about intent.

### Code

```js
// server/src/deception.js: trappsec decoys. Cover stories are listed in the deception report.
const { Sentry } = require('trappsec');

function installDeception(app) {
  const ts = new Sentry(app, 'ledgerly-api', process.env.APP_ENV || 'development');

  // Captured from GET /api/v3/books/bk_test/entries: anonymous, and as a viewer.
  ts.default_responses.unauthenticated = {
    status_code: 401,
    response_body: { error: { type: 'unauthenticated', detail: 'Sign in to continue.' } },
    mime_type: 'application/json',
  };
  ts.default_responses.authenticated = {
    status_code: 403,
    response_body: { error: { type: 'forbidden', detail: 'You need the owner role for this.' } },
    mime_type: 'application/json',
  };

  // Session middleware is global, so the user is already resolved on trap routes.
  ts.identify_user((req) => (req.session?.userId
    ? { user: req.session.userId, role: req.session.plan }
    : null));

  // Ledger exports: dark-launched behind ledgerExportsBeta, which is never enabled.
  ts.trap('/api/v3/books/:bookId/ledger-exports')
    .methods('POST')
    .intent('data_exfiltration');

  // The settings form echoes myRole; roles really come from memberships.
  ts.watch('/api/v3/books/:bookId')
    .body('myRole', {
      defaultValue: (req) => req.session?.memberships?.[req.params.bookId],
      intent: 'privilege_escalation',
    });

  if (process.env.SECURITY_WEBHOOK_URL) {
    ts.add_webhook(process.env.SECURITY_WEBHOOK_URL, { secret: process.env.SECURITY_WEBHOOK_SECRET });
  }
  return ts;
}

module.exports = { installDeception };
```

`server.js` calls `installDeception(app)` after the session middleware. It awaits `ts.close()` inside the graceful-shutdown handler it already had, before `process.exit`. A new bare `SIGTERM` listener would stop Node from exiting on SIGTERM.

```ts
// src/api/exports.ts (existing module; one method added, same style as its neighbors)
export const exportsApi = {
  listAccountExports: () => http.get<ExportJob[]>('/api/v3/account/exports').then((r) => r.data),
  createAccountExport: (format: ExportFormat) =>
    http.post<ExportJob>('/api/v3/account/exports', { format }).then((r) => r.data),
  createLedgerExport: (bookId: string, format: ExportFormat) =>
    http.post<ExportJob>(`/api/v3/books/${bookId}/ledger-exports`, { format }).then((r) => r.data),
};
```

```tsx
// src/pages/books/BookSettingsPage.tsx (existing page)
const ledgerExportsBeta = useFlag('ledgerExportsBeta');
const createLedgerExport = useMutation({ mutationFn: (format: ExportFormat) => exportsApi.createLedgerExport(bookId, format) });
// ...
{ledgerExportsBeta && (
  <Button variant="secondary" onClick={() => createLedgerExport.mutate('csv')}>
    {t('bookSettings.exportLedger')}
  </Button>
)}
```

```json
// public/locales/{en,de,fr}/translation.json, beside the other bookSettings keys
"exportLedger": "Export full ledger"
```

### Checks that passed before this was called done

- **Fired every tripwire.**
  - Anonymous POST to the decoy: the real 401, plus a signal.
  - Viewer session: the 403, plus an alert carrying the user.
  - PATCH as owner with the echoed form: no event.
  - PATCH as accountant with `myRole: "owner"`: an alert, and the role was unchanged.
- **Parity.** `compare_responses.mjs` against `POST /api/v3/books/:bookId/close-periods` (owner-only) showed the same status, body and header names for a viewer.
- **Survival.** `scan_bundle.mjs --dir dist --lure /ledger-exports --lure ledgerExportsBeta`: both found, no findings.
- **False positives.**
  - `ledgerExportsBeta` is absent from the flag config, so `useFlag` returns false for everyone. Its name is recorded in the report so nobody reuses it.
  - `createLedgerExport` has exactly one call site, behind the flag.
- **Team.** AGENTS.md now names `exportsApi.createLedgerExport` and the flag as security sensors. CODEOWNERS sends `server/src/deception.js` and the two frontend files to the security team.
