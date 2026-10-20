# Worked example: obvious vs. convincing

This example shows the reasoning, not names to reuse. Copying its paths, flags or fields into another app creates exactly the cross-app fingerprint the skill warns about.

## The app

"Ledgerly" is a fictional bookkeeping SaaS for accounting firms.
- **Backend:** Express, API under `/api/v3`.
- **Frontend:** React + Vite.

House-style dossier, from recon:

- **Routes:** `/api/v3/books/:bookId/<plural-noun>`. Actions are sub-resources (`/close-periods`). IDs are prefixed (`bk_`, `usr_`). JSON is camelCase.
- **Errors:** `{ "error": { "type": "...", "detail": "..." } }` through an `HttpError` class and one error middleware. Types in use: `unauthenticated`, `forbidden`, `not_found`, `validation_failed`. Captured from the running app:
  - anonymous: `401 {"error":{"type":"unauthenticated","detail":"Sign in to continue."}}`
  - forbidden: `403 {"error":{"type":"forbidden","detail":"You need the owner role for this."}}`
  - unknown book: `404 {"error":{"type":"not_found","detail":"Book not found."}}`
- **Pipeline:** cookie sessions via global middleware. Each book route runs `requireSession`, `loadBook` (404 for books the caller isn't a member of), `requireRole(...)`, then `validate(schema)`. Each book has roles `owner | accountant | viewer`, loaded into `req.session.memberships`. Firms sign up self-serve, so anyone can own a book.
- **Frontend:**
  - an axios instance `http` in `src/lib/http.ts`;
  - per-domain API objects (`exportsApi`, `booksApi`) in `src/api/`;
  - react-query hooks and i18next;
  - homegrown flags: `useFlag(name)` reads `session.flags`, which lists only enabled flags; unknown names return false;
  - the book settings form sends back the fetched book object with edits (`{...book, name}`).
- **History:** per-account CSV exports shipped last year. An issue asks for "full ledger export per book".
- **Telemetry:** the OpenTelemetry SDK is initialized in `server/src/telemetry`, exporting traces and logs over OTLP, with HTTP server instrumentation and the default always-on sampler.
- **Deployment:** behind an AWS load balancer; the app already sets `app.set('trust proxy', 1)`, so `req.ip` is the client. Requests carry an `X-Request-Id` the access log records.
- **Source maps:** not deployed. **Repo:** private.

Threat narrative: Ledgerly holds firms' financial records. An attacker with an accountant or viewer seat wants (a) bulk data out of books they can see, and (b) owner rights. An attacker who signs up their own firm owns their own books and will compare.

## The obvious design (don't do this)

```js
// src/routes/admin.js
// INTERNAL DEBUG - remove before prod
router.get('/admin/config', (req, res) => res.json({ debug: true }));

router.patch('/api/v3/me', requireSession, (req, res, next) => {
  if (req.body.is_admin) console.log('HONEYPOT TRIGGERED', req.ip);
  next();
});
```
```js
// src/adminDebug.js
export const getConfig = () => fetch('/admin/config');
```

Why it fails:
- **Generic path.** `/admin/config` is on every scanner wordlist, so it collects anonymous noise. It also fits nothing in a `/api/v3/books/...` API.
- **No chain.** It skips `requireSession`, so it answers anonymous callers with 200 where every real route answers 401. One unauthenticated request separates it from the real API.
- **Too good to be true.** `200 {"debug": true}` reads as bait.
- **Foreign field.** Ledgerly models permissions as roles; `is_admin` appears nowhere else in it.
- **No identity, no structure.** A bare `console.log` with no user, no intent and a revealing message.
- **The lure undermines itself:**
  - the comment and file names point straight at it;
  - it uses `fetch` where the app uses `http`;
  - nothing imports the standalone export, so tree-shaking removes it and it never ships.

## The convincing design

### 1. Decoy route: ledger exports behind a beta flag

- **Cover story:** full-ledger export, the feature the issue asked for, dark-launched behind a flag that was never enabled.
- **See:** in the `BookSettings-*.js` chunk, a button gated by `useFlag('ledgerExportsBeta')` that calls `exportsApi.createLedgerExport(bookId, 'csv')`, which POSTs to `/api/v3/books/:bookId/ledger-exports`.
- **Think:** "Bulk export exists but is hidden behind a client-side flag; maybe the server only checks the flag."
- **Do:** call the endpoint, or flip the flag. Either sends an authenticated POST → alert (`data_exfiltration`).
- **Chain copied:** `close-periods`, the owner-only action beside it: `requireSession`, then the tripwire, `loadBook`, `requireRole('owner')`, `validate(...)`.
- **Responses:** every probe gets what `close-periods` gives it (401, 404 for foreign books, 403 "You need the owner role for this." for accountants and viewers, 422 for bad bodies). An owner, who passes every check, gets the final denial: `403 forbidden` "Ledger exports aren't enabled for this firm yet." That makes sense to an owner, and it uses an error type the app already returns.

### 2. Honey field: `myRole` on the book update

- **Cover story:** none needed. `GET /api/v3/books/:bookId` already returns `myRole`, the UI uses it for gating, and the settings form echoes it back. The server derives roles from memberships and never reads `myRole` on PATCH. The bait already exists; extrapolate from it.
- **Check:** at the top of `PATCH /api/v3/books/:bookId`, after `requireSession`: compare `myRole` with the caller's real role from the session. Owners saving settings echo their own role and record nothing. An accountant who sends `"myRole": "owner"` records an alert (`privilege_escalation`). The settings schema ignores unknown fields, so the check removes `myRole` after recording, and the endpoint behaves exactly as before.

### Chain

For accountants and viewers, the decoy's 403 says the owner role is required. The book response shows `myRole`. Setting it trips the honey field. Two alerts with the same identity leave little doubt about intent.

### Code

A new `server/src/security/` module, next to the app's other telemetry code, does two things. Its `setRequestContext` middleware runs right after `requireSession` on every route and sets the caller's identity on the request's server span. Its route middleware records hits as findings through a dedicated `ledgerly.security` logger: `recordProbe` for the decoy and `checkField` for the honey field, both keyed by inventory ID.

```js
// server/src/routes/books.js (existing router)
router.post('/:bookId/close-periods', requireSession, loadBook, requireRole('owner'), validate(closePeriodSchema), closePeriods);

// Security tripwire: full-ledger export, dark-launched behind ledgerExportsBeta and never enabled. See docs/security/tripwires.md.
router.post('/:bookId/ledger-exports', requireSession, recordProbe('books.ledger-exports'), loadBook, requireRole('owner'),
  validate(ledgerExportSchema),
  (req, res, next) => next(new HttpError(403, 'forbidden', "Ledger exports aren't enabled for this firm yet.")));

// Security tripwire: myRole is echoed by the settings form; roles come from memberships. See docs/security/tripwires.md.
router.patch('/:bookId', requireSession,
  checkField('books.my-role', 'myRole', (req) => req.session.memberships?.[req.params.bookId]),
  loadBook, requireRole('owner'), validate(bookSettingsSchema), updateBook);
```

An accountant's PATCH with `"myRole": "owner"` gets the app's normal 403 and produces this finding (resource omitted):

```json
{
  "eventName": "trappsec.deception.field_hit",
  "severityText": "WARN",
  "body": "honey field hit",
  "traceId": "4bf92f3577b34da6a3ce929d0e0e4736",
  "spanId": "00f067aa0ba902b7",
  "attributes": {
    "trappsec.schema.version": "1",
    "trappsec.tenant.id": "firm_9kd2",
    "user.id": "usr_41xQ",
    "security_rule.name": "books.my-role",
    "security_rule.category": "privilege_escalation",
    "trappsec.finding.field.name": "myRole",
    "trappsec.finding.field.value": "owner",
    "trappsec.finding.resource.type": "book",
    "trappsec.finding.resource.id": "bk_8Hq2"
  }
}
```

Who and from where are on the server span with the same trace and span IDs, which the backend joins to the finding:

```json
{
  "kind": "SERVER",
  "name": "PATCH /api/v3/books/:bookId",
  "attributes": {
    "http.request.method": "PATCH",
    "http.route": "/api/v3/books/:bookId",
    "url.path": "/api/v3/books/bk_8Hq2",
    "http.response.status_code": 403,
    "client.address": "198.51.100.23",
    "user_agent.original": "Mozilla/5.0 ...",
    "user.id": "usr_41xQ",
    "user.name": "sam.okafor",
    "user.roles": ["accountant"],
    "trappsec.tenant.id": "firm_9kd2",
    "session.id": "sess_7d1c",
    "trappsec.credential.type": "session",
    "trappsec.credential.id": "sess_7d1c",
    "trappsec.actor.type": "user",
    "trappsec.flagged": true
  }
}
```

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

- **Probed like its sibling.** Each probe went to `ledger-exports` and to `close-periods`:
  - anonymous, expired cookie, foreign book, unknown book, malformed body: identical responses;
  - viewer and accountant: identical 403, plus an alert carrying the user and their role in that book;
  - owner of their own book: the final denial on the decoy, 201 on the sibling, plus an alert.
- **Honey field.**
  - PATCH as owner with the echoed form: no event, same response as before.
  - PATCH as accountant with `myRole: "owner"`: an alert, the same 403 as before, and the role unchanged.
  - An unrelated unknown field is ignored exactly like `myRole`.
- **Inert.** A test hits the decoy as each role and asserts no export job, no file and no change to the book.
- **Robust.** A test makes the security logger throw; every response is unchanged.
- **Attribution and schema.** Each finding matches references/telemetry.md and shares its trace and span IDs with the request's server span, which names the user, their role in that book, the firm, the session and the credential. A forged `X-Forwarded-For` didn't change the recorded IP.
- **Parity.** `compare_responses.mjs` against `close-periods` reported no differences: anonymous and with an expired cookie (`--identical`), and as a viewer.
- **Elimination.** As a self-serve owner, every other book endpoint can be made to work. `ledger-exports` can't, but it is gated by the same owner check testers see failing on `close-periods`, and it sits behind a client flag like the app's other unreleased features.
- **Survival.** `scan_bundle.mjs --dir dist --lure /ledger-exports --lure ledgerExportsBeta`: both found, no findings.
- **False positives.**
  - `ledgerExportsBeta` is not in the flag config, and `session.flags` lists only enabled flags, so its absence looks like any other disabled flag. Its name is recorded in the inventory so nobody reuses it.
  - `createLedgerExport` has exactly one call site, behind the flag.
- **Team.** `docs/security/tripwires.md` lists both tripwires with their files and tests. AGENTS.md names `exportsApi.createLedgerExport`, the flag and the two routes as security sensors not to remove, call or complete. CODEOWNERS sends `server/src/security/`, `server/src/routes/books.js` and the two frontend files to the security team.
