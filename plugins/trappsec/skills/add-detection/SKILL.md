---
name: add-detection
description: Turn an application's existing validation and authorization into high-signal detections of someone probing its business logic. Finds the checks that reject inputs and states the app's real clients can never produce (values the UI never offers, client-sent totals that disagree with the server, workflow steps out of order, another tenant's IDs, replayed one-time tokens) and makes each one emit an OpenTelemetry finding tied to the caller's identity, without changing any response. Use this whenever the user wants to detect tampering, impossible states, business-logic abuse, mass assignment or IDOR attempts in their own app, or wants security alerts from existing validation. Not for adding new validation, fixing vulnerabilities, rate limiting, WAF rules or audit logging.
license: MIT
---

# Add detection

You are making the application's existing defenses report on themselves. Most apps already reject the inputs an attacker sends while probing business logic: a price that doesn't match the catalogue, a role the form never offers, a refund for an order that was never paid, another tenant's project ID in a request body. They reject them quietly, so nobody learns that someone tried. Each such rejection, where no real client could ever have produced the input, is a detection waiting to happen.

The judgment calls are yours:
- which rejections are impossible for every real client, and which ones ordinary users hit by mistake;
- recording each impossible one with who did it and from where;
- proving that nothing about the app's behavior changes, and that no real user ever triggers a detection.

## What makes a good detection

| Property | In practice |
|---|---|
| Impossible | No real client can produce the input: not the current UI, not an older version still in use, not a retry, a race or a double click. A detection a real user can trigger is a bug. |
| Existing | It instruments a check the app already makes. The app's response and behavior stay exactly as they were. |
| Silent | Nothing in any response reveals that the check now reports. |
| Attributed | The finding shares its trace with the request's server span, which names the account, credential, tenant and client. |
| Meaningful | It points at an intent worth acting on: privilege, money, other tenants' data, workflow integrity. |
| Proven | You have triggered it, and shown that the real client's flows never do. |

## What counts as impossible

Look for these where validation or authorization already rejects them:

- **Values the UI never offers:** an enum outside the options any version of the form showed; a disabled or hidden option; a role, status, plan or scope no screen lets a user pick.
- **Values the server already knows:** a client-sent price, total, owner, tenant or user ID that must equal the server's own value, when it can't have changed while the client held it (a price staff can edit while a cart is open can). Client values that must agree with each other (line totals and the order total) qualify, unless one can legitimately be empty or the server drops rows.
- **Objects the caller can't have seen:** another tenant's ID in a field the client fills from its own data, including an API path it builds from its own list (`/requests/${id}/approve`). IDs in page URLs usually don't qualify: shared links, bookmarks and stale tabs carry them. One lookup of the rejected ID, to tell another tenant's object from a deleted one, is allowed. Objects the app itself lets the caller reach across tenants (break-glass, sharing, support access) are excluded: check the links it renders, not only its forms.
- **Workflow steps out of order:** approving one's own request, refunding an unpaid order, acting on a resource in a state the UI never offers the action for.
- **Replays:** a one-time token used again, after its first use completed, by an account that is neither the one that used it nor its intended recipient. Tokens bound to no recipient (an emailed invitation, a forwarded coupon) or held only by possession (a signing or magic link) have no second party to compare: leave them to the audit trail. Revisiting a link, or repeating a request within seconds, is never a replay.
- **Forgeries:** a signature that fails on a value of the shape the app issues, not one that expired, was cut short or was re-encoded by a mail client (check the signature alone, then the shape by length and character class only); an idempotency key reused with a different payload.
- **Request shapes the client never sends:** query text where the client sends only persisted query hashes (an unknown hash is just a stale client), a content type it never uses.
- **Limits the client enforces:** quantities, lengths or counts beyond what the UI allows, where the server also rejects them.

Not detections: typos, expired sessions, values a real user can type, concurrent edits, retries, an option retired recently enough that open tabs still send it, and refusals a real user can reach (a role revoked under an open tab, a state another user just produced). When a rejection is ambiguous, leave it alone.

**Which clients.** A form sends only its options; a script on a public API, an SDK or an AI agent can send anything the schema allows. A condition qualifies only if no client of the app could produce it, so check each example against every client's code. Where some clients can send anything (scripts on API keys), scope the rule to the credential types whose clients you can read, and say so in the inventory; tokens issued by one login endpoint are one class, so scope by issuer (a claim), never by "bearer". For a client you can't read (a mobile build without source), keep to inputs the server already rejects.

If you find an impossible state the app *doesn't* reject, that's a vulnerability, not a detection. Report it; don't fix it as part of this work unless the user asks.

## Workflow

### 0. Prerequisites and questions

- **OpenTelemetry traces and logs are a prerequisite.** Check them first, as references/telemetry.md describes, including how the app samples traces. If they aren't in place, stop and tell the user.
- **Ownership.** Confirm this is the user's own application.
- **Questions.** Ask in one batch, only what the code cannot tell you:
  1. Which clients call the API besides the web UI in this repo: mobile apps and their oldest supported versions, partner integrations, scripts, SDKs, AI agents?
  2. What sits in front of the app in production (load balancer, CDN, ingress), if the repo doesn't say?

### 1. Reconnaissance

- **Every client's real behavior.** For each endpoint you consider, find what every real client sends: the form's options, the values it computes, what it echoes back, how it retries. Include older client versions still in use.
- **Every rejection.** Find where the app rejects input or state: validators, schema constraints, permission checks, state-machine guards, signature checks, explicit error branches in domain code.
- **Who and from where.** Where the authenticated principal lives after authentication (user, tenant, credential, impersonation), and how the client IP reaches the app through its proxies.

### 2. Design

For each candidate rejection, write down:
- the condition, in one sentence;
- why no real client can produce it, with evidence from the client code;
- the intent (references/telemetry.md);
- a stable rule ID.

Keep only the ones whose evidence holds for every client; fewer, certain detections beat many plausible ones. List the rejected candidates and why in the plan, so the next agent doesn't add them back.

### 3. Present the plan

Unless the user already told you to go ahead, show the plan and wait:

| # | Rule ID | Endpoint / operation | Condition | Why no real client produces it | Intent |
|---|---|---|---|---|---|

### 4. Implement

- **Record in the branch that already rejects**, after authentication, with the app's own idioms; the response, status, timing class and side effects stay exactly as they were. A rejection need not be an error status: a form redisplayed with an error, a redirect with a flash message, a GraphQL `errors` entry in a 200. Record on the specific error (Django's `invalid_choice`, Rails' `errors.of_kind?(:role, :inclusion)`), never on any validation error; a validator without an error code may be given one. Never pass the classification through the response.
- **Never add a new rejection, and never change what the app accepts.**
- **Evaluate only what the check already evaluates**, values already in hand, and the one lookup above; never walk attacker-supplied structures. A rule behind an earlier permission check only sees callers who passed it: report the blind spot, don't reorder the checks.
- **One recording module** sets the caller's identity on the server span and emits the finding in references/telemetry.md. Recording never fails, blocks or changes a request.
- **Every rule has a stable ID, a marker in server code naming it at each site that records it, and an entry in one server-side inventory** with its condition, its evidence and its intent.

### 5. Verify

1. **Project checks.** Lint, type checks and the app's existing tests pass.
2. **Each rule fires.** Send the impossible input as a normal user. The finding matches references/telemetry.md and shares its trace and span IDs with the request's server span, which names the right user, tenant and credential, has `security.flagged` set, and passes the `client.address` check.
3. **Behavior unchanged.** The response to the impossible input is identical to the response before your change: status, headers and body. Capture them before the first of these skills edits the code (a worktree of the commit before it works), and normalize what changes per response: `Date`, request IDs, CSRF and other random tokens, JSON key order. No data changed that didn't change before.
4. **Real flows stay silent.** Replay every real client flow through the endpoints you touched, including the edge cases (retries, stale tabs, concurrent edits). Not one finding.
5. **Robustness.** Make your own recording module fail in a test, through one fault point it exposes (not the OpenTelemetry API, which the instrumentation shares); responses don't change.
6. **Names.** Every finding and span attribute uses the names in references/telemetry.md, and nothing else in the app uses them with another meaning.
7. **Tests.** One test per rule that fires it and asserts the finding and the unchanged response, plus one that replays the real flows and asserts no findings.

### 6. Report

- The rule inventory, with file:line for each rule.
- For each rule, a command that triggers it.
- The false-positive evidence: what each real client sends, and why it can't match.
- Impossible states you found that the app doesn't reject (vulnerabilities to fix separately).
- Assumptions and residual risks, including any proxy misconfiguration that affects the recorded client IP.

## Keep the team in on it

Every rule is real product code, and someone will eventually refactor the check it lives in. The inventory, the markers and the tests keep the detection alive. In a private repository, add a short note to the repo's agent instructions (`AGENTS.md` or `CLAUDE.md`; create `AGENTS.md` if there are none) naming the rules and asking agents to keep them when they change the surrounding validation.

## Ground rules

- **A false positive is a bug.** If a real client can produce it, it isn't a detection.
- **Never change behavior.** Same responses, same acceptance, same side effects.
- **Don't fix, report.** Missing validation is a vulnerability for the user to decide on.
- **No secrets in events**, even when the caller submitted one.
- **Stay in scope.** Ask before touching auth, infrastructure or CI.

## Reference files

- **references/telemetry.md**: the OpenTelemetry prerequisite, the request context and records shared with add-auditing and add-deception, and the detection finding.
