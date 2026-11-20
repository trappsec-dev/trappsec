---
name: add-detection
description: Turn an application's existing validation and authorization into high-signal detections of someone probing its business logic. Finds the checks that reject inputs and states the app's real clients can never produce (values the UI never offers, client-sent totals that disagree with the server, workflow steps out of order, another tenant's IDs, replayed one-time tokens) and makes each one emit an OpenTelemetry finding tied to the caller's identity, without changing any response. It also counts every other refusal on the request's span, so a backend can see probing no single rule is sure of, and reports input that breaks a query, command, template, file path or outbound call. Use this whenever the user wants to detect tampering, impossible states, business-logic abuse, mass assignment, IDOR or injection attempts in their own app, or wants security alerts from existing validation. Inputs the app ignores rather than refuses (fields no handler reads, routes nothing serves) are add-deception's. Not for adding new validation, fixing vulnerabilities, rate limiting, WAF rules or audit logging.
license: MIT
---

# Add detection

You are making the application's existing defenses report on themselves. Most apps already reject the inputs an attacker sends while probing business logic: a price that doesn't match the catalogue, a role the form never offers, a refund for an order that was never paid, another tenant's project ID in a request body. They reject them quietly, so nobody learns that someone tried. Each such rejection, where no real client could ever have produced the input, is a detection waiting to happen.

The judgment calls are yours:
- which rejections are impossible for every real client, and which ones ordinary users hit by mistake: the first become findings, the second are only counted;
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
- **Objects the caller can't have seen:** another tenant's ID in a field the client fills from its own data, including an API path it builds from its own list (`/requests/${id}/approve`). IDs in page URLs usually don't qualify: shared links, bookmarks and stale tabs carry them. One lookup of the rejected ID, to tell another tenant's object from a deleted one, is allowed; make it on every rejection of that kind, so response time doesn't tell the caller which IDs exist. Objects the app itself lets the caller reach across tenants (break-glass, sharing, support access) are excluded: check the links it renders, not only its forms.
- **Workflow steps out of order:** approving one's own request, refunding an unpaid order, acting on a resource in a state the UI never offers the action for.
- **Replays:** a one-time token used again, after its first use completed, by an account that is neither the one that used it nor its intended recipient. Tokens bound to no recipient (an emailed invitation, a forwarded coupon) or held only by possession (a signing or magic link) have no second party to compare: leave them to the audit trail. Revisiting a link, or repeating a request within seconds, is never a replay.
- **Forgeries:** a signature that fails on a value of the shape the app issues, not one that expired, was cut short or was re-encoded by a mail client (check the signature alone, then the shape by length and character class only); an idempotency key reused with a different payload.
- **Request shapes the client never sends:** query text where the client sends only persisted query hashes (an unknown hash is just a stale client), a content type it never uses.
- **Limits the client enforces:** quantities, lengths or counts beyond what the UI allows, where the server also rejects them.

Not detections: typos, expired sessions, values a real user can type, concurrent edits, retries, an option retired recently enough that open tabs still send it, and refusals a real user can reach (a role revoked under an open tab, a state another user just produced). When a rejection is ambiguous, it gets no rule.

**Which clients.** A form sends only its options; a script on a public API, an SDK or an AI agent can send anything the schema allows. A condition qualifies only if no client of the app could produce it, so check each example against every client's code. Where some clients can send anything (scripts on API keys), scope the rule to the credential types whose clients you can read, and say so in the inventory; tokens issued by one login endpoint are one class, so scope by issuer (a claim), never by "bearer". For a client you can't read (a mobile build without source), take the evidence from the server instead: what it ever hands that account. A client holds only the IDs and values the server listed or returned to it, so a request for a record the server never showed the account (another employee's payslip, when the list is filtered to the caller's own and a payslip never changes owner) is impossible from any client, readable or not. Check the one way it isn't: a person who holds two accounts and switches between them in one browser, where a page or tab loaded as the first sends the second's session. Where the client keeps such state across a sign-in, the rule needs a fact stale state can't supply, or it isn't a detection. A missing client source never takes a whole surface off the map.

If you find an impossible state the app *doesn't* reject, that's a vulnerability, not a detection. Report it; don't fix it as part of this work unless the user asks.

## Every other refusal is counted

A rule fires only when you are certain, which leaves out most of what an attacker does while working out an app: permission errors on routes they guess, validation errors as they change one field at a time, 404s as they walk IDs. Real users cause each of these too, so none can be a finding. But one account producing forty of them in a minute, across routes a user of its role never visits, is a pattern only the backend can see, and only if every refusal is recorded.

So every refusal the app makes is written on the request's server span, with its kind, the app's own reason code and the object or field it was about (references/telemetry.md, Request outcome). It is an attribute, never a log record and never an alert. Record it in the one place the app already turns errors into responses (its exception handler, error middleware or error formatter), from the error's class and code, so no handler changes; add a per-branch call only where a refusal doesn't pass through that place (a form redisplayed with errors, a redirect with a flash message, a GraphQL `errors` entry). A refusal that fires a rule is counted too.

## Sinks

Where request input reaches a query built as text, a command, a template, a deserializer, a file path or an outbound address, a probe shows up as an operation that fails in a way the app's own code never causes, or that runs somewhere it never should. Those are sink findings, with their own detector and three sources: references/sinks.md. Read it before reconnaissance when the app has any such operation.

## Workflow

### 0. Prerequisites and questions

- **OpenTelemetry traces and logs are a prerequisite.** Check them first, as references/telemetry.md describes, including how the app samples traces. If they aren't in place, stop and tell the user.
- **Ownership.** Confirm this is the user's own application.
- **Stay in scope.** Change only what the plan says, and ask before touching auth, infrastructure or CI.
- **Questions.** Ask in one batch, only what the code cannot tell you:
  1. Which clients call the API besides the web UI in this repo: mobile apps and their oldest supported versions, partner integrations, scripts, SDKs, AI agents?
  2. What sits in front of the app in production (load balancer, CDN, ingress), if the repo doesn't say?

### 1. Reconnaissance

- **Attack paths.** Map the routes an attacker takes and their chokepoints as references/attack-paths.md describes, starting from add-deception's map and hand-offs if it has run. Every refusal at a chokepoint is a candidate; refusals elsewhere that pass the bar are candidates too.
- **Every client's real behavior.** For each endpoint you consider, find what every real client sends: the form's options, the values it computes, what it echoes back, how it retries. Include older client versions still in use.
- **Every rejection.** Find where the app rejects input or state: validators, schema constraints, permission checks, state-machine guards, signature checks, explicit error branches in domain code.
- **Where errors become responses.** The exception handler, error middleware or formatter that maps each error class to a status and body, the error classes and codes it knows, and every refusal that answers without passing through it.
- **Sinks.** Each operation in references/sinks.md that request input reaches, how the value gets there, and what the app does when it fails.
- **Who and from where.** Where the authenticated principal lives after authentication (user, tenant, credential, impersonation), and how the client IP reaches the app through its proxies.

### 2. Design

For each candidate rejection, write down:
- the attack path, stage and chokepoint, when it sits on one;
- the condition, in one sentence;
- why no real client can produce it, with evidence from the client code;
- the intent (references/telemetry.md);
- a stable rule ID.

Keep every candidate whose evidence holds for every client, and only those: a plausible rule is a false positive waiting, and a certain one is worth keeping however many there are. List the rejected candidates and why in the plan, so the next agent doesn't add them back; each is still counted as a refusal.

For the refusals, write one table from each error class or code to its `security.refusal.kind` and reason, and for each sink rule its source (references/sinks.md). Inputs at a chokepoint that the app ignores rather than refuses are handed off to add-deception, and inputs it accepts are vulnerabilities (references/attack-paths.md).

### 3. Present the plan

Unless the user already told you to go ahead, show the plan and wait:

| # | Path / stage | Rule ID | Endpoint / operation | Condition | Why no real client produces it | Intent |
|---|---|---|---|---|---|---|

Then list, from the attack-path map, the inputs handed off to add-deception and the chokepoints left uncovered and why. Below that:

- the refusal table: error class or code, kind, reason, where it is recorded, and the refusals that can't be recorded because they happen before the app's code runs;
- the sink rules, in the rule table's columns with the sink and source in place of the client evidence, and the sinks checked and found safe.

### 4. Implement

- **Record in the branch that already rejects**, with the app's own idioms, and with the caller's identity where it is known; a refusal before authentication (a forged link, an anonymous request) records what it knows. The response, status, timing class and side effects stay exactly as they were. A rejection need not be an error status: a form redisplayed with an error, a redirect with a flash message, a GraphQL `errors` entry in a 200. Record on the specific error code or kind the check raises, never on any validation error; a validator without an error code may be given one where the code never reaches the response. Where one error answers several refusals, record in the branch that decides, not on the error. A check the app also uses to filter what it lists (a permission test behind a list endpoint) records where a request is refused, never inside the shared check. Never pass the classification through the response.
- **Never add a new rejection, and never change what the app accepts.**
- **Refusals** are written by the request-context module from the table in the plan, in the place errors become responses, once the response is known. Kind and reason come from the error's class and code in server code, the field name from the server's schema, the resource from what the check held. A request with several keeps the first and counts the rest. An error class the table doesn't know writes nothing, rather than a guess.
- **Sink rules** follow references/sinks.md: recorded at the app's own call site or helper, with no parsing of the input and nothing that can change the operation's outcome.
- **Evaluate only what the check already evaluates**, values already in hand, and the one lookup above; never walk attacker-supplied structures. A rule behind an earlier permission check only sees callers who passed it: report the blind spot, don't reorder the checks.
- **One recording module** sets the caller's identity on the server span and emits the finding in references/telemetry.md. Recording never fails, blocks or changes a request.
- **Every rule has a stable ID, a marker in server code naming it at each site that records it, and an entry in one server-side inventory** with its label, condition, evidence, detector, intent and severity. The same inventory lists the inputs handed off to add-deception and the chokepoints left uncovered, with their reasons, so add-deception and the next agent can read them.
- **The inventory reports itself.** Add the inventory records, the self-check command and the drift test in references/telemetry.md (Inventory records and the self-check), reusing them if another skill added them.

### 5. Verify

1. **Project checks.** Lint, type checks and the app's existing tests pass.
2. **Each rule fires.** Send the impossible input as a normal user. The finding matches references/telemetry.md and shares its trace and span IDs with the request's server span, which names the right user, tenant and credential, has `security.flagged` set, and passes the `client.address` check.
3. **Behavior unchanged.** The response to the impossible input is identical to the response before your change: status, headers and body. Capture them before the first of these skills edits the code (a worktree of the commit before it works), and normalize what changes per response: `Date`, request IDs, CSRF and other random tokens, JSON key order. No data changed that didn't change before.
4. **Real flows stay silent.** Replay every real client flow through the endpoints you touched, including the edge cases (retries, stale tabs, concurrent edits). Not one finding.
5. **Refusals.** For each row of the refusal table, one request that causes it: the server span carries the right kind, reason and object, the response is identical to before, and no log record was added. A request that succeeds carries no `security.refusal.*`. The real flows of check 4 produce refusals where real users are refused, and still no finding.
6. **Sink rules.** As references/sinks.md describes: each fires on input that breaks the structure, and the app's whole test suite, run with recording on, fires none.
7. **Inventory and self-check.** Start the app and find one inventory record per rule, with one hash and the right size. Run the self-check command and find one `test` finding per rule. Remove one rule's recording call in a scratch copy and show the drift test fails.
8. **Robustness.** Make your own recording module fail in a test, through one fault point it exposes (not the OpenTelemetry API, which the instrumentation shares); responses don't change.
9. **Names.** Every finding and span attribute uses the names in references/telemetry.md, and nothing else in the app uses them with another meaning.
10. **Tests.** One test per rule that fires it and asserts the finding and the unchanged response, plus one that replays the real flows and asserts no findings. Where the suite's own infrastructure can't run here (a database it needs), write them anyway, verify live instead, and say which ran.

### 6. Report

- The rule inventory, with file:line for each rule.
- The attack-path map with every input's outcome: covered, handed off to add-deception, uncovered with its reason, or vulnerability (references/attack-paths.md).
- For each rule, a command that triggers it.
- The false-positive evidence: what each real client sends, and why it can't match.
- Impossible states you found that the app doesn't reject (vulnerabilities to fix separately), including every sink invariant the code implies and doesn't check.
- The refusal table, and what the backend can now do with it: rates of each kind per account, credential and address against that actor's own requests. This skill sets no thresholds.
- The self-check command, when to schedule it (after each deploy, and daily), and the two alerts it makes possible: an inventory entry with no test finding in a day, and an inventory hash that changed without a release.
- Assumptions and residual risks, including any proxy misconfiguration that affects the recorded client IP.

## Keep the team in on it

Every rule is real product code, and someone will eventually refactor the check it lives in. The inventory, the markers and the tests keep the detection alive. In a private repository, add a short note to the repo's agent instructions (`AGENTS.md` or `CLAUDE.md`; create `AGENTS.md` if there are none) naming the rules and asking agents to keep them when they change the surrounding validation. In a public repository the inventory and markers are visible too; a detection still works when it is known, because the check refuses anyway, so keep them, add no note, and tell the user.

## Reference files

- **references/attack-paths.md**: the attack-path map and the test that divides its inputs between add-detection and add-deception, shared with add-deception.
- **references/telemetry.md**: the OpenTelemetry prerequisite, the request context, request outcome and records shared with add-auditing, add-deception and add-response, the inventory records and self-check, and the detection and sink findings.
- **references/sinks.md**: which operations count as sinks, the three sources of a sink finding, and the rules every sink rule follows.
