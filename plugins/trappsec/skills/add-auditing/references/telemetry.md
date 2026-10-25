# Telemetry

What add-auditing emits, and what it needs in place first. The common core is shared word for word with add-deception and add-detection, so records from all three line up.

<!-- BEGIN COMMON CORE: identical in add-auditing, add-deception and add-detection -->
## Prerequisite: OpenTelemetry traces and logs

These skills write to OpenTelemetry traces and logs together. Before designing anything, confirm the app already has:
- an OpenTelemetry SDK with a tracer provider and a logger provider, both exported (usually OTLP to a Collector), initialized in every entry point that will emit: the web server, workers, each CLI, script or management command;
- a server span for every request, from HTTP server instrumentation or, on a function platform, the invocation span;
- log records emitted in a request carrying its trace and span IDs (test with a record your own code emits; framework access lines are often written after the span ends);
- a way to emit a log record with an event name through the Logs API (see Stack notes).

Confirm it end to end: emit one record from a request and find it, with its event name and trace ID, where the app's telemetry lands, reading the SDK's own error output as you do.

If any of these is missing, stop. Tell the user what you found and that this skill needs OpenTelemetry traces and logs first, and offer to set them up as a separate change, listing the gaps below in the same message.

**Gaps that don't stop the work.** The server span should carry `http.request.method`, `http.route`, `url.path`, `http.response.status_code`, `client.address` and `user_agent.original`. Where the instrumentation uses older names, leaves one out or fills one wrongly (a raw path in `http.route`), the request-context module writes the right attribute on the server span, or sets an opt-in the repo owns (Python: `OTEL_SEMCONV_STABILITY_OPT_IN=http/dup`), and tells the user.

**What this work may touch in the telemetry setup:** a server request hook, or where there is none a small middleware or filter running inside the server span; an opt-in; attributes on the server span; on a function platform, a flush per invocation. Everything else is the user's to decide, so report and ask: exporters, processors, samplers, the resource, inbound trace-context extraction, metric exemplars, and what other instrumentations capture.

**Sampling and inbound context.** If the app samples traces itself, findings from dropped requests can't be joined to their caller, and `trappsec.flagged` can't bring a dropped trace back. Most instrumentations also take their parent from the caller's `traceparent`, so on a public entry point a caller can stop the server span being exported or choose its trace ID. Report either; the usual fixes are a parent-based always-on sampler and ignoring inbound context at public entry points. Audit records don't depend on this, and findings carry the request context themselves when the server span isn't recording.

## Common core

### Namespace

Event names and attributes these skills define live under the fixed `trappsec` namespace, the same everywhere. Never invent attributes in OpenTelemetry's own namespaces.

`trappsec` is written only in the string literals that spell attribute keys and event names (a constant holding one is fine), the tests that assert them, and plans that cite them. No identifier, file name, comment, logger name, rule ID, record body, attribute value or error message contains it: values reach dashboards and tickets, and code is read by teammates and sometimes by attackers. Name the recording code like the app's other observability code, and before you finish, search the source for the word.

### Three kinds of record

Each fact is said once, where it is known.

| Record | Says | When |
|---|---|---|
| Request context, on the server span | Who called and from where | Once per request |
| Audit record, a log record | The complete audit entry: who did what, for whom, to what, from where, with what result | When an audited action succeeds, is denied or fails |
| Finding, a log record | Which deception or detection rule fired, on what, plus the tenant and account as routing keys | When a rule fires |

The backend joins each finding to its request's context by trace and span ID. Audit records stand on their own, without the join, the span or sampling. A request carrying several actions or findings (a GraphQL document, a batch) emits one record for each, all on the request's span.

### Request context

One small module, shared by all three skills (reuse it, its inventory and its tests if another skill added it), writes the request context on the server span from the app's own state, never from anything the caller sent:
- `client.address` and any missing request attribute as the request starts, so requests that fail authentication carry them too;
- identity once authentication has succeeded: right after it, or in a response hook while the span is open, which leaves authentication code alone. The endpoint that signs someone in writes it on success; a refusal raised before authentication writes what it knows;
- the tenant the server resolved (from the session, a token, a row it loaded, or an argument after its membership check), never one the caller merely named. A request acting in several keeps the first; each record carries its own.

Omit an attribute whose value is unknown; never write an empty string.

**Reaching the server span.** The current span in a handler is often a child (a controller, framework or database span). Capture the server span where it is known (Stack notes), keep it in the request, write the context and `trappsec.flagged` to it, and emit findings in its context so they carry its span ID. Operations over a long-lived connection (WebSocket, subscriptions) have no per-operation span: start a server-kind span for each.

| Span attribute | Type | Value |
|---|---|---|
| `user.id` | string | A stable ID for the account the request acted as; not an email. Absent for a credential no person holds |
| `user.name` | string | That account's login, unless it is personal data the user wants kept out |
| `user.roles` | string[] | The roles that matter for authorization |
| `trappsec.tenant.id` | string | The organization or workspace acted in; a fixed ID in a single-tenant app |
| `session.id` | string | A hash or row ID of the session, never the cookie or key itself |
| `trappsec.credential.type` | string | `session`, `token`, `api_key`, `oauth_client`, `service_account` or `link` (a signed or one-time URL) |
| `trappsec.credential.id` | string | The credential's ID, so it can be revoked; omitted when it has none. Never the secret |
| `trappsec.actor.type` | string | `user`, `service`, `integration` or `agent` |
| `trappsec.actor.id` | string | The real actor when someone or something acts as `user.id` (impersonation, support access, an agent); an integration's credential ID when there is no `user.id` |
| `trappsec.flagged` | boolean | `true` once any finding fires in the request, so the backend keeps the trace |

**`client.address`** is the address that connected to the outermost proxy the app trusts, and the module writes it on every request, replacing the instrumentation's (many take the first `X-Forwarded-For` entry, which the caller controls):
- the platform's field where it gives one (API Gateway's `requestContext.http.sourceIp`), never a forwarding header;
- otherwise the framework's resolver (Rails `remote_ip`, Express `trust proxy`, Werkzeug `ProxyFix`, uvicorn `--forwarded-allow-ips`), reporting what it trusts by default;
- otherwise the smallest setting beside the module: the entry the nearest trusted proxy appended, counting from the right. That is safe only if the app can't be reached except through those proxies; ask, and tell the user what it assumes;
- an IP literal, or else the connection's own address.

If the app's own setting is wrong, report it and its fix rather than changing proxy or infrastructure configuration. To verify, send a forged `X-Forwarded-For` through a stand-in proxy that appends the connecting address: the recorded IP is that address. A direct request alone proves nothing.

### Log records

- **One record per occurrence, emitted as an event**, with the event name in the record's event-name field (never an `event.name` attribute) and no dynamic values in it.
- **A dedicated logger per family**, named like the app's others: audit records from one (`<app>.audit`), findings from another (`<app>.security`), so the backend can route them apart from each other and from ordinary logs.
- **In the trace context of the request that caused it**, under the app's existing resource. Work outside a request (a job, a consumer, a script) records in the span its instrumentation starts, or starts one: one per message for a batch consumer. Work a request starts in-process inherits its context; start it detached, with a link, when it should stand alone.
- **With its timestamp set**; some SDKs leave it empty.
- **The body is a short fixed display string** ("member role changed"); everything else goes in attributes.
- **Severity:** audit records `INFO`; findings `WARN` when the caller is identified (a user or a credential), `INFO` when anonymous.

### Intents

Findings carry one of these in `security_rule.category`: `reconnaissance`, `privilege_escalation`, `account_takeover`, `cross_tenant_access` (another organization's data), `cross_account_access` (another user's, inside one), `data_exfiltration`, `entitlement_abuse`, `payment_fraud`, `mass_assignment` (a field the handler must not honor), `parameter_tampering` (a value the client never offers, in a field the handler reads), `workflow_tampering`, `defense_evasion`. Where privilege or entitlement is the evident aim, that intent wins. If none fits, add one to the inventory.

### Values

- Attacker-controlled strings are cut to 1024 characters and arrays to 20 elements; objects become compact JSON within a fixed budget of nodes and depth. A request document or raw body is recorded as its length and a hash.
- No secrets (passwords, tokens, keys, session secrets, signed links), even when the caller sent one, and no document or message content.
- Action and rule names and intents come from server code. An ID the caller sent and the app rejected is recorded as what was sent, never as the actor or tenant.
- Build each record from fresh values: some SDKs silently drop a map attribute that holds the same object twice. Where the SDK has no map value or rejects one, write dotted keys under the attribute's name (`trappsec.audit.actor.id`) and tell the user.
- Listed values are a starting vocabulary; anything specific to one action or rule goes in its declared params. Where one endpoint carries several operations (GraphQL, JSON-RPC), `operation` there names the one recorded.

**Secrets in URLs.** On routes whose path or query holds a secret, the module overwrites every server-span attribute filled from the URL (`url.path`, `url.full`, `url.query`, `http.target`, `http.url`, `http.route`): the path with the route template, which may only be known after routing, and the query with a fixed marker. Then search every exported signal for a real token (child and outbound spans, metric exemplars, span events, the app's logs) and report what only a user setting can stop.

### Emitting

- Emitting never fails, blocks or changes a request: errors are swallowed, and nothing waits on the network in the request path.
- Its cost is constant and small, whatever the request contains.
- A short-lived process flushes or shuts down its tracer and logger providers on every exit path.
- A function platform that freezes the process after the response needs a logger flush as the last step of every invocation, error paths included: the one network wait these skills allow, bounded by the exporter's timeout. Tell the user, and suggest a local collector or extension.
- Each skill keeps one inventory or registry in server code of everything that emits, with stable IDs that records refer to.

### Stack notes

Known shapes of the advice above; check them against the versions in use.

| Stack | Server span | Event name and map values |
|---|---|---|
| Python (FastAPI, Django, Flask) | The instrumentor's request hook; keep the span on the request (`request.state`, `flask.g`) | `get_logger(name).emit(..., event_name=...)`; the `logging` bridge can't |
| Node | `getRPCMetadata(context.active()).span` | `logs` from `@opentelemetry/api`, the package the SDK registered; a separate `@opentelemetry/api-logs` silently drops records |
| Go | `trace.SpanFromContext(r.Context())` in the outermost wrapper inside `otelhttp`; with `ServeMux`, `http.route` from `r.Pattern` | The Logs API with `SetEventName`; `slog` can't. Map values move between releases |
| Ruby (Rack, Rails) | `OpenTelemetry::Instrumentation::Rack.current_span`, from a middleware after the instrumentation's | The logs SDK may reject map values: use dotted keys |
| Java (agent, Spring) | `Span.current()` in the first servlet filter, before the security chain; never in a controller | `getLogsBridge()` with `setEventName`, `AttributeKey.valueKey` for maps; Logback can't. Match `opentelemetry-api` to the agent |
| Functions (Lambda) | `get_current_span()` at handler entry, or a decorator on it | Flush every invocation |

### Changing the schema

The schema version is `"1"`: `trappsec.schema.version` on findings, `version` inside audit entries. Add attributes freely under `trappsec`; renaming or removing one, or changing its meaning, raises the version. `user.*`, `session.id` and `security_rule.*` are still in Development in OpenTelemetry's semantic conventions: if one is renamed, follow it and raise the version.
<!-- END COMMON CORE -->

## Audit records

An audit record is what customers see in an audit log, export to their own SIEM and hand to auditors as evidence, so it is complete on its own: it reads the same whether or not its trace was kept, and whether or not the action ran in a request.

### Names

Event names are `trappsec.audit.<area>.<action>`, in lower snake case and the product's own language: `trappsec.audit.book.member_role_changed`, `trappsec.audit.auth.sign_in`, `trappsec.audit.export.started`. One name per action, whatever path triggered it; the outcome is part of the entry, never a separate name.

### The entry

The record has two attributes: `trappsec.audit`, holding the whole entry as a map, and `log.record.uid`, set to the entry's `id`. The entry repeats what the server span says about the caller on purpose: it is evidence and must stand without the span. One recording module fills both from the same values.

| Key | Required | Value |
|---|---|---|
| `id` | Always | A unique, time-sortable ID (a ULID or UUIDv7; a few lines of code, no new dependency), to deduplicate and page through the log |
| `time` | Always | When it happened, UTC, ISO 8601 with milliseconds |
| `version` | Always | `"1"` |
| `action` | Always | The event name without `trappsec.audit.`, such as `book.member_role_changed` |
| `operation` | Always | Starting vocabulary: `create`, `read`, `update`, `delete`, `share`, `export`, `grant`, `revoke`, `approve`, `reject`, `execute`, `authenticate`, `configure` |
| `outcome` | Always | `result` (`success`, `denied`, `failure`; below), and a machine-readable `reason` when it isn't a success |
| `actor` | Always | Who actually did it: `type` (`user`, `service`, `integration`, `agent`), `id`, and `name` at the time. For an unknown login or a rejected token, `type` alone (`unknown` if even that isn't known); for an unattended job, `service` and the job's identity |
| `tenant` | Always | The organization or workspace: `id` and `name`; omitted when the request never reached one |
| `origin` | Always | `ip`, `user_agent`, `session_id`, and `credential` (`type`, `id` when it has one; never the secret). A job has `host` and `job_id` instead, with the service's credential; a script or admin tool a person runs has `host`, with the operator as the actor |
| `resource` | When it applies | The main object acted on: `type`, `id`, and `name` at the time |
| `on_behalf_of` | When it applies | The account the action counted as, when that isn't the actor (the person an agent works for, the customer a support engineer impersonated): `id` and `name` |
| `approved_by` | When it applies | The person who approved an agent's action: `id` and `name` |
| `related` | When it applies | Other objects in the action, each with a `role`, `type`, `id` and `name`: a move's source and destination, a transfer's new owner |
| `participants` | When it applies | People or groups affected, with `id` and `name`: share recipients, the member whose role changed |
| `changes` | On success | Before and after per field, `{ "<field>": { "old": …, "new": … } }`, in their own types, arrays for sets. No `old` for a first value, never an empty string; `{ "redacted": true }` for a field too sensitive to record. A denial or failure changed nothing: what was asked for goes in `params` |
| `impact` | When it applies | `count` of items affected, read or exported |
| `authz` | When it applies | The `permission` evaluated, for authorization decisions |
| `params` | When it applies | Anything specific to this action, declared in the registry: a sign-in's method and MFA, an export's format |

- **Outcomes.** `success` once the state committed, whatever the response shows. `denied` when the app refused because of who the caller is: not signed in, a missing permission or role, a quota of their plan, approving their own request, another tenant's object (even when answered as a 404 or a validation error; one lookup to tell it from a deleted object is allowed). `failure` for everything else: a wrong password or rejected token, a bad request or CSRF token, validation, the target's own state (a balance, a status), a missing object, a conflict, an error.
- **Names are as they were at the time**, so an entry reads correctly after a rename or deletion. Cache nothing that ends up in an entry; a long-lived process would record a stale name.
- **Personal data.** Where a regulation covers the people named (a patient under HIPAA; anyone under GDPR when the user asks for IDs only, since write-once storage and erasure conflict), record IDs and resolve names at read time. Data revealing health, family or other special categories (a leave type that means sick leave) never goes in `changes` or `params`. Retention of `origin.ip` and `origin.user_agent` is the pipeline owner's call: say so in the report.
- **Justifications.** One the user had to give (a break-glass reason, a required refund note) is recorded, truncated: it is the evidence. Optional notes and other free text are content and stay out. Under a regulation covering what users type, ask whether the justification goes in the entry or stays in the app with its row ID in `params`.
- **Delegated and deferred actions.** An action that commits after the request that asked for it (an approved deploy a worker runs, a queued export) records that request's `actor`, `on_behalf_of` and `approved_by`, stored with the work (adding them to the queued item is expected; tell the user), and its `origin` is where it committed. The queuing request records refusals and failures; the success is recorded where the work commits, and the approval is its own action. When several requests together complete something (the last signer), the completion belongs to the request whose commit made it true. A consumer that may see a message twice emits only from the commit that changed the row.
- **Bulk paths.** A job or script applying one action to many objects gets its own registry action (`invoice.bulk_voided`) with `impact.count`, one entry per tenant per run, and its per-item changes emit nothing.
- **Sign-ins.** The actor is the account the attempt targeted, when it exists; a failed attempt records its `id` only, its origin and the reason, never the login that was typed.
- **Never sampled, written once.** The backend stores audit records exactly as received.
- **No display sentence.** The UI builds "Priya changed Sam's role" from the entry, so it can be translated.

A role change:

```json
{
  "trappsec.audit": {
    "id": "01JAB7Q3M2V8K4T0R6YHXN5C1D",
    "time": "2026-10-20T08:55:12.204Z",
    "version": "1",
    "action": "book.member_role_changed",
    "operation": "update",
    "outcome": { "result": "success" },
    "actor": { "type": "user", "id": "usr_07Lm", "name": "Priya Raman" },
    "tenant": { "id": "firm_9kd2", "name": "Hartley & Co" },
    "origin": {
      "ip": "203.0.113.40",
      "user_agent": "Mozilla/5.0 (Macintosh; …)",
      "session_id": "sess_2b8e",
      "credential": { "type": "session", "id": "sess_2b8e" }
    },
    "resource": { "type": "book", "id": "bk_8Hq2", "name": "Hartley & Co, FY2026" },
    "participants": [{ "id": "usr_41xQ", "name": "Sam Okafor" }],
    "changes": { "role": { "old": "senior_accountant", "new": "accountant" } }
  },
  "log.record.uid": "01JAB7Q3M2V8K4T0R6YHXN5C1D"
}
```
