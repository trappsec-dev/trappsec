# Telemetry

What add-auditing emits, and what it needs in place first. The common core is shared word for word with add-deception and add-detection, so records from all three line up.

<!-- BEGIN COMMON CORE: identical in add-auditing, add-deception and add-detection -->
## Prerequisite: OpenTelemetry traces and logs

These skills write to OpenTelemetry traces and logs together. Before designing anything, confirm the app already has:
- an OpenTelemetry SDK initialized at startup, with a tracer provider and a logger provider, both exported (usually OTLP to a Collector);
- HTTP server instrumentation, so every request has a server span carrying the request: `http.request.method`, `http.route`, `url.path`, `http.response.status_code`, `client.address`, `user_agent.original`;
- log records emitted during a request carrying that request's trace and span IDs;
- a way to emit a log record with an event name through the OpenTelemetry Logs API. Logging-library bridges (Python `logging`, Go `slog`, pino) often can't set one; the recording module then calls the Logs API directly. Confirm it end to end: emit one record and find it, with its event name and trace ID, where the app's telemetry lands.

Instrumentation that emits older attribute names (some need an opt-in, such as `OTEL_SEMCONV_STABILITY_OPT_IN=http` in Python) or leaves one out (Go's `otelhttp` with the standard `ServeMux` sets no `http.route`) is in place: report the gap and the setting or small fix that closes it, and carry on.

If any of these is missing, stop. Tell the user what you found and that this skill needs OpenTelemetry traces and logs in place first. Don't set them up as part of this work; offer to do it as a separate change.

Sampling belongs to the backend, not the app: every server span is exported, and the backend decides what to keep. If the app samples traces itself, findings from requests it drops can't be joined to their caller, and `trappsec.flagged` can't bring back a trace the app already dropped. Tell the user, and ask before changing the sampler (a parent-based, always-on sampler is the usual fix). Audit records don't depend on it.

## Common core

### Namespace

Event names and attributes these skills define live under the fixed `trappsec` namespace, the same in every app and service and for all three skills. Never invent attributes in OpenTelemetry's own namespaces.

`trappsec` appears only in attribute keys and event names: the string literals that spell them, and tests that assert them, are the only places it is written. No attribute value, record body, logger name, rule or inventory ID, code identifier, comment or error message contains it: values show up in dashboards, tickets and searches, and code is read by teammates and sometimes by attackers. The recording code is named like the app's other observability code.

### Three kinds of record

Each fact is said once, where it is known.

| Record | Says | When |
|---|---|---|
| Request context, on the server span | Who called and from where | Once per request |
| Audit record, a log record | The complete audit entry: who did what, for whom, to what, from where, with what result | When an audited action succeeds, is denied or fails |
| Finding, a log record | Which deception or detection rule fired, on what, plus the tenant and account as routing keys | When a rule fires |

The backend joins each finding to its request's context by trace and span ID. Audit records are complete on their own and never depend on the join, the span or sampling.

### Request context

Set once per request on the server span (the local root span the HTTP instrumentation creates), right after authentication, from the app's authenticated state and never from anything the caller sent. On the endpoint that authenticates (sign-in, token exchange), set it once the sign-in succeeds. Omit an attribute whose value is unknown; never set an empty string. One small module does it for all three skills: if another of these skills already added it, reuse it.

**Reaching the server span.** The current span in a handler is often a child (Express's request handler span, a database or framework span), not the server span. Capture the server span where it is known: a server request hook of the instrumentation, `getRPCMetadata(context.active()).span` in Node, or the authentication middleware keeping it in the request context before any child starts. Write the request context and `trappsec.flagged` to that span, and emit findings in its context, so they carry its span ID.

| Span attribute | Type | Value |
|---|---|---|
| `user.id` | string | A stable ID for the account the request acted as; not an email |
| `user.name` | string | That account's login, when the app has one |
| `user.roles` | string[] | The roles that matter for authorization |
| `trappsec.tenant.id` | string | The organization or workspace the request acted in; in a single-tenant app, a fixed ID for the deployment |
| `session.id` | string | The session, when there is one |
| `trappsec.credential.type` | string | `session`, `token`, `api_key`, `oauth_client` or `service_account` |
| `trappsec.credential.id` | string | That credential's ID, so it can be revoked. Never the secret. |
| `trappsec.actor.type` | string | `user`, `service`, `integration` or `agent` |
| `trappsec.actor.id` | string | When someone or something acts as `user.id` (impersonation, support access, an agent working for a person), the real actor |
| `trappsec.flagged` | boolean | `true` once any finding fires during the request, so the backend keeps the whole trace |

`client.address` must be the IP the app resolves through its trusted-proxy configuration. Many HTTP instrumentations take the first `X-Forwarded-For` entry, which the caller controls, or the proxy's own address. When the server span's value differs from the app's resolved IP, the request-context module overwrites `client.address` with the app's value. If the app's own trusted-proxy setting is wrong, report it and the setting that would fix it instead of changing proxy or infrastructure configuration yourself.

### Log records

- **One record per occurrence, emitted as an event.** The event name goes in the record's own event-name field, not an `event.name` attribute, and never contains dynamic values.
- **A dedicated logger per family**, named like the app's other loggers: audit records from one (for example `<app>.audit`), findings from another (for example `<app>.security`). The backend routes by logger and event name, so the two never mix with each other or with ordinary logs.
- **Inside the trace context of the request that caused it**, so the SDK stamps its trace and span IDs; under the app's existing resource (`service.name`, `service.version`, `deployment.environment.name`). Work outside a request (a job, a queue consumer, a script) starts a span of its own and records inside it.
- **With its timestamp set** when emitting; some SDKs leave it empty.
- **The body is a short fixed display string**, such as "member role changed". Everything else goes in attributes.
- **Severity:** audit records `INFO`; findings `WARN` when the caller is identified and `INFO` when anonymous.

### Intents

Findings carry one of these in `security_rule.category`: `reconnaissance`, `privilege_escalation`, `account_takeover`, `cross_tenant_access`, `data_exfiltration`, `entitlement_abuse`, `payment_fraud`, `mass_assignment`, `workflow_tampering`, `defense_evasion`. If none fits, add one to the inventory rather than force a rule into the nearest.

### Values

- Attacker-controlled strings are truncated to 1024 characters and arrays to 20 elements; objects become compact JSON text.
- No secrets anywhere (passwords, tokens, keys, session secrets), even when the caller submitted one. No document or message content. A secret in a URL path or query (a share link's token) reaches the server span through the instrumentation: report it.
- Names of actions and rules, and intents, come from server code, never from the request. An ID the caller sent and the app rejected (another tenant's project, an object that doesn't exist) is recorded as what was sent, never as the actor or tenant.
- Each record is built from fresh values. Some SDKs drop a whole map-valued attribute without an error when it holds the same object twice (OpenTelemetry JS reads that as a cycle).
- Listed values are a starting vocabulary. Anything specific to one action or rule goes in its params, declared in the registry or inventory.

### Emitting

- Emitting never fails, blocks or changes a request: errors while recording are swallowed, and nothing waits on the network in the request path.
- Its cost is constant and small, whatever the request contains.
- A short-lived process (a script, a CLI command) flushes or shuts down its logger provider before it exits, on every exit path, or its records are lost.
- Each skill keeps one inventory or registry in server code of everything that emits, with stable IDs; records refer to those IDs.

### Changing the schema

The schema version is `"1"`: `trappsec.schema.version` on findings, `version` inside audit entries. Add attributes freely under `trappsec`. Renaming or removing one, or changing its meaning, raises the version.

`user.*`, `session.id` and `security_rule.*` are still in Development status in OpenTelemetry's semantic conventions. If OpenTelemetry renames one, follow it and raise the version.
<!-- END COMMON CORE -->

## Audit records

An audit record is what customers see in an audit log, export to their own SIEM and hand to auditors as evidence, so it is complete on its own. It reads the same whether or not its trace was kept, however long traces are retained, and whether or not the action ran in a request at all.

### Names

Event names are `trappsec.audit.<area>.<action>`, in lower snake case and the product's own language: `trappsec.audit.book.member_role_changed`, `trappsec.audit.auth.sign_in`, `trappsec.audit.export.started`. One name per action, whatever path triggered it. The outcome is part of the entry, never a separate name.

### The entry

The record has two attributes: `trappsec.audit`, holding the whole entry as a map, and `log.record.uid`, set to the entry's `id`. Everything critical is inside the map. It repeats what the server span says about the caller on purpose: the entry is evidence and must stand without the span. One recording module fills both from the same values.

| Key | Required | Value |
|---|---|---|
| `id` | Always | A unique, time-sortable ID (a ULID or a UUIDv7; a few lines in the app are fine, no new dependency), used to deduplicate and to page through the log |
| `time` | Always | When it happened, UTC, ISO 8601 with milliseconds |
| `version` | Always | `"1"` |
| `action` | Always | The event name without `trappsec.audit.`, such as `book.member_role_changed` |
| `operation` | Always | Starting vocabulary: `create`, `read`, `update`, `delete`, `share`, `export`, `grant`, `revoke`, `authenticate`, `configure`. Add a verb to the registry when none fits |
| `outcome` | Always | `result`, and a machine-readable `reason` when it isn't a success. `denied` when the app refused because of who the caller is (a permission, the tenant's scope, the plan); `failure` for everything else (validation, not found, conflict, error); `success` once it committed |
| `actor` | Always | Who actually did it: `type` (`user`, `service`, `integration`, `agent`), `id`, and `name` at the time. When no such account exists (a sign-in for an unknown login), `type` alone |
| `tenant` | Always | The organization or workspace: `id` and `name`. When the request never reached one, omit it |
| `origin` | Always | `ip`, `user_agent`, `session_id`, and `credential` (`type`, `id`; never the secret). For a job: `host` and `job_id` instead of the request's keys, with the service's credential. For a script or admin tool a person runs: `host`, and the operator as the actor |
| `resource` | When it applies | The main object acted on: `type`, `id`, and `name` at the time |
| `on_behalf_of` | When it applies | The account the action counted as, when that isn't the actor: the person an agent works for, the customer a support engineer impersonated. `id` and `name` |
| `approved_by` | When it applies | The person who approved an agent's action: `id` and `name` |
| `related` | When it applies | Other objects in the action, each with a `role`, `type`, `id` and `name`: a move's source and destination, a transfer's new owner |
| `participants` | When it applies | People or groups affected, with `id` and `name`: share recipients, the member whose role changed |
| `changes` | When it applies | Before and after values per field, `{ "<field>": { "old": …, "new": … } }`, in their own types, with arrays for sets such as permissions. A field too sensitive to record is `{ "redacted": true }`. Only on a success: a denial or failure changed nothing, so what was asked for goes in `params` when it matters |
| `impact` | When it applies | `count` of items affected, read or exported |
| `authz` | When it applies | The `permission` evaluated, for authorization decisions |
| `params` | When it applies | Anything specific to this action, declared in the registry: a sign-in's method and MFA, an export's format |

- **Names are as they were at the time**, so an entry still reads correctly after a rename or deletion. Where a name is itself regulated personal data (a patient's, under HIPAA), record the ID alone.
- **A justification the user had to give** (a break-glass reason, a refund note the policy requires) is recorded, truncated: it is the evidence. Other free text is content and stays out.
- **Delegated and deferred actions.** An action that commits later than the request that asked for it (a deploy a worker runs once approved, a queued export) records the `actor`, `on_behalf_of` and `approved_by` of that request, so they are stored with the work; its `origin` is where it committed. The approval itself is its own action.
- **Sign-ins:** the actor is the account the attempt targeted, when it exists. A failed attempt still records its origin and the outcome's reason, never the login that was typed.
- **Never sampled, written once.** The backend stores audit records exactly as received.
- **No display sentence.** The UI that shows an entry builds "Priya changed Sam's role" from it, so it can be translated.

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
