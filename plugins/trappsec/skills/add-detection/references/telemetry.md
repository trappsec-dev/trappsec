# Telemetry

What add-detection emits, and what it needs in place first. The common core is shared word for word with add-auditing and add-deception, and the findings core with add-deception, so records from all three line up.

<!-- BEGIN COMMON CORE: identical in add-auditing, add-deception and add-detection -->
## Prerequisite: OpenTelemetry traces and logs

These skills write to OpenTelemetry traces and logs together. Before designing anything, confirm the app already has:
- an OpenTelemetry SDK initialized at startup in every entry point that will emit (the web server, workers, each CLI or management command), with a tracer provider and a logger provider, both exported (usually OTLP to a Collector);
- HTTP server instrumentation, so every request has a server span carrying the request: `http.request.method`, `http.route`, `url.path`, `http.response.status_code`, `client.address`, `user_agent.original`;
- log records emitted during a request carrying that request's trace and span IDs (check with a record your own view code emits: a framework's error-response log line is often written after the request's span has ended);
- a way to emit a log record with an event name through the OpenTelemetry Logs API. Logging-library bridges (Python `logging`, Go `slog`, pino) often can't set one; the recording module then calls the Logs API directly, imported from the same API package the SDK registered with (a second copy, such as an older `@opentelemetry/api-logs`, silently drops every record). Confirm it end to end: emit one record and find it, with its event name and trace ID, where the app's telemetry lands. A framework that configures logging at startup (Django's `LOGGING`) can drop a handler attached before it.

If any of these is missing, stop.

Instrumentation that emits older attribute names (some need an opt-in, such as `OTEL_SEMCONV_STABILITY_OPT_IN=http` in Python, where `http/dup` keeps the old names too for existing dashboards) or leaves one out (Go's `otelhttp` with the standard `ServeMux` sets no `http.route`; Django's sets no `url.path`) is in place: don't stop for it. When you stop for something else, list these gaps in the same message. Otherwise the request-context module closes them as part of this work: set an opt-in the repo owns and tell the user, or write the missing attribute on the server span (Go: `r.Pattern` after the mux matched).

What this work may touch in the telemetry setup: a server request hook registered on the HTTP instrumentation, an opt-in setting, and attributes on the server span. Exporters, processors, samplers and the resource are the user's: ask first. Tell the user what you found and that this skill needs OpenTelemetry traces and logs in place first. Don't set them up as part of this work; offer to do it as a separate change.

Sampling belongs to the backend, not the app: every server span is exported, and the backend decides what to keep. If the app samples traces itself, findings from requests it drops can't be joined to their caller, and `trappsec.flagged` can't bring back a trace the app already dropped. Tell the user, and ask before changing the sampler (a parent-based, always-on sampler is the usual fix). Audit records don't depend on it.

## Common core

### Namespace

Event names and attributes these skills define live under the fixed `trappsec` namespace, the same in every app and service and for all three skills. Never invent attributes in OpenTelemetry's own namespaces.

`trappsec` appears only in attribute keys and event names: the string literals that spell them, the tests that assert them, and plans or docs that cite them are the only places it is written. Before you finish, search the source for it and remove any other occurrence. No attribute value, record body, logger name, rule or inventory ID, code identifier, comment or error message contains it: values show up in dashboards, tickets and searches, and code is read by teammates and sometimes by attackers. The recording code is named like the app's other observability code.

### Three kinds of record

Each fact is said once, where it is known.

| Record | Says | When |
|---|---|---|
| Request context, on the server span | Who called and from where | Once per request |
| Audit record, a log record | The complete audit entry: who did what, for whom, to what, from where, with what result | When an audited action succeeds, is denied or fails |
| Finding, a log record | Which deception or detection rule fired, on what, plus the tenant and account as routing keys | When a rule fires |

The backend joins each finding to its request's context by trace and span ID. Audit records are complete on their own and never depend on the join, the span or sampling.

### Request context

Set on the server span (the local root span the HTTP instrumentation creates) from the app's authenticated state, never from anything the caller sent. `client.address` and any missing request attribute are written as the request starts, before authentication, so requests that fail it carry them too. The identity attributes are written right after authentication; on the endpoint that authenticates (sign-in, token exchange), once the sign-in succeeds. A tenant the server resolved from a token or a row (an invitation being accepted) is set too; a tenant the caller merely named never is. Omit an attribute whose value is unknown; never set an empty string. One small module does it for all three skills: if another of these skills already added it, reuse it.

**Reaching the server span.** The current span in a handler is often a child (Express's request handler span, a database or framework span), not the server span. Capture the server span where it is known: the instrumentation's server request hook (Python's FastAPI and Django instrumentors take one; keep the span in the request), `getRPCMetadata(context.active()).span` in Node, `trace.SpanFromContext(r.Context())` in Go's outermost wrapper inside `otelhttp`, or the first middleware keeping it in the request context before any child starts. Write the request context and `trappsec.flagged` to that span, and emit findings in its context, so they carry its span ID.

| Span attribute | Type | Value |
|---|---|---|
| `user.id` | string | A stable ID for the account the request acted as; not an email. Absent for a credential no person holds (an integration's API key) |
| `user.name` | string | That account's login, when the app has one |
| `user.roles` | string[] | The roles that matter for authorization |
| `trappsec.tenant.id` | string | The organization or workspace the request acted in; in a single-tenant app, a fixed ID for the deployment |
| `session.id` | string | The session, when there is one. Never the cookie or session key itself, which is the bearer secret in most frameworks: a hash of it or the session's row ID |
| `trappsec.credential.type` | string | `session`, `token`, `api_key`, `oauth_client` or `service_account` |
| `trappsec.credential.id` | string | That credential's ID, so it can be revoked. Never the secret. |
| `trappsec.actor.type` | string | `user`, `service`, `integration` or `agent` |
| `trappsec.actor.id` | string | When someone or something acts as `user.id` (impersonation, support access, an agent working for a person), the real actor; for an integration with no `user.id`, its credential's ID |
| `trappsec.flagged` | boolean | `true` once any finding fires during the request, so the backend keeps the whole trace |

`client.address` must be the IP the app resolves through its trusted-proxy configuration. Many HTTP instrumentations take the first `X-Forwarded-For` entry, which the caller controls, or the proxy's own address. The request-context module writes the app's resolved IP to `client.address` on every request. If the app has no trusted-proxy setting, add the smallest one beside the module: take the entry the nearest trusted proxy appended, counting from the right, never the first, and tell the user how many proxies it assumes. If the app's own setting is wrong, report it and the setting that would fix it instead of changing proxy or infrastructure configuration yourself.

### Log records

- **One record per occurrence, emitted as an event.** The event name goes in the record's own event-name field, not an `event.name` attribute, and never contains dynamic values.
- **A dedicated logger per family**, named like the app's other loggers: audit records from one (for example `<app>.audit`), findings from another (for example `<app>.security`). The backend routes by logger and event name, so the two never mix with each other or with ordinary logs.
- **Inside the trace context of the request that caused it**, so the SDK stamps its trace and span IDs; under the app's existing resource (`service.name`, `service.version`, `deployment.environment.name`). Work outside a request (a job, a queue consumer, a script) starts a span of its own and records inside it.
- **With its timestamp set** when emitting; some SDKs leave it empty.
- **The body is a short fixed display string**, such as "member role changed". Everything else goes in attributes.
- **Severity:** audit records `INFO`; findings `WARN` when the caller is identified and `INFO` when anonymous.

### Intents

Findings carry one of these in `security_rule.category`: `reconnaissance`, `privilege_escalation`, `account_takeover`, `cross_tenant_access`, `data_exfiltration`, `cross_account_access`, `entitlement_abuse`, `payment_fraud`, `mass_assignment`, `parameter_tampering`, `workflow_tampering`, `defense_evasion`. `cross_tenant_access` is another organization's data; `cross_account_access` is another user's inside one; `parameter_tampering` is a value the client never offers. If none fits, add one to the inventory rather than force a rule into the nearest.

### Values

- Attacker-controlled strings are truncated to 1024 characters and arrays to 20 elements; objects become compact JSON text.
- No secrets anywhere (passwords, tokens, keys, session secrets), even when the caller submitted one. No document or message content. A secret in a URL path or query (a share link's token) reaches the server span through the instrumentation: on routes whose template holds one, the request-context module overwrites `url.path`, `url.full` and `url.query` with the route template, and tells the user.
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

<!-- BEGIN FINDINGS CORE: identical in add-deception and add-detection -->
## Findings

A finding carries what only the rule knows, and the two keys the backend needs to route and count it before joining it to the request context. Omit an attribute whose value is unknown.

| Attribute | Type | Value |
|---|---|---|
| `trappsec.schema.version` | string | `"1"` |
| `trappsec.tenant.id` | string | Routing key: the tenant the request acted in |
| `user.id` | string | Routing key: the account; absent when anonymous |
| `security_rule.name` | string | The rule's stable ID from the inventory |
| `security_rule.category` | string | Its intent |
| `trappsec.finding.field.name` | string | The honey field or impossible input |
| `trappsec.finding.field.value` | string | What was sent, as text; `[redacted]` when the input is a secret (a token, a password) |
| `trappsec.finding.resource.type`, `trappsec.finding.resource.id` | string | The object involved, such as another tenant's project |
| `trappsec.finding.params.<name>` | any | Anything specific to the rule, declared in the inventory |

When a finding fires, also set `trappsec.flagged` = `true` on the server span.

**No server span to join to.** When a finding fires outside a traced request (a job, a queue consumer, a script) or the server span isn't recording, the finding carries the request-context attributes itself, and `client.address` and `user_agent.original` when it has them.
<!-- END FINDINGS CORE -->

## Detection events

| Event name | When |
|---|---|
| `trappsec.detection.rule_hit` | An existing check rejected an input or state no real client can produce |

- `security_rule.name` is the rule's inventory ID and `security_rule.category` its intent.
- `trappsec.finding.field.*` names the impossible input, when one field carries it.
- `trappsec.finding.resource.*` names the object involved: the order refunded twice, the other tenant's project.
- `trappsec.finding.params.*` holds what a responder needs to judge the rule, when it is safe to record: the server's price behind a tampered total, the state the workflow was in.

The status the caller received is on the server span, and is whatever the app already answered.
