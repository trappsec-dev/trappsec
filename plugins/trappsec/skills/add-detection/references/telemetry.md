# Telemetry

What add-detection emits, and what it needs in place first. The common core is shared word for word with add-auditing and add-deception, and the findings core with add-deception, so records from all three line up.

<!-- BEGIN COMMON CORE: identical in add-auditing, add-deception and add-detection -->
## Prerequisite: OpenTelemetry traces and logs

These skills write to OpenTelemetry traces and logs together. Before designing anything, confirm the app already has:
- an OpenTelemetry SDK initialized in every entry point that will emit (the web server, workers, each CLI, script or management command), with a tracer provider and a logger provider, both exported (usually OTLP to a Collector);
- a server span for every request: from HTTP server instrumentation, or on a function platform the invocation span the platform instrumentation creates;
- log records emitted during a request carrying that request's trace and span IDs. Check with a record your own code emits: a framework's access or error log line is often written after the request's span has ended, and says nothing about this;
- a way to emit a log record with an event name through the OpenTelemetry Logs API (see the stack notes below).

Confirm it end to end: emit one record from a request and find it, with its event name and trace ID, where the app's telemetry lands. Read the SDK's own error output while you do.

If any of these is missing, stop. Tell the user what you found and that this skill needs OpenTelemetry traces and logs in place first. Don't set them up as part of this work; offer to do it as a separate change. In the same message, list the gaps below that you would otherwise close.

**Gaps that don't stop the work.** The server span should carry `http.request.method`, `http.route`, `url.path`, `http.response.status_code`, `client.address` and `user_agent.original`. Instrumentation often emits older names (`http.method`, `http.target`), leaves one out, or fills one with a wrong value (a function platform's `http.route` holding the raw path). The request-context module closes these as part of this work: it writes the missing or wrong attribute on the server span, or sets an opt-in the repo owns (Python: `OTEL_SEMCONV_STABILITY_OPT_IN=http/dup`, which keeps the old names for existing dashboards), and tells the user.

**What this work may touch in the telemetry setup:** a server request hook on the instrumentation, or where it has none, a small middleware or filter running inside the server span; an opt-in setting; attributes on the server span; and, on a function platform, a flush at the end of each invocation. Everything else is the user's, and you report and ask: exporters, processors, samplers, the resource, inbound trace-context extraction, metric exemplars, and what other instrumentations capture.

**Sampling and inbound context.** Every server span should be exported and the backend decide what to keep. If the app samples traces itself, findings from requests it drops can't be joined to their caller, and `trappsec.flagged` can't bring back a trace the app already dropped. Most instrumentations also take their parent from the caller's `traceparent` header, so on a public entry point a caller can stop the server span from being exported or pick its trace ID. Tell the user about either, and ask before changing them (a parent-based, always-on sampler, and ignoring inbound context at public entry points, are the usual fixes). Audit records don't depend on any of this; findings carry the request context themselves when the server span isn't recording (below).

## Common core

### Namespace

Event names and attributes these skills define live under the fixed `trappsec` namespace, the same in every app and service and for all three skills. Never invent attributes in OpenTelemetry's own namespaces.

`trappsec` is written only in the string literals that spell attribute keys and event names (a named constant holding one is fine), in tests that assert them, and in plans or docs that cite them. No identifier, file or package name, comment, logger name, rule or inventory ID, record body, attribute value or error message contains it: values show up in dashboards, tickets and searches, and code is read by teammates and sometimes by attackers. The recording code is named like the app's other observability code. Before you finish, search the source for it, or add a test that strips string literals and finds none.

### Three kinds of record

Each fact is said once, where it is known.

| Record | Says | When |
|---|---|---|
| Request context, on the server span | Who called and from where | Once per request |
| Audit record, a log record | The complete audit entry: who did what, for whom, to what, from where, with what result | When an audited action succeeds, is denied or fails |
| Finding, a log record | Which deception or detection rule fired, on what, plus the tenant and account as routing keys | When a rule fires |

The backend joins each finding to its request's context by trace and span ID. Audit records are complete on their own and never depend on the join, the span or sampling. One request can carry several actions or findings (a GraphQL document, a batch); each is its own record, and all share the request's span.

### Request context

Set on the server span from the app's authenticated state, never from anything the caller sent. One small module does it for all three skills: if another of these skills already added it, reuse it, with its inventory and tests.

- **When.** `client.address` and any missing request attribute are written as the request starts, before authentication, so requests that fail it carry them too. The identity attributes are written once authentication has succeeded: right after it, or in a response hook while the span is still open, which touches no authentication code. The endpoint that authenticates (a sign-in, a token exchange, a login mutation) writes them when the sign-in succeeds. A refusal raised before authentication runs writes what it knows itself.
- **Tenant.** One the server resolved from the session, a token or a row (an invitation being accepted) is set; one the caller merely named never is. Where the tenant is an argument of the operation, set it after the membership check. A request that acts in several keeps the first, and each record carries its own.
- **Omit an attribute whose value is unknown**; never set an empty string.

**Reaching the server span.** The current span in a handler is often a child (a framework's controller or handler span, a database span), and which children exist can depend on instrumentation settings. Capture the server span where it is known, keep it in the request, and write the request context and `trappsec.flagged` to it; emit findings in its context, so they carry its span ID. The stack notes below say where. Operations over a long-lived connection (WebSocket, GraphQL subscriptions) have no per-operation span: start a server-kind span per operation.

| Span attribute | Type | Value |
|---|---|---|
| `user.id` | string | A stable ID for the account the request acted as; not an email. Absent for a credential no person holds (an integration's API key) |
| `user.name` | string | That account's login, when the app has one and it isn't personal data the user asked to keep out |
| `user.roles` | string[] | The roles that matter for authorization |
| `trappsec.tenant.id` | string | The organization or workspace the request acted in; in a single-tenant app, a fixed ID for the deployment |
| `session.id` | string | The session, when there is one. Never the cookie or session key itself, which is the bearer secret in most frameworks: a hash of it or the session's row ID |
| `trappsec.credential.type` | string | `session`, `token`, `api_key`, `oauth_client`, `service_account` or `link` (a signed or one-time URL whose holder is unknown) |
| `trappsec.credential.id` | string | That credential's ID, so it can be revoked. Never the secret. Omit it when the credential has none |
| `trappsec.actor.type` | string | `user`, `service`, `integration` or `agent` |
| `trappsec.actor.id` | string | When someone or something acts as `user.id` (impersonation, support access, an agent working for a person), the real actor; for an integration with no `user.id`, its credential's ID |
| `trappsec.flagged` | boolean | `true` once any finding fires during the request, so the backend keeps the whole trace |

**`client.address`** is the address of whoever connected to the first proxy the app trusts, and the request-context module writes it on every request:
- Where the platform hands the app that address (API Gateway's `requestContext.http.sourceIp`), use it and never read forwarding headers.
- Where the framework has a resolver (Rails `request.remote_ip`, Express `trust proxy`, Werkzeug `ProxyFix`, uvicorn `--forwarded-allow-ips`), use it, and report what it trusts by default.
- Where the app has none, add the smallest one beside the module: the entry the nearest trusted proxy appended, counting from the right, never the first.
- Counting from the right is safe only if the app can be reached solely through those proxies; a direct request with a forged header is otherwise believed. Ask whether the origin is reachable directly, and tell the user what the setting assumes.
- The value is an IP literal; anything else (`unknown`, a host name) falls back to the connection's address.
- Many HTTP instrumentations take the first `X-Forwarded-For` entry, which the caller controls; the module's value replaces theirs. If the app's own setting is wrong, report it and the setting that would fix it instead of changing proxy or infrastructure configuration yourself.

### Log records

- **One record per occurrence, emitted as an event.** The event name goes in the record's own event-name field, not an `event.name` attribute, and never contains dynamic values.
- **A dedicated logger per family**, named like the app's other loggers: audit records from one (for example `<app>.audit`), findings from another (for example `<app>.security`). The backend routes by logger and event name, so the two never mix with each other or with ordinary logs.
- **Inside the trace context of the request that caused it**, so the SDK stamps its trace and span IDs; under the app's existing resource (`service.name`, `service.version`, `deployment.environment.name`). Work outside a request (a job, a queue consumer, a script) records inside the span its instrumentation already starts, or starts one if there is none: one per message for a consumer that handles a batch. Work started from a request in the same process inherits that request's context; start it detached, with a link, when it should stand alone.
- **With its timestamp set** when emitting; some SDKs leave it empty.
- **The body is a short fixed display string**, such as "member role changed". Everything else goes in attributes.
- **Severity:** audit records `INFO`; findings `WARN` when the caller is identified (a user or a credential) and `INFO` when anonymous.

### Intents

Findings carry one of these in `security_rule.category`: `reconnaissance`, `privilege_escalation`, `account_takeover`, `cross_tenant_access`, `cross_account_access`, `data_exfiltration`, `entitlement_abuse`, `payment_fraud`, `mass_assignment`, `parameter_tampering`, `workflow_tampering`, `defense_evasion`.
- `cross_tenant_access` is another organization's data; `cross_account_access` is another user's inside one.
- `mass_assignment` is a field the handler must not honor; `parameter_tampering` is a value outside what the client offers, in a field the handler reads. Where escalating privilege or entitlement is the evident aim, that intent wins.
- If none fits, add one to the inventory rather than force a rule into the nearest.

### Values

- Attacker-controlled strings are truncated to 1024 characters and arrays to 20 elements; objects become compact JSON text, built within a fixed budget of nodes and depth. A request document or body (a GraphQL query, a raw payload) is recorded as its length and a hash, never its text.
- No secrets anywhere (passwords, tokens, keys, session secrets, signed links), even when the caller submitted one. No document or message content.
- Names of actions and rules, and intents, come from server code, never from the request. An ID the caller sent and the app rejected (another tenant's project, an object that doesn't exist) is recorded as what was sent, never as the actor or tenant.
- Each record is built from fresh values. Some SDKs drop a whole map-valued attribute without an error when it holds the same object twice (OpenTelemetry JS reads that as a cycle). Where the SDK has no map value, or rejects one, write the entry as dotted keys under its attribute's name (`trappsec.audit.actor.id`) and tell the user.
- Listed values are a starting vocabulary. Anything specific to one action or rule goes in its params, declared in the registry or inventory. On an endpoint that carries several operations (GraphQL, JSON-RPC), `operation` in those params names the one recorded.

**Secrets in URLs.** On routes whose path or query holds a secret (a share link's token), the request-context module overwrites every server-span attribute the instrumentation filled from the URL, under whatever name: `url.path`, `url.full`, `url.query`, `http.target`, `http.url`, `http.route`. The path becomes the route template, which is often known only after routing (write it again then, or match a fixed list of prefixes at the start), and the query a fixed marker. Unmatched routes keep their path. Then search every exported signal for a real token: child and outbound client spans, metric exemplars, span events and the app's own logs often carry the same URL. What you can't overwrite there is a setting the user owns: report it with the setting that would fix it.

### Emitting

- Emitting never fails, blocks or changes a request: errors while recording are swallowed, and nothing waits on the network in the request path.
- Its cost is constant and small, whatever the request contains.
- A short-lived process (a script, a CLI command) flushes or shuts down its tracer and logger providers before it exits, on every exit path, or its records are lost.
- On a function platform that freezes the process once the response is returned, the module flushes the logger provider as the last step of every invocation, error paths included: the one wait on the network these skills allow. The exporter's timeout bounds it; tell the user, and suggest a local collector or extension so the wait stays on the machine.
- Each skill keeps one inventory or registry in server code of everything that emits, with stable IDs; records refer to those IDs. Skills sharing the module share its inventory and the test that every entry has a marker.

### Stack notes

Where the generic advice above has a known shape. Check each against the versions in use.

| Stack | Server span | Event name and map values |
|---|---|---|
| Python (FastAPI, Django, Flask) | The instrumentor's request hook (`server_request_hook`, `request_hook`); keep the span on the request (`request.state`, `flask.g`) | `get_logger(name).emit(...)` with `event_name`; the `logging` bridge can't set it |
| Node | `getRPCMetadata(context.active()).span` | `logs` from `@opentelemetry/api`, the package the SDK registered; a separate `@opentelemetry/api-logs` copy drops every record |
| Go | `trace.SpanFromContext(r.Context())` in the outermost wrapper inside `otelhttp`; with `ServeMux`, write `http.route` from `r.Pattern` | The Logs API with `SetEventName`; `slog` can't. Map values have moved between releases: check the version's API |
| Ruby (Rack, Rails) | `OpenTelemetry::Instrumentation::Rack.current_span`, from a middleware after the instrumentation's | The logs SDK may log an error for map values: use dotted keys |
| Java (agent, Spring) | `Span.current()` in the first servlet filter, ordered before the security chain; never in a controller | `getLogsBridge()` with `setEventName`; `AttributeKey.valueKey` for maps; a Logback appender can't. Align `opentelemetry-api` with the agent, not the framework's BOM |
| Functions (Lambda) | `get_current_span()` at handler entry, or a decorator on the handler | Flush at the end of every invocation (Emitting) |

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
| `trappsec.finding.field.value` | string | What was sent, as text; `[redacted]` when the inventory marks the field secret (a token, a password, a signed link) |
| `trappsec.finding.resource.type`, `trappsec.finding.resource.id` | string | The object involved, such as another tenant's project |
| `trappsec.finding.params.<name>` | any | Anything specific to the rule, declared in the inventory |

When a finding fires, also set `trappsec.flagged` = `true` on the server span. One request can trip a deception tripwire and a detection rule on different fields; each is its own finding. One input never fires two rules.

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
