# Telemetry

What add-detection emits, and what it needs in place first. The common core is shared word for word with add-auditing and add-deception, and the findings core with add-deception, so records from all three line up.

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
