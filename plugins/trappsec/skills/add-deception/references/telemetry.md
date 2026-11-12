# Telemetry

What add-deception emits, and what it needs in place first. The common core is shared word for word with add-auditing and add-detection, and the findings core with add-detection, so records from all three line up.

<!-- BEGIN COMMON CORE: identical in add-auditing, add-deception and add-detection -->
## Prerequisite: OpenTelemetry traces and logs

These skills write to OpenTelemetry traces and logs together. Before designing anything, confirm the app already has:
<!-- BEGIN PREREQUISITE CORE: identical in add-auditing, add-deception, add-detection and add-telemetry -->
- an OpenTelemetry SDK with a tracer provider and a logger provider, both exported (usually OTLP to a Collector), initialized in every entry point that will emit: the web server, workers, each CLI, script or management command;
- a server span for every request, from HTTP server instrumentation or, on a function platform, the invocation span;
- log records emitted in a request carrying its trace and span IDs (test with a record your own code emits; framework access lines are often written after the span ends);
- a way to emit a log record with an event name through the Logs API.
<!-- END PREREQUISITE CORE -->

Confirm it end to end: emit one record from a throwaway probe request (delete it afterwards) and find it, with its event name and trace ID, where the app's telemetry lands. Turn the SDK's own error reporting up while you do (Learning the stack); most SDKs print nothing about a dropped record by default. On a function platform, probe with the process frozen after the response: a missing flush there is work this skill does (below), not a reason to stop.

If any of these is missing, stop. Tell the user what you found and that this skill needs OpenTelemetry traces and logs first, and offer to set them up with add-telemetry as a separate change, listing the gaps below in the same message.

**Gaps that don't stop the work.** The server span should carry `http.request.method`, `http.route`, `url.path`, `http.response.status_code`, `client.address` and `user_agent.original`. Where the instrumentation uses older names, leaves one out or fills one wrongly (a raw path in `http.route`), the request-context module writes the right attribute on the server span, or sets an opt-in the repo owns (Learning the stack), and tells the user.

**What this work may touch in the telemetry setup:** a server request hook, or where there is none a small middleware or filter running inside the server span; an opt-in; attributes on the server span; on a function platform, a flush per invocation. Everything else is the user's to decide, so report and ask: exporters, processors, samplers, the resource, inbound trace-context extraction, metric exemplars, and what other instrumentations capture.

**Sampling and inbound context.** If the app samples traces itself, findings from dropped requests can't be joined to their caller, and `security.flagged` can't bring a dropped trace back. Most instrumentations also take their parent from the caller's `traceparent`, so on a public entry point a caller can stop the server span being exported or choose its trace ID. Report either; the usual fixes are a parent-based always-on sampler and ignoring inbound context at public entry points. Audit records don't depend on this, and findings carry the request context themselves when the server span isn't recording.

## Common core

### Names

The names these skills define are the same in every app, so one query works across services:
- audit records: event names `audit.<area>.<action>`, with the entry in one attribute, `audit`;
- findings: one event name, `security.finding`, with `security.finding.kind` saying which kind fired and the details under `security.finding.*`, beside OpenTelemetry's `security_rule.*`;
- the request context on the server span: `tenant.id`, `credential.type`, `credential.id`, `actor.type`, `actor.id` and `security.flagged`, beside OpenTelemetry's `user.*`, `session.id` and `client.address`.

Use OpenTelemetry's own attributes as they are, and never invent new ones in its namespaces. Before writing a name, search the app and its telemetry for it: if the app already emits `audit.*` events or sets one of these attributes with another meaning, stop and ask the user rather than mix two meanings under one name. Name the recording code like the app's other observability code.

### Three kinds of record

Each fact is said once, where it is known.

| Record | Says | When |
|---|---|---|
| Request context, on the server span | Who called and from where | Once per request |
| Audit record, a log record | The complete audit entry: who did what, for whom, to what, from where, with what result | When an audited action succeeds, is denied or fails |
| Finding, a log record | Which deception or detection rule fired, on what, plus the tenant and account as routing keys | When a rule fires |

The backend joins each finding to its request's context by trace and span ID. Audit records stand on their own, without the join, the span or sampling. A request carrying several actions or findings (a GraphQL document, a batch) emits one record for each, all on the request's span.

### Request context

One small module, shared by all three skills (reuse it and its tests if another skill added it; each skill keeps its own inventory or registry), writes the request context on the server span from the app's own state, never from anything the caller sent:
- `client.address` and any missing request attribute as the request starts, so requests that fail authentication carry them too;
- identity once authentication has succeeded: right after it, or in a response hook while the span is open, which leaves authentication code alone. The endpoint that signs someone in writes it on success; a refusal raised before authentication writes what it knows;
- the tenant the server resolved (from the session, a token, a row it loaded, or an argument after its membership check), never one the caller merely named. A request acting in several keeps the first; each record carries its own.

Omit an attribute whose value is unknown; never write an empty string. A skill that finds the module already in place checks that it writes every attribute in the table below that the app knows (roles, the session's ID), and adds what is missing.

**Reaching the server span.** The current span in a handler is often a child (a controller, framework or database span). Capture the server span where it is known (Learning the stack), keep it in the request, write the context and `security.flagged` to it, and emit findings in its context so they carry its span ID. Operations over a long-lived connection (WebSocket, subscriptions) have no per-operation span: start a server-kind span for each.

| Span attribute | Type | Value |
|---|---|---|
| `user.id` | string | A stable ID for the account the request acted as; not an email. Absent for a credential no person holds |
| `user.name` | string | That account's login, unless it is personal data the user wants kept out |
| `user.roles` | string[] | The roles that matter for authorization |
| `tenant.id` | string | The organization or workspace acted in; a fixed ID in a single-tenant app |
| `session.id` | string | A hash or row ID of the session, never the cookie or key itself |
| `credential.type` | string | `session`, `token`, `api_key`, `oauth_client`, `service_account` or `link` (a signed or one-time URL) |
| `credential.id` | string | The credential's ID, so it can be revoked; omitted when it has none. Never the secret |
| `actor.type` | string | `user`, `service`, `integration` or `agent` |
| `actor.id` | string | The real actor when someone or something acts as `user.id` (impersonation, support access, an agent); an integration's credential ID when there is no `user.id` |
| `security.flagged` | boolean | `true` once any finding fires in the request, so the backend keeps the trace |

**`client.address`** is the address that connected to the outermost proxy the app trusts, and the module writes it on every request, replacing the instrumentation's (many take the first `X-Forwarded-For` entry, which the caller controls):
- the platform's own source-address field where the caller can't write it, never a forwarding header. A CDN's client-IP header is a forwarding header like any other;
- otherwise the framework's own trusted-proxy resolver, reporting what it trusts by default. Its setting is the app's own: set it to the proxies' address ranges rather than a hop count where it allows that, and say so. Edge, load balancer and CDN configuration stays the user's;
- otherwise the smallest setting beside the module: the entry the nearest trusted proxy appended, counting from the right. That is safe only if the app can't be reached except through those proxies; ask, and tell the user what it assumes;
- an IP literal, or else the connection's own address.

If the app's own setting is wrong, report it and its fix rather than changing proxy or infrastructure configuration. To verify, call the app's resolver in a test with an untrusted peer address and a forged `X-Forwarded-For`; where it can't be called directly, send the forged header through a stand-in proxy that appends the connecting address, from a client address the app's trust setting doesn't trust (another machine, or this one's LAN address; when loopback is trusted, so is every `127.x` address): the recorded IP is the client's. A direct request alone proves nothing.

### Log records

- **One record per occurrence, emitted as an event**, with the event name in the record's event-name field (never an `event.name` attribute) and no dynamic values in it.
- **A dedicated logger per family**, named like the app's others: audit records from one (`<app>.audit`), findings from another (`<app>.security`), so the backend can route them apart from each other and from ordinary logs.
- **In the trace context of the request that caused it**, under the app's existing resource. Work outside a request (a job, a consumer, a script) records in the span its instrumentation starts, or starts one: one per message for a batch consumer. Work a request starts in-process inherits its context; start it detached, with a link, when it should stand alone.
- **With its timestamp set**; some SDKs leave it empty.
- **The body is a short fixed label** naming the action or rule ("change member role"), true whatever the outcome; everything else goes in attributes.
- **Severity:** audit records `INFO`; findings as their own section says.

### Values

- Attacker-controlled strings are cut to 1024 characters and arrays to 20 elements; objects become compact JSON within a fixed budget of nodes and depth. A request document or raw body is recorded as its length and a hash.
- No secrets (passwords, tokens, keys, session secrets, signed links), even when the caller sent one, and no document or message content. Personal data the user asked to keep out (emails and names of people under GDPR) is treated the same: an ID, or `[redacted]` for a value.
- Action and rule names and intents come from server code. An ID the caller sent and the app rejected is recorded as what was sent, never as the actor or tenant.
- Build each record from fresh values: some SDKs silently drop a map attribute that holds the same object twice. Where the SDK has no map value or rejects one, write dotted keys under the attribute's name (`audit.actor.id`) and tell the user.
- Listed values are a starting vocabulary; anything specific to one action or rule goes in its declared params. Where one endpoint carries several operations (GraphQL, JSON-RPC), `operation` there names the one recorded.

**Secrets in URLs.** On routes whose path or query holds a secret, the module overwrites each server-span attribute the instrumentation filled from the URL (whichever of `url.path`, `url.full`, `url.query`, `http.target`, `http.url`, `http.route` the exported span carries; never add absent ones): the path with the route template, which may only be known after routing, and the value of each query key that names a secret with a fixed marker, keeping the others. Then search every exported signal for a real token (child and outbound spans, span events, the app's logs, and metric exemplars, which also carry the raw `client.address`) and report what only a user setting can stop (exemplars: `OTEL_METRICS_EXEMPLAR_FILTER=always_off`).

### Emitting

- Emitting never fails, blocks or changes a request: errors are swallowed, and nothing waits on the network in the request path.
- Its cost is constant and small, whatever the request contains.
- A short-lived process flushes or shuts down its tracer and logger providers on every exit path.
- A function platform that freezes the process after the response needs a logger flush as the last step of every invocation, error paths included: the one network wait these skills allow, bounded by the exporter's timeout. Tell the user, and suggest a local Collector or extension.
- Each skill keeps one inventory or registry in server code of everything that emits, with stable IDs that records refer to.

### Learning the stack

These skills name no stack's APIs, because they change between releases and an app on a stack nobody listed deserves the same result. Learn them for this app from the OpenTelemetry project's current documentation, then confirm each version-specific answer (hook timing, constructor shapes, option names) in the installed SDK and instrumentation code. The installed code, the type checker and the probe overrule the documentation and any example here. In the plan, give the answers that shaped a design choice, with their source:

- **Reaching the server span.** Where code that runs during the request can hold the server span itself rather than the current child: the instrumentation's request hook, a lookup the SDK provides for the server span, or the outermost wrapper or middleware running just inside the instrumentation. Capture it there, before framework or security code starts child spans, and keep it on the request. Identity known only later (after an authentication filter, in a sign-in success or sign-out handler) is written to the captured span from there.
- **Once the response is known.** Where code runs after the response status is set while the server span is still open: a response hook, or a wrapper of the response's end in the module's own middleware. A hook's name doesn't say when it runs: read where the instrumentation calls it.
- **What your hook receives.** Whether the code you hook gets the model, a serialized response or a framework wrapper, and whether the framework calls its own handlers internally (one endpoint calling another, a pipeline a job invokes), so one action can pass the hook twice.
- **Emitting an event.** Which API emits a log record with an event name. It is usually the Logs API from the same API package the SDK registered; a logging library's bridge often can't set one. A second copy of the API package, at another version or under another name, can register nothing and drop every record without an error.
- **Map values.** Whether the SDK accepts a map as an attribute value, or rejects or silently drops one; where it doesn't take maps, write dotted keys.
- **Matching versions.** The API package at the version the running SDK or agent expects (an agent reports its own as `telemetry.sdk.version` on the resource), pinned through the app's dependency management.
- **Attribute names.** Whether the HTTP instrumentation writes the stable semantic conventions by default, or has an opt-in the repo owns.
- **The SDK's own errors.** How it reports them (an environment variable some SDKs read and others ignore, or its own logger), so you can turn them up while you probe.
- **Constructor shapes.** Constructors and option names change between major releases, and a wrong shape often builds a component that silently does nothing (an exporter passed where an options object is expected). Take them from the installed code, and let the type checker and the probe confirm them.
- **Function platforms.** The invocation span is the active span at handler entry, or comes from a wrapper of the handler; request attributes come from the event the platform passes (its method, source address, user agent and route); the tracer and logger providers are flushed in the handler wrapper, and some instrumentations must be handed the tracer provider to flush the invocation span.

Every answer is then proven by the end-to-end probe above, which is the authority: a record that doesn't arrive with its event name, or a finding without the server span's ID, means an answer is wrong, whatever the documentation said.

### Changing the schema

The schema version is `"1"`: `security.schema.version` on findings, `version` inside audit entries. Add attributes freely under `audit` and `security.finding`; renaming or removing one, or changing its meaning, raises the version. `user.*`, `session.id` and `security_rule.*` are still in Development in OpenTelemetry's semantic conventions: if one is renamed, follow it and raise the version.
<!-- END COMMON CORE -->

<!-- BEGIN FINDINGS CORE: identical in add-deception and add-detection -->
## Findings

Every finding is emitted as the event `security.finding`. It carries what only the rule knows, and the two keys the backend needs to route and count it before joining it to the request context. Omit an attribute whose value is unknown.

| Attribute | Type | Value |
|---|---|---|
| `security.schema.version` | string | `"1"` |
| `security.finding.kind` | string | `rule` for a detection rule; `decoy_route` or `honey_field` for a deception tripwire |
| `tenant.id` | string | Routing key: the tenant the request acted in |
| `user.id` | string | Routing key: the account; absent when anonymous |
| `security_rule.name` | string | The rule's stable ID from the inventory |
| `security_rule.category` | string | Its intent |
| `security.finding.field.name` | string | The honey field or impossible input |
| `security.finding.field.value` | string | What was sent, as text; `[redacted]` when the inventory marks the field secret (a token, a password, a signed link) or personal data the user keeps out |
| `security.finding.resource.type`, `security.finding.resource.id` | string | The object involved, such as another tenant's project |
| `security.finding.params.<name>` | any | Anything specific to the rule, declared in the inventory |

Severity is `WARN` when the caller is identified (a user or a credential), `INFO` when anonymous. When a finding fires, also set `security.flagged` = `true` on the server span. One request can trip a deception tripwire and a detection rule on different fields; each is its own finding. One tripwire may watch several fields of one intent; each field present is its own finding. One input never fires two rules.

**No server span to join to.** When a finding fires outside a traced request (a job, a queue consumer, a script) or the server span isn't recording, the finding carries the request-context attributes itself, and `client.address` and `user_agent.original` when it has them.

### Intents

Findings carry one of these in `security_rule.category`: `reconnaissance`, `privilege_escalation`, `account_takeover`, `cross_tenant_access` (another organization's data), `cross_account_access` (another user's, inside one), `data_exfiltration`, `entitlement_abuse`, `payment_fraud`, `mass_assignment` (a field the handler must not honor), `parameter_tampering` (a value the client never offers, in a field the handler reads), `workflow_tampering`, `defense_evasion`. Where privilege or entitlement is the evident aim, that intent wins. If none fits, add one to the inventory.
<!-- END FINDINGS CORE -->

## Deception findings

| `security.finding.kind` | When | Finding attributes it uses |
|---|---|---|
| `decoy_route` | A decoy route was called | `security.finding.resource.*` when the path names an object |
| `honey_field` | A honey field arrived with a value real clients never send | `security.finding.field.*`, and `security.finding.resource.*` for the object the request targeted |

`security_rule.name` is the tripwire's inventory ID and `security_rule.category` its intent.
