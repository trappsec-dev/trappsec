# Telemetry

What add-deception emits, and what it needs in place first. The common core is shared word for word with add-auditing and add-detection, and the findings core with add-detection, so records from all three line up.

<!-- BEGIN COMMON CORE: identical in add-auditing, add-deception and add-detection -->
## Prerequisite: OpenTelemetry traces and logs

These skills write to OpenTelemetry traces and logs together. Before designing anything, confirm the app already has:
- an OpenTelemetry SDK initialized at startup, with a tracer provider and a logger provider, both exported (usually OTLP to a Collector);
- HTTP server instrumentation, so every request has a server span carrying the request: `http.request.method`, `http.route`, `url.path`, `http.response.status_code`, `client.address`, `user_agent.original`;
- log records emitted during a request carrying that request's trace and span IDs.

If any of these is missing, stop. Tell the user what you found and that this skill needs OpenTelemetry traces and logs in place first. Don't set them up as part of this work; offer to do it as a separate change.

Sampling belongs to the backend, not the app: every server span is exported, and the backend decides what to keep. If the app samples traces itself, findings from requests it drops can't be joined to their caller. Tell the user, and ask before changing the sampler. Audit records don't depend on it.

## Common core

### Namespace

Event names and attributes these skills define live under the fixed `trappsec` namespace, the same in every app and service and for all three skills. Never invent attributes in OpenTelemetry's own namespaces.

`trappsec` appears only in attribute keys and event names. No attribute value, record body, logger name, rule or inventory ID, code identifier, comment or error message contains it: values show up in dashboards, tickets and searches, and code is read by teammates and sometimes by attackers. The recording code is named like the app's other observability code.

### Three kinds of record

Each fact is said once, where it is known.

| Record | Says | When |
|---|---|---|
| Request context, on the server span | Who called and from where | Once per request |
| Audit record, a log record | The complete audit entry: who did what, for whom, to what, from where, with what result | When an audited action succeeds, is denied or fails |
| Finding, a log record | Which deception or detection rule fired, on what, plus the tenant and account as routing keys | When a rule fires |

The backend joins each finding to its request's context by trace and span ID. Audit records are complete on their own and never depend on the join, the span or sampling.

### Request context

Set once per request on the server span (the local root span the HTTP instrumentation creates), right after authentication, from the app's authenticated state and never from anything the caller sent. One small module does it for all three skills: if another of these skills already added it, reuse it.

| Span attribute | Type | Value |
|---|---|---|
| `user.id` | string | A stable ID for the account the request acted as; not an email |
| `user.name` | string | That account's login, when the app has one |
| `user.roles` | string[] | The roles that matter for authorization |
| `trappsec.tenant.id` | string | The organization or workspace the request acted in |
| `session.id` | string | The session, when there is one |
| `trappsec.credential.type` | string | `session`, `token`, `api_key`, `oauth_client` or `service_account` |
| `trappsec.credential.id` | string | That credential's ID, so it can be revoked. Never the secret. |
| `trappsec.actor.type` | string | `user`, `service`, `integration` or `agent` |
| `trappsec.actor.id` | string | When someone or something acts as `user.id` (impersonation, support access, an agent working for a person), the real actor |
| `trappsec.flagged` | boolean | `true` once any finding fires during the request, so the backend keeps the whole trace |

`client.address` must be the IP the app resolves through its trusted-proxy configuration. If the instrumentation reads a forwarding header the app doesn't trust, or records a proxy's address, report it and the setting that would fix it instead of changing proxy or infrastructure configuration yourself.

### Log records

- **One record per occurrence, emitted as an event.** The event name goes in the record's own event-name field, not an `event.name` attribute, and never contains dynamic values.
- **A dedicated logger per family**, named like the app's other loggers: audit records from one (for example `<app>.audit`), findings from another (for example `<app>.security`). The backend routes by logger and event name, so the two never mix with each other or with ordinary logs.
- **Inside the trace context of the request that caused it**, so the SDK stamps its trace and span IDs; under the app's existing resource (`service.name`, `service.version`, `deployment.environment.name`).
- **The body is a short fixed display string**, such as "member role changed". Everything else goes in attributes.
- **Severity:** audit records `INFO`; findings `WARN` when the caller is identified and `INFO` when anonymous.

### Intents

Findings carry one of these in `security_rule.category`: `reconnaissance`, `privilege_escalation`, `account_takeover`, `cross_tenant_access`, `data_exfiltration`, `entitlement_abuse`, `payment_fraud`, `mass_assignment`, `defense_evasion`. If none fits, add one to the inventory rather than force a rule into the nearest.

### Values

- Attacker-controlled strings are truncated to 1024 characters and arrays to 20 elements; objects become compact JSON text.
- No secrets anywhere (passwords, tokens, keys, session secrets), even when the caller submitted one. No document or message content.
- IDs, names of actions and rules, and intents come from server code, never from the request.
- Listed values are a starting vocabulary. Anything specific to one action or rule goes in its params, declared in the registry or inventory.

### Emitting

- Emitting never fails, blocks or changes a request: errors while recording are swallowed, and nothing waits on the network in the request path.
- Its cost is constant and small, whatever the request contains.
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
| `trappsec.finding.field.value` | string | What was sent, as text |
| `trappsec.finding.resource.type`, `trappsec.finding.resource.id` | string | The object involved, such as another tenant's project |
| `trappsec.finding.params.<name>` | any | Anything specific to the rule, declared in the inventory |

When a finding fires, also set `trappsec.flagged` = `true` on the server span.

**No server span to join to.** When a finding fires outside a traced request (a job, a queue consumer, a script) or the active span isn't recording, the finding carries the request-context attributes itself, and `client.address` and `user_agent.original` when it has them.
<!-- END FINDINGS CORE -->

## Deception events

| Event name | When | Finding attributes it uses |
|---|---|---|
| `trappsec.deception.decoy_hit` | A decoy route was called | `trappsec.finding.resource.*` when the path names an object |
| `trappsec.deception.field_hit` | A honey field arrived with a value real clients never send | `trappsec.finding.field.*`, and `trappsec.finding.resource.*` for the object the request targeted |

`security_rule.name` is the tripwire's inventory ID and `security_rule.category` its intent.
