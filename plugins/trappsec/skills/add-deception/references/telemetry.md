# Telemetry

What add-deception emits, and what it needs in place first. The common core is shared word for word with the add-auditing and add-detection skills, so events from all three line up.

<!-- BEGIN COMMON CORE: identical in add-auditing, add-deception and add-detection -->
## Prerequisite: OpenTelemetry logs

Everything these skills record travels as OpenTelemetry log records. Before designing anything, confirm the app already has:
- an OpenTelemetry SDK initialized at startup, with a logger provider and an exporter for log records (usually OTLP to a Collector). Traces alone are not enough;
- log records emitted while handling a request carrying that request's trace context.

If either is missing, stop. Tell the user what you found and that this skill needs OpenTelemetry logs in place first. Don't set it up as part of this work; offer to do it as a separate change.

## Common core

### Namespace

Event names and attributes these skills define live under the fixed `trappsec` namespace, the same in every app and service and for all three skills, so one set of queries and detections works everywhere. Never invent attributes in OpenTelemetry's own namespaces.

### The event

- One log record per occurrence, emitted as an event: the event name identifies what happened.
- Emitted inside the trace context of the request that caused it.
- Under the app's existing resource, which identifies at least `service.name`, `service.version` and `deployment.environment.name`.
- The body is a short fixed description. Request data goes in attributes, never in the body.
- Every event carries `trappsec.schema.version` = `"1"`.

### Attributes every event carries when known

Standard OpenTelemetry attributes where one exists; `trappsec.*` for the rest. Omit an attribute whose value is unknown.

| Attribute | Type | Value |
|---|---|---|
| `http.request.method`, `http.route`, `url.path` | string | The request, with the route template in `http.route` |
| `http.response.status_code` | int | The status the caller received |
| `client.address` | string | The client IP the app resolves through its trusted-proxy configuration; never a forwarding header read directly |
| `user_agent.original` | string | The User-Agent header |
| `trappsec.request.id` | string | The app's own request ID, if it has one besides the trace ID |
| `user.id` | string | A stable ID for the account the request acted as; not an email or display name |
| `user.roles` | string[] | The roles that matter for the operation |
| `trappsec.tenant.id` | string | The organization or workspace the request acted in |
| `trappsec.actor.type` | string | `user`, `service`, `integration` or `agent` |
| `trappsec.actor.id` | string | When someone acts as `user.id` (impersonation, support access, an agent acting for a person), the real actor |
| `session.id` | string | The session the request belongs to |
| `trappsec.credential.type` | string | `session`, `token`, `api_key`, `oauth_client` or `service_account` |
| `trappsec.credential.id` | string | The ID of that credential, so it can be revoked. Never the secret. |
| `trappsec.credential.scopes` | string[] | The credential's scopes, when it has them |
| `trappsec.outcome` | string | `success`, `failure` or `denied` |
| `error.type` | string | A machine-readable reason when the outcome isn't `success` |

Who and from where always come from the app's authenticated state and its proxy configuration, never from anything the caller sent.

### Intents

Events that flag suspected abuse carry one of these in `security_rule.category`: `reconnaissance`, `privilege_escalation`, `account_takeover`, `cross_tenant_access`, `data_exfiltration`, `entitlement_abuse`, `payment_fraud`, `mass_assignment`, `defense_evasion`.

### Values

- Attacker-controlled strings are truncated to 1024 characters and arrays to 20 elements; objects become compact JSON text.
- No secrets in any attribute (passwords, tokens, keys, session secrets), even when the caller submitted one. No document or message content.
- IDs, kinds and intents that describe the rule or action come from server code, never from the request.

### Emitting

- Emitting never fails, blocks or changes a request: errors while recording are swallowed, and nothing waits on the network in the request path.
- Its cost is constant and small, whatever the request contains.
- Each skill keeps one inventory in server code of everything that emits, with stable IDs; events refer to those IDs.

### Changing the schema

Add attributes freely under `trappsec`. Renaming or removing one, or changing its meaning, raises `trappsec.schema.version`.
<!-- END COMMON CORE -->

## Deception events

| Event name | When |
|---|---|
| `trappsec.deception.decoy_hit` | A decoy route was called |
| `trappsec.deception.field_hit` | A honey field arrived with a value real clients never send |

Severity is `WARN` when the caller is identified and `INFO` when anonymous.

| Attribute | Type | Value |
|---|---|---|
| `security_rule.ruleset.name` | string | `deception` |
| `security_rule.name` | string | The tripwire's ID from the inventory |
| `security_rule.category` | string | The tripwire's intent |
| `trappsec.deception.kind` | string | `decoy_route` or `honey_field` |
| `trappsec.deception.field.name` | string | For honey fields: the field or parameter name |
| `trappsec.deception.field.location` | string | For honey fields: `body`, `query` or `header` |
| `trappsec.deception.field.value` | string | For honey fields: the submitted value, as text |
