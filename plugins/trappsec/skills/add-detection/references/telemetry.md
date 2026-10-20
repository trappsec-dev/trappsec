# Telemetry

What add-detection emits, and what it needs in place first. The common core is shared word for word with the add-auditing and add-deception skills, so events from all three line up.

<!-- BEGIN COMMON CORE: identical in add-auditing, add-deception and add-detection -->
## Prerequisite: OpenTelemetry logs

Everything these skills record travels as OpenTelemetry log records. Before designing anything, confirm the app already has:
- an OpenTelemetry SDK initialized at startup, with a logger provider and an exporter for log records (usually OTLP to a Collector). Traces alone are not enough;
- log records emitted while handling a request carrying that request's trace context.

If either is missing, stop. Tell the user what you found and that this skill needs OpenTelemetry logs in place first. Don't set it up as part of this work; offer to do it as a separate change.

## Common core

### Namespace

Event names and attributes these skills define live under the fixed `trappsec` namespace, the same in every app and service and for all three skills, so one schema serves every app. Never invent attributes in OpenTelemetry's own namespaces.

`trappsec` appears only in attribute keys and event names. No attribute value, record body, rule or inventory ID, code identifier, comment or error message contains it: values show up in dashboards, tickets and searches, and code is read by teammates and sometimes by attackers. The recording code is named like the app's other observability code.

### The event

- One log record per occurrence, emitted as an event: the event name identifies what happened. Set it in the log record's own event name field, not as an `event.name` attribute, which is deprecated. Event names never contain dynamic values.
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

Some standard attributes used here are still in Development status in OpenTelemetry's semantic conventions (`user.*`, `session.id`, `security_rule.*`) and may be renamed. When one is, or when OpenTelemetry standardizes something defined here under `trappsec` (tenants, credentials, actors, audit events), move to the standard name and raise `trappsec.schema.version`.
<!-- END COMMON CORE -->

## Detection events

| Event name | When |
|---|---|
| `trappsec.detection.rule_hit` | An existing check rejected an input or state no real client can produce |

Severity is `WARN` when the caller is identified and `INFO` when anonymous. `trappsec.outcome` and `http.response.status_code` record what the caller received, which is whatever the app already answered.

| Attribute | Type | Value |
|---|---|---|
| `security_rule.ruleset.name` | string | `detection` |
| `security_rule.name` | string | The rule's ID from the inventory |
| `security_rule.category` | string | The rule's intent |
| `trappsec.detection.operation` | string | The domain operation the check guards, such as `order.refund` |
| `trappsec.detection.field.name` | string | The field or parameter whose value was impossible, if one |
| `trappsec.detection.field.location` | string | `body`, `query`, `header` or `path` |
| `trappsec.detection.field.value` | string | The submitted value, as text |
| `trappsec.detection.expected` | string | What a real client would have sent, when it is safe to record (the server's price, the allowed options) |
| `trappsec.detection.resource.type`, `trappsec.detection.resource.id` | string | The object involved, when the rule concerns one (the order refunded twice, the other tenant's project) |
