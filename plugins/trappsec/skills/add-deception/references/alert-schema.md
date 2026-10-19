# Alert schema

Every tripwire emits the same event, in every app and every language, so one set of detection rules, dashboards and routing works everywhere. The schema is expressed as OpenTelemetry. Version 1.

## The event

One OpenTelemetry log record per hit, emitted as an event:

| Field | Value |
|---|---|
| Event name | `deception.decoy_hit` (a decoy route), `deception.field_hit` (a honey field) or `deception.rule_hit` (a value the real UI never offers) |
| Severity | `WARN` when the caller is identified, `INFO` when anonymous |
| Body | A short fixed description, such as `decoy route hit`. Never put request data in the body; it belongs in attributes. |
| Trace context | The trace and span of the request that tripped it, so the alert links to the rest of that request's telemetry. |
| Resource | The app's existing resource: at least `service.name` and `deployment.environment.name`. |

Emit it through the OpenTelemetry SDK the app already uses. If the app has none, write the same event as one JSON log line through the app's logger, with the event name in `event.name`, the severity in `severity`, the trace and span IDs in `trace_id` and `span_id` when known, the resource attributes, and every attribute below under its exact name. A collector can then map both forms to the same record.

## Attributes

Use standard OpenTelemetry attributes wherever one exists, and the `deception.` namespace for the rest. Omit an attribute when its value is unknown; never send an empty string as a placeholder.

### Always

| Attribute | Type | Value |
|---|---|---|
| `deception.schema.version` | string | `"1"` |
| `deception.tripwire.id` | string | The tripwire's stable ID from the app's inventory. Never shown to clients. |
| `deception.kind` | string | `decoy_route`, `honey_field` or `value_rule` |
| `deception.intent` | string | One value from the intent list below |
| `deception.attributed` | boolean | `true` when the caller is identified |
| `http.request.method` | string | Request method |
| `http.route` | string | The route template, such as `/api/v2/books/{bookId}` |
| `url.path` | string | The requested path |
| `client.address` | string | The client IP, resolved as described in implementation.md §6 |
| `user_agent.original` | string | The User-Agent header |

### The caller, when identified

| Attribute | Type | Value |
|---|---|---|
| `user.id` | string | A stable ID for the account, not an email or display name |
| `user.roles` | string[] | The roles that matter for this route: account roles, or the caller's role in the tenant in the path |
| `deception.tenant.id` | string | The organization or workspace the caller acted in |
| `deception.credential.type` | string | `session`, `token`, `api_key` or `service_account` |
| `deception.credential.id` | string | The ID of that session, token or key, so it can be revoked. Never the secret. |
| `deception.actor.id` | string | When someone acts as `user.id` (impersonation, support access), the real person behind the request |

### By kind

| Attribute | Kind | Type | Value |
|---|---|---|---|
| `deception.field.name` | `honey_field`, `value_rule` | string | The field or parameter name |
| `deception.field.location` | `honey_field`, `value_rule` | string | `body`, `query` or `header` |
| `deception.field.value` | `honey_field`, `value_rule` | string | The submitted value as text, truncated |
| `http.response.status_code` | all | int | The status the caller received |
| `deception.request.id` | all | string | The app's own request ID, if it logs one besides the trace ID |

## Intents

`reconnaissance`, `privilege_escalation`, `account_takeover`, `cross_tenant_access`, `data_exfiltration`, `entitlement_abuse`, `payment_fraud`, `mass_assignment`, `defense_evasion`. If the team already has a security vocabulary, map these to it in the alerting rules, not in the events.

## Values

- Attacker-controlled strings are truncated to 1024 characters, and arrays to 20 elements. Objects become compact JSON text.
- No secrets in any attribute: no passwords, tokens, keys or session secrets, even when the caller submitted one.
- The tripwire ID, kind and intent come from server code, never from the request.

## Changing the schema

Add attributes freely in the `deception.` namespace. Renaming or removing one, or changing its meaning, is a new `deception.schema.version`.
