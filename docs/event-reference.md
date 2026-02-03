---
layout: default
title: Event Reference
nav_order: 6
permalink: /events/
---

# Event Reference

This page details the schema for the events emitted by trappsec. These events are sent to all configured handlers (Log, Webhook, OpenTelemetry).

All events share a common set of fields, with specific details added depending on the event type (`trap_hit`, `watch_hit`, or `rule_hit`).

## Common Fields

Every event includes the following fields:

| Field | Type | Description |
|---|---|---|
| `timestamp` | Float | Unix timestamp of when the event occurred. |
| `event` | String | The event name (e.g., `trappsec.trap_hit`). |
| `type` | String | `signal` for unauthenticated events, `alert` if user context is present. |
| `path` | String | The HTTP path of the request. |
| `method` | String | The HTTP method (GET, POST, etc.). |
| `user_agent` | String | The User-Agent string from the request. |
| `ip` | String | The source IP address. |
| `app` | Object | Application context containing `service`, `environment`, and `hostname`. |
| `user` | String (Optional) | The user ID, if identified. |
| `role` | String (Optional) | The user role, if identified. |

## Event Types

### `trap_hit`

Generated when a request matches a defined **Trap** (honey trap).

#### Specific Fields

| Field | Type | Description |
|---|---|---|
| `intent` | String | The intent configured for this trap (e.g., "account_takeover"). |

#### Sample Payload

```json
{
  "timestamp": 1706500000.123,
  "event": "trappsec.trap_hit",
  "type": "alert",
  "path": "/admin/backup.sql",
  "method": "GET",
  "user_agent": "Mozilla/5.0 ...",
  "ip": "203.0.113.42",
  "app": {
    "service": "billing-api",
    "environment": "production",
    "hostname": "worker-01"
  },
  "user": "alice_admin",
  "role": "admin",
  "intent": "database_exfiltration"
}
```

### `watch_hit`

Generated when a **Watch** detects honey tokens or specific field values in the request body.

#### Specific Fields

| Field | Type | Description |
|---|---|---|
| `found_fields` | Array | List of intercepted fields that triggered the watch. |

**found_fields**

| Field | Type | Description |
|---|---|---|
| `type` | String | The type of field (e.g., "body"). |
| `field` | String | The name of the field. |
| `value` | Any | The value that triggered the match. |
| `intent` | String | The intent associated with this specific field rule. |

#### Sample Payload

```json
{
  "timestamp": 1706500123.456,
  "event": "trappsec.watch_hit",
  "type": "signal",
  "path": "/api/v1/login",
  "method": "POST",
  "user_agent": "curl/7.68.0",
  "ip": "198.51.100.12",
  "app": {
    "service": "auth-service",
    "environment": "production",
    "hostname": "auth-01"
  },
  "found_fields": [
    {
      "type": "body",
      "field": "is_admin",
      "value": true,
      "intent": "privilege_escalation"
    }
  ]
}
```

### `rule_hit`

Generated when a custom business logic rule is manually triggered using `trigger()`.

#### Specific Fields

| Field | Type | Description |
|---|---|---|
| `reason` | String | The reason provided for triggering the rule. |
| `intent` | String (Optional) | The intent associated with this rule. |
| `metadata` | Object (Optional) | Additional custom context provided during the trigger. |

#### Sample Payload

```json
{
  "timestamp": 1706500987.654,
  "event": "trappsec.rule_hit",
  "type": "alert",
  "path": "/api/v1/transfer",
  "method": "POST",
  "user_agent": "Mozilla/5.0 ...",
  "ip": "203.0.113.88",
  "app": {
    "service": "banking-app",
    "environment": "production",
    "hostname": "api-02"
  },
  "user": "bob_user",
  "role": "customer",
  "reason": "Velocity limit exceeded for transfers",
  "intent": "fraud_attempt",
  "metadata": {
    "transfer_amount": 50000,
    "currency": "USD"
  }
}
```
