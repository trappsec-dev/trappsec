---
layout: default
title: Event Reference
permalink: /events/
tagline: "Schema and fields for every event emitted by trappsec."
---

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
| `user_agent` | String or null | The User-Agent string from the request (over 1024 characters: the first 1024 followed by `...`). |
| `ip` | String or null | The source IP address. |
| `app` | Object | Application context containing `service`, `environment`, and `hostname`. |
| `user` | String or null | The user ID, if identified. Always present, also on signals. |
| `role` | String or null | The user role, if identified. Always present, also on signals. |

**All keys are always present.** Each event carries exactly the common fields plus its own specific fields below; no other keys appear. A value that is absent is `null`, never omitted, so receivers can rely on a stable schema. `path` is truncated like `user_agent`: the first 1024 characters followed by `...`. Serialization never fails: values that are not JSON-native are stringified.

## Event Types

### `trap_hit`

Generated when a request matches a defined **Trap** (honey trap).

#### Specific Fields

| Field | Type | Description |
|---|---|---|
| `intent` | String or null | The intent configured for this trap (e.g., "account_takeover"). |

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
| `type` | String | Where the field was found: `"query"` or `"body"`. |
| `field` | String | The name of the field. |
| `value` | Any | The sanitized value that triggered the match (see [Value sanitization](#value-sanitization)). |
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
| `intent` | String or null | The intent associated with this rule. |
| `metadata` | Object or null | Additional custom context provided during the trigger. |

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

### `heartbeat`

Sent only to webhook handlers configured with `heartbeat_interval`. It lets a receiver detect a sensor that has gone silent. Heartbeats are not alerts and are not affected by `alerts_only`.

```json
{
  "timestamp": 1706501000.0,
  "event": "trappsec.heartbeat",
  "service": "billing-api",
  "environment": "production"
}
```

With multiple workers, every worker sends its own heartbeat; see [Production](/production/#multiple-workers-and-heartbeats).

## Value sanitization

`found_fields[].value` is sanitized before being recorded, so an attacker cannot make events huge or unserializable:

| Input | Recorded as |
|---|---|
| null, bool, number | unchanged |
| string | truncated to 1024 characters, with `...` appended |
| list | first 20 elements, each sanitized |
| object / map | compact JSON string with sorted keys and no HTML escaping (`{"a":1,"b":"<x>"}`), truncated to 1024 characters with `...` appended |
| anything else (file uploads, bytes) | the type name, e.g. `"<UploadFile>"` |

## Value matching

A watch with a default value fires when the request value differs from it. Comparison is canonical and identical in every language:

*   Equal values match.
*   Numbers match numerically and booleans are never numbers: `1` matches `1.0`; `true` does not match `1`.
*   A string matches a bool/number when it equals that value's canonical form: `"true"`/`"false"` (lowercase), `"5"` (not `"5.0"`); other floats as JavaScript writes them (`"0.1"`, `"1e-7"`, `"1e+21"`), identically in every SDK. So a form field `is_admin=false` matches a default of `false`.
*   Strings compare exactly (no trimming, no case folding): `"False"` does **not** match `false`.
*   **Duplicate keys** (`?role=user&role=admin`, repeated form fields): one value is compared as a scalar; with several, the request is a violation unless every value matches. All occurrences are stripped.
*   **JSON keys**: Python and Node match keys case-sensitively. Go matches case-insensitively (`IsAdmin`, `is_admin` and `IS_ADMIN` all hit), because `encoding/json` binds struct fields that way.
*   A top-level JSON array is inspected element by element (objects only); scalars and other shapes are skipped without error.

## Handlers

| Handler | Notes |
|---|---|
| Log | Always on. One JSON line per event on the `trappsec` logger. trappsec never configures logging globally; attach your own handler. |
| Webhook | `add_webhook`. Raw event JSON (or your `template` output) via `POST`. Asynchronous, see below. |
| Slack | `add_slack`. Slack-formatted message; `&`, `<`, `>` in request-derived values are escaped; always has a non-empty `text` fallback. |
| OpenTelemetry | `add_otel`. Span event attributes are strings, bools, ints, floats or homogeneous arrays of those. Nulls are dropped; everything else is stringified. |

### alerts_only

Webhook and Slack handlers default to `alerts_only=true`: events with `type="signal"` (no identified user) are **dropped** for that handler. The Log and OpenTelemetry handlers receive everything. Set `alerts_only=false` to forward signals too. Heartbeats are unaffected.

## Webhook signing

When a `secret` is configured, every webhook request (events and heartbeats) carries:

| Header | Value |
|---|---|
| `x-trappsec-timestamp` | Unix time in integer seconds when the request was signed. |
| `x-trappsec-signature` | `sha256=` followed by the hex HMAC-SHA256 of `"<timestamp>.<raw body>"` using the secret as key. |

Verify against the **raw bytes** of the body, with a constant-time comparison, and reject stale timestamps to stop replays (5 minutes is a sensible window; tolerate clock skew). Receivers that also want strict replay protection should remember recently seen signatures for the window.

<div class="lang-switcher">
  <button class="lang-btn active" onclick="switchLang('python')">Python</button>
  <button class="lang-btn" onclick="switchLang('node')">Node.js</button>
  <button class="lang-btn" onclick="switchLang('go')">Go</button>
</div>

<div class="lang-content" data-lang="python" markdown="1">

```python
import hmac, hashlib, time

def verify(secret: str, headers: dict, raw_body: bytes, window=300) -> bool:
    ts = headers.get("x-trappsec-timestamp", "")
    sig = headers.get("x-trappsec-signature", "")
    if not ts.isdigit() or abs(time.time() - int(ts)) > window:
        return False
    expected = "sha256=" + hmac.new(
        secret.encode(), ts.encode() + b"." + raw_body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, sig)
```

</div>
<div class="lang-content" data-lang="node" markdown="1">

```javascript
const crypto = require("crypto");

function verify(secret, headers, rawBody /* Buffer */, windowSec = 300) {
  const ts = headers["x-trappsec-timestamp"] || "";
  const sig = headers["x-trappsec-signature"] || "";
  if (!/^\d+$/.test(ts) || Math.abs(Date.now() / 1000 - Number(ts)) > windowSec) return false;
  const expected = "sha256=" + crypto.createHmac("sha256", secret)
    .update(`${ts}.`).update(rawBody).digest("hex");
  const a = Buffer.from(expected), b = Buffer.from(sig);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
```

</div>
<div class="lang-content" data-lang="go" markdown="1">

```go
func verify(secret string, h http.Header, body []byte, window time.Duration) bool {
    ts, err := strconv.ParseInt(h.Get("x-trappsec-timestamp"), 10, 64)
    if err != nil || time.Since(time.Unix(ts, 0)).Abs() > window {
        return false
    }
    mac := hmac.New(sha256.New, []byte(secret))
    mac.Write([]byte(strconv.FormatInt(ts, 10) + "."))
    mac.Write(body)
    expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
    return hmac.Equal([]byte(expected), []byte(h.Get("x-trappsec-signature")))
}
```

</div>

> **Upgrading:** earlier versions sent a bare hex digest of the body in `x-trappsec-signature` with no timestamp. Update receivers to the format above.

### Delivery semantics

Delivery is asynchronous through a bounded queue (1000 events); when full, events are dropped with a rate-limited warning. At most 2 retries with short backoff. Receivers should be idempotent and return 2xx quickly; non-2xx responses are only logged. Call `close()` on shutdown to flush.
