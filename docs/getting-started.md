---
layout: default
title: Getting Started
nav_order: 2
permalink: /getting-started/
---

<div class="lang-switcher">
  <button class="lang-btn active" onclick="switchLang('python')">Python</button>
  <button class="lang-btn" onclick="switchLang('node')">Node.js</button>
</div>

# Getting Started

{: .note }
> **Just want to run code?** Check out the [Ultra Quickstart](/ultra-quickstart/) to copy-paste and run locally.

## installation

<div class="lang-content" data-lang="python" markdown="1">

```bash
pip install trappsec
```

</div>
<div class="lang-content" data-lang="node" markdown="1">

```bash
npm install trappsec
```

</div>

## initialization

Initialize the Sentry in your application. This is the main entry point for defining your traps.

<div class="lang-content" data-lang="python" markdown="1">

```python
import trappsec
# app is your Flask or FastAPI instance
ts = trappsec.Sentry(app, service="PaymentService", environment="Production")
```

</div>
<div class="lang-content" data-lang="node" markdown="1">

```javascript
const { Sentry } = require('trappsec');
// app is your Express instance
const ts = new Sentry(app, "PaymentService", "Production");
```

</div>



## deception primitives

We currently support two core primitives: **Decoy Routes** and **Honey Fields**. Each primitive should be paired with a lure strategy (bait, breadcrumbs, etc.) to effectively attract attackers.

### 1. Decoy Routes
Fake endpoints that are not part of your real API but are designed to blend in. When a request hits a decoy route, trappsec intercepts it, sends a realistic dummy response, and generates a high-fidelity alert.

#### Adaptive Responses
Traps can adapt to the attacker's authentication status. Real APIs protect sensitive endpoints, so your traps should too. you can configure what responses to send for authentication and unauthenticated scenarios so that it mirrors a real API and nudges attackers to use credentials to identify themselves. The framework uses a default response template for unauthenticated requests that must be overridden to match your application behavior.

<div class="lang-content" data-lang="python" markdown="1">

```python
# Static response
ts.trap("/deployment/config") \
    .methods("GET") \
    .intent("Reconnaissance") \
    .respond(200, {"region": "us-east-1", "deployment_type": "production"}) \
    .if_unauthenticated(401, {"error": "Login Required"})

# Dynamic response
import random
ts.trap("/deployment/metrics") \
    .methods("GET") \
    .intent("Reconnaissance") \
    .respond(200, lambda r: {"cpu": f"{random.randint(5, 95)}%", "memory": f"{random.randint(20, 90)}%"})

```

</div>
<div class="lang-content" data-lang="node" markdown="1">

```javascript
// Static response
ts.trap("/deployment/config")
    .methods("GET")
    .intent("Reconnaissance")
    .respond({ status: 200, body: { "region": "us-east-1", "deployment_type": "production" } })
    .if_unauthenticated({ status: 401, body: { "error": "Login Required" } });

// Dynamic response
ts.trap("/deployment/metrics")
    .methods("GET")
    .intent("Reconnaissance")
    .respond({
        status: 200,
        body: (req) => ({
            "cpu": `${Math.floor(Math.random() * 90) + 5}%`,
            "memory": `${Math.floor(Math.random() * 70) + 20}%`
        })
    });
```

</div>

#### Response Templates
You can define reusable templates for common responses (e.g., deprecated API errors).

<div class="lang-content" data-lang="python" markdown="1">

```python
ts.template("deprecated_api", 410, {"error": "Gone", "message": "API v1 is deprecated"})

ts.trap("/api/v1/users").methods("GET").respond(template="deprecated_api")
```

</div>
<div class="lang-content" data-lang="node" markdown="1">

```javascript
ts.template("deprecated_api", 410, { "error": "Gone", "message": "API v1 is deprecated" });

ts.trap("/api/v1/users").methods("GET").respond({ template: "deprecated_api" });
```

</div>

### 2. Honey Fields
Fake fields or parameters that appear contextually relevant. trappsec monitors these fields on legitimate routes. It can alert on the specific *presence* of a field or if its value *deviates* from a default.

{: .note }
> Unlike traps, watches do **not** tamper with the response. The request proceeds to your application logic normally. Only the alert is triggered.

<div class="lang-content" data-lang="python" markdown="1">

```python
# Alert if 'role' is present (regardless of value)
ts.watch("/api/profile/update").body("role", intent="Privilege Escalation")

# Alert if 'role' is present AND not equal to 'user'
ts.watch("/auth/register") \
    .body("role", default="user", intent="Role Tampering")
```

</div>
<div class="lang-content" data-lang="node" markdown="1">

```javascript
// Alert if 'role' is present
ts.watch("/api/profile/update").body("role", { intent: "Privilege Escalation" });

// Alert if 'role' is present AND not equal to 'user'
ts.watch("/auth/register")
    .body("role", { defaultValue: "user", intent: "Role Tampering" });
```

</div>

## baiting & lures

{: .note }
> **How do attackers find these traps?** 
> 
> Simply defining a trap isn't enough; you need to make sure attackers stumble upon them. Check out the [Baiting & Lures](./baiting-and-lures.md) guide to learn how to plant effective clues (like hidden frontend comments or legacy API mirrors) that lead attackers into your traps.

## attribution
To make alerts actionable, we need to know *who* is attacking.

<div class="lang-content" data-lang="python" markdown="1">

```python
# Extract user info from your authentication middleware (e.g. Flask-Login, JWT)
ts.identify_user(lambda r: {
    "user_id": getattr(r.user, "id", None), # assuming request.user is set
    "role": getattr(r.user, "role", "guest")
})

# Handle proxies / load balancers
ts.override_source_ip(lambda r: r.headers.get("x-real-ip", r.remote_addr))
```

</div>
<div class="lang-content" data-lang="node" markdown="1">

```javascript
// Extract user info from your authentication middleware (e.g. Passport, Clerk)
ts.identify_user((req) => ({
    "user_id": req.user?.id,
    "role": req.user?.role || "guest"
}));

ts.override_source_ip((req) => req.headers["x-real-ip"] || req.ip);
```

</div>

---

## alerts & integrations
trappsec can integrate directly into your existing workflows. Events are written to your standard logging handlers by default, but can be configured to also integrate into **OpenTelemetry** for observability or **Webhooks** to trigger automated responses or notify security teams.

### Webhooks
Send alerts to Slack, Discord, or custom incident response tools.

<div class="lang-content" data-lang="python" markdown="1">

```python
ts.add_webhook("https://hooks.slack.com/services/...")
```

</div>
<div class="lang-content" data-lang="node" markdown="1">

```javascript
ts.add_webhook("https://hooks.slack.com/services/...");

</div>

### OpenTelemetry
Enrich your OTEL spans with trappsec metadata to track attacks in your existing observability platform (Jaeger, Honeycomb, Datadog).

<div class="lang-content" data-lang="python" markdown="1">
ts.add_otel()
```

</div>
<div class="lang-content" data-lang="node" markdown="1">

```javascript
ts.add_otel();
```

</div>

## default responses
You can globally configure how trappsec responds to events. This is useful for maintaining consistency across all your traps without repeating configuration.

There are two default profiles you can override:
1.  **authenticated**: Used when `respond()` is not configured (defaults to `200 OK` with empty JSON).
2.  **unauthenticated**: Used when `if_unauthenticated()` is not configured (defaults to `401 Unauthorized` with empty JSON).

<div class="lang-content" data-lang="python" markdown="1">

```python
# Override default unauthenticated response
ts.default_responses["unauthenticated"] = {
    "status_code": 403,
    "response_body": {"error": "Access Denied", "code": 1001},
    "mime_type": "application/json"
}

# Override default authenticated response
ts.default_responses["authenticated"] = {
    "status_code": 200,
    "response_body": {"status": "ok"},
    "mime_type": "application/json"
}
```

</div>
<div class="lang-content" data-lang="node" markdown="1">

```javascript
// Override default unauthenticated response
ts.default_responses["unauthenticated"] = {
    "status_code": 403,
    "response_body": { "error": "Access Denied", "code": 1001 },
    "mime_type": "application/json"
};

// Override default authenticated response
ts.default_responses["authenticated"] = {
    "status_code": 200,
    "response_body": { "status": "ok" },
    "mime_type": "application/json"
};
```

</div>
