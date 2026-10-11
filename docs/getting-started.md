---
layout: default
title: Getting Started
permalink: /getting-started/
tagline: "Install the SDK, initialize the Sentry, and define your first traps in under 10 minutes."
---

<div class="lang-switcher">
  <button class="lang-btn active" onclick="switchLang('python')">Python</button>
  <button class="lang-btn" onclick="switchLang('node')">Node.js</button>
  <button class="lang-btn" onclick="switchLang('go')">Go</button>
</div>

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
<div class="lang-content" data-lang="go" markdown="1">

```bash
# Install the integration for your framework (gin, nethttp, or echo)
go get github.com/trappsec-dev/trappsec/packages/go/gin
```

</div>

## initialization

Initialize the Sentry in your application. This is the main entry point for defining your traps.

<div class="lang-content" data-lang="python" markdown="1">

```python
import trappsec
# app is your Flask or FastAPI instance
ts = trappsec.Sentry(
    app, service="PaymentService", environment="Production"
)
```

</div>
<div class="lang-content" data-lang="node" markdown="1">

```javascript
const { Sentry } = require('trappsec');
// app is your Express instance
const ts = new Sentry(app, "PaymentService", "Production");
```

</div>
<div class="lang-content" data-lang="go" markdown="1">

```go
import trappsec "github.com/trappsec-dev/trappsec/packages/go/gin"

// r is your *gin.Engine (swap import path for nethttp or echo)
ts := trappsec.InstallSentry(r, "PaymentService", "Production")
```

</div>



## deception primitives

We currently support two core primitives: **Decoy Routes** and **Honey Fields**. Each primitive should be paired with a lure strategy (bait, breadcrumbs, etc.) to effectively attract attackers.

### 1. Decoy Routes
Fake endpoints that are not part of your real API but are designed to blend in. When a request hits a decoy route, trappsec intercepts it, sends a realistic dummy response, and generates a high-fidelity alert.

#### Auth-aware Responses
Just like real APIs, traps return different responses based on whether the incoming request is authenticated or not. This nudges attackers to use credentials to identify themselves. The framework uses a default response template for unauthenticated requests that must be overridden to match your application behavior.

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
    .respond(200, lambda r: {
        "cpu":    f"{random.randint(5, 95)}%",
        "memory": f"{random.randint(20, 90)}%",
    })

```

</div>
<div class="lang-content" data-lang="node" markdown="1">

```javascript
// Static response
ts.trap("/deployment/config")
    .methods("GET")
    .intent("Reconnaissance")
    .respond({
        status: 200,
        body: { region: "us-east-1", deployment_type: "production" },
    })
    .if_unauthenticated({ status: 401, body: { error: "Login Required" } });

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
<div class="lang-content" data-lang="go" markdown="1">

```go
// Static response
ts.Trap("/deployment/config").
    Methods("GET").
    Intent("Reconnaissance").
    Respond(trappsec.ResponseConfig{
        Status: 200,
        Body: map[string]any{
            "region":          "us-east-1",
            "deployment_type": "production",
        },
    }).
    IfUnauthenticated(trappsec.ResponseConfig{
        Status: 401,
        Body:   map[string]any{"error": "Login Required"},
    })

// Dynamic response
ts.Trap("/deployment/metrics").
    Methods("GET").
    Intent("Reconnaissance").
    Respond(trappsec.ResponseConfig{
        Status: 200,
        Body: func(_ any) any {
            return map[string]any{
                "cpu":    fmt.Sprintf("%d%%", rand.Intn(91)+5),
                "memory": fmt.Sprintf("%d%%", rand.Intn(71)+20),
            }
        },
    })
```

</div>

#### Response Templates
You can define reusable templates for common responses (e.g., deprecated API errors).

<div class="lang-content" data-lang="python" markdown="1">

```python
ts.template(
    "deprecated_api", 410,
    {"error": "Gone", "message": "API v1 is deprecated"},
)

ts.trap("/api/v1/users").methods("GET").respond(template="deprecated_api")
```

</div>
<div class="lang-content" data-lang="node" markdown="1">

```javascript
ts.template("deprecated_api", 410, {
    error: "Gone", message: "API v1 is deprecated",
});

ts.trap("/api/v1/users").methods("GET").respond({ template: "deprecated_api" });
```

</div>
<div class="lang-content" data-lang="go" markdown="1">

```go
ts.Template(
    "deprecated_api",
    410,
    map[string]any{"error": "Gone", "message": "API v1 is deprecated"},
) // an optional fourth argument sets the MIME type (default "application/json")

ts.Trap("/api/v1/users").Methods("GET").
    Respond(trappsec.ResponseConfig{Template: "deprecated_api"})
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
ts.watch("/api/profile/update")
    .body("role", { intent: "Privilege Escalation" });

// Alert if 'role' is present AND not equal to 'user'
ts.watch("/auth/register")
    .body("role", { default: "user", intent: "Role Tampering" });
```

</div>
<div class="lang-content" data-lang="go" markdown="1">

```go
// Alert if 'role' is present (regardless of value)
ts.Watch("/api/profile/update").
    Body("role", trappsec.Intent("Privilege Escalation"))

// Alert if 'role' is present AND not equal to 'user'
ts.Watch("/auth/register").
    Body("role", trappsec.Default("user"), trappsec.Intent("Role Tampering"))
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
    "user": getattr(r.user, "id", None),  # assuming request.user is set
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
    "user": req.user?.id,
    "role": req.user?.role || "guest"
}));

ts.override_source_ip((req) => req.headers["x-real-ip"] || req.ip);
```

</div>
<div class="lang-content" data-lang="go" markdown="1">

```go
// Extract user info from auth middleware (e.g. JWT claims on context)
ts.IdentifyUser(func(req any) *trappsec.AuthContext {
    c := req.(*gin.Context) // cast to your framework's request type
    uid := c.GetHeader("x-user-id")
    if uid == "" {
        return nil
    }
    role := c.GetHeader("x-user-role")
    if role == "" {
        role = "user"
    }
    return &trappsec.AuthContext{User: uid, Role: role}
})

// Handle proxies / load balancers
ts.OverrideSourceIP(func(req any) string {
    c := req.(*gin.Context)
    if ip := c.GetHeader("x-real-ip"); ip != "" {
        return ip
    }
    return c.ClientIP()
})
```

</div>

---

## alerts & integrations
trappsec can integrate directly into your existing workflows. Events are written to your standard logging handlers by default, but can be configured to also integrate into **OpenTelemetry** for observability or **Webhooks** to trigger automated responses or notify security teams.

### Webhooks
Send alerts to a SIEM, incident response tool or any HTTP endpoint that accepts a JSON `POST` (the raw trappsec event, see the [Event Reference](/events/)). For Slack, use `add_slack` below, which sends a Slack-formatted payload. Delivery is asynchronous and never blocks your request path; call `close()` on shutdown to flush (see [Production](/production/)).
Webhook delivery is `alerts_only` by default, so only `type: "alert"` events are sent unless you override it.

<div class="lang-content" data-lang="python" markdown="1">

```python
ts.add_webhook("https://siem.example.com/hooks/trappsec")
ts.add_webhook("https://siem.example.com/hooks/trappsec", alerts_only=False)
```

</div>
<div class="lang-content" data-lang="node" markdown="1">

```javascript
ts.add_webhook("https://siem.example.com/hooks/trappsec");
ts.add_webhook("https://siem.example.com/hooks/trappsec", { alerts_only: false });
```

</div>
<div class="lang-content" data-lang="go" markdown="1">

```go
ts.AddWebhook("https://siem.example.com/hooks/trappsec", nil)
// Send all events (not just alerts)
alertsOnly := false
ts.AddWebhook(
    "https://siem.example.com/hooks/trappsec",
    &trappsec.WebhookOptions{AlertsOnly: &alertsOnly},
)
```

</div>

### Slack
Use a Slack incoming webhook with a presentation-optimized payload out of the box. Do not point `add_webhook` at a Slack URL: Slack rejects the raw event payload.

<div class="lang-content" data-lang="python" markdown="1">

```python
ts.add_slack("https://hooks.slack.com/services/...")
```

</div>
<div class="lang-content" data-lang="node" markdown="1">

```javascript
ts.add_slack("https://hooks.slack.com/services/...");
```

</div>
<div class="lang-content" data-lang="go" markdown="1">

```go
ts.AddSlack("https://hooks.slack.com/services/...", nil)
```

</div>

### OpenTelemetry
Enrich your OTEL spans with trappsec metadata to track attacks in your existing observability platform (Jaeger, Honeycomb, Datadog).

<div class="lang-content" data-lang="python" markdown="1">

```python
ts.add_otel()
```

</div>
<div class="lang-content" data-lang="node" markdown="1">

```javascript
ts.add_otel();
```

</div>
<div class="lang-content" data-lang="go" markdown="1">

```go
ts.AddOTEL()
```

</div>

## default responses
You can globally configure how trappsec responds to events. This is useful for maintaining consistency across all your traps without repeating configuration.

Defaults are resolved when traps are built (at bootstrap), not when `.trap()` is called, so you can set them **before or after** declaring traps; the order does not matter.

There are two default profiles you can override. Each setter takes the same arguments as the trap method it stands in for: only what you pass changes, and `template` replaces the whole response.
1.  **authenticated**: `default_response(...)` / `DefaultResponse(...)`, used when a trap does not call `respond()` (defaults to `200 OK` with empty JSON).
2.  **unauthenticated**: `default_unauthenticated_response(...)` / `DefaultUnauthenticatedResponse(...)`, used when a trap does not call `if_unauthenticated()` (defaults to `401 Unauthorized` with empty JSON).

<div class="lang-content" data-lang="python" markdown="1">

```python
# Override default unauthenticated response
ts.default_unauthenticated_response(status=403, body={"error": "Access Denied", "code": 1001})

# Override default authenticated response
ts.default_response(body={"status": "ok"})
```

</div>
<div class="lang-content" data-lang="node" markdown="1">

```javascript
// Override default unauthenticated response
ts.default_unauthenticated_response({ status: 403, body: { error: "Access Denied", code: 1001 } });

// Override default authenticated response
ts.default_response({ body: { status: "ok" } });
```

</div>
<div class="lang-content" data-lang="go" markdown="1">

```go
// Override default unauthenticated response
ts.DefaultUnauthenticatedResponse(trappsec.ResponseConfig{
    Status: 403, Body: map[string]any{"error": "Access Denied", "code": 1001},
})

// Override default authenticated response
ts.DefaultResponse(trappsec.ResponseConfig{Body: map[string]any{"status": "ok"}})
```

</div>
