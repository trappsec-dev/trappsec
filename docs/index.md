# **turn apps into traps**

Trappsec is an open-source application-layer deception framework that helps developers catch attackers probing their APIs. It provides simple deception primitives to confirm malicious intent while blending into your codebase. It places a high value on the ability to attribute attacks to specific identities. With alerts that include intent and attribution, security teams can respond more effectively to attacks.

![Trappsec Flow](./assets/images/trappsec-flow.webp)

## installation

<div class="tabbed-content" markdown="1">
**Python**
```bash
pip install trappsec
```

**Node.js**
```bash
npm install trappsec
```
</div>

## quick start

Initialize the Sentry in your application. This is the main entry point for defining your traps.

<div class="tabbed-content" markdown="1">
**Python (Flask/FastAPI)**
```python
import trappsec
# app is your Flask or FastAPI instance
ts = trappsec.Sentry(app, service="PaymentService", environment="Production")
```

**Node.js (Express)**
```javascript
const { Sentry } = require('trappsec');
// app is your Express instance
const ts = new Sentry(app, "PaymentService", "Production");
```
</div>

## deception primitives

We currently support two core primitives: **Decoy Routes** and **Honey Fields**. Each primitive should be paired with a lure strategy (bait, breadcrumbs, etc.) to effectively attract attackers.

### 1. Decoy Routes
Fake endpoints that are not part of your real API but are designed to blend in. When a request hits a decoy route, Trappsec intercepts it, sends a realistic dummy response, and generates a high-fidelity alert.

<div class="tabbed-content" markdown="1">
**Python**
```python
# Static response
ts.trap("/admin/config") \
    .methods("GET") \
    .intent("Admin Panel Probing") \
    .respond(200, {"allow_signup": True, "debug_mode": True})

# Dynamic response
import random
ts.trap("/metrics") \
    .methods("GET") \
    .respond(200, lambda r: {"cpu": f"{random.randint(10, 50)}%"})
```

**Node.js**
```javascript
// Static response
ts.trap("/admin/config")
    .methods("GET")
    .intent("Admin Panel Probing")
    .respond({ status: 200, body: { "allow_signup": true, "debug_mode": true } });

// Dynamic response
ts.trap("/metrics")
    .methods("GET")
    .respond({ 
        status: 200, 
        body: (req) => ({ "cpu": `${Math.floor(Math.random() * 40) + 10}%` }) 
    });
```
</div>

#### Response Templates
You can define reusable templates for common responses (e.g., deprecated API errors).

<div class="tabbed-content" markdown="1">
**Python**
```python
ts.template("deprecated_api", 410, {"error": "Gone", "message": "API v1 is deprecated"})

ts.trap("/api/v1/users").methods("GET").respond(template="deprecated_api")
```

**Node.js**
```javascript
ts.template("deprecated_api", 410, { "error": "Gone", "message": "API v1 is deprecated" });

ts.trap("/api/v1/users").methods("GET").respond({ template: "deprecated_api" });
```
</div>

### 2. Honey Fields (Watches)
Fake fields or parameters that appear contextually relevant. Trappsec monitors these fields on legitimate routes. It can alert on the specific *presence* of a field or if its value *deviates* from a default.

<div class="tabbed-content" markdown="1">
**Python**
```python
# Alert if 'is_admin' is present (regardless of value)
ts.watch("/api/profile/update").body("is_admin", intent="Privilege Escalation")

# Alert if 'role' is present AND not equal to 'user'
ts.watch("/auth/register") \
    .body("role", default="user", intent="Role Tampering")
```

**Node.js**
```javascript
// Alert if 'is_admin' is present
ts.watch("/api/profile/update").body("is_admin", { intent: "Privilege Escalation" });

// Alert if 'role' is present AND not equal to 'user'
ts.watch("/auth/register")
    .body("role", { defaultValue: "user", intent: "Role Tampering" });
```
</div>

## attribution
To make alerts actionable, Trappsec needs to know *who* is attacking.

<div class="tabbed-content" markdown="1">
**Python**
```python
# Extract user info from headers, session, etc.
ts.identify_user(lambda r: {
    "user_id": r.headers.get("x-user-id"),
    "role": r.headers.get("x-user-role")
})

# Handle proxies / load balancers
ts.override_source_ip(lambda r: r.headers.get("x-real-ip", r.remote_addr))
```

**Node.js**
```javascript
ts.identify_user((req) => ({
    "user_id": req.headers["x-user-id"],
    "role": req.headers["x-user-role"]
}));

ts.override_source_ip((req) => req.headers["x-real-ip"] || req.ip);
```
</div>

## alerts & integrations

### Webhooks
Send alerts to Slack, Discord, or custom incident response tools.

<div class="tabbed-content" markdown="1">
**Python**
```python
ts.add_webhook("https://hooks.slack.com/services/...")
```

**Node.js**
```javascript
ts.add_webhook("https://hooks.slack.com/services/...");
```
</div>

### OpenTelemetry
Emit alerts as OTEL spans to visualize attacks in your existing observability platform (Jaeger, Honeycomb, Datadog).

<div class="tabbed-content" markdown="1">
**Python**
```python
# Ensure OTEL is instrumented first
ts.add_otel()
```

**Node.js**
```javascript
ts.add_otel();
```
</div>

## wiring effective traps

*   **Don't Overplay**: Deception is most effective when it is boring. A generic `401 Unauthorized` is often more convincing than a flashy "Access Denied" page.
*   **Be Consistent**: Ensure response headers, error formats, and schema conventions match your real API.
*   **Silent Interception**: When using Honey Fields, let the request succeed (200 OK) after silently stripping the malicious field. This keeps the attacker unaware they've been caught.

## support

Contact us at [nikhil@ftfy.co](mailto:nikhil@ftfy.co) or open an issue on GitHub.