
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


## default responses
You can globally configure how trappsec responds to events. trappsec uses default responses when you don't explicitly define one for a trap. You can override these to match your application's error schema.

<div class="lang-content" data-lang="python" markdown="1">

```python
# Override default unauthenticated response (default is 401)
ts.default_responses["unauthenticated"] = {
    "status_code": 403,
    "response_body": {"error": "Access Denied", "code": 1001},
    "mime_type": "application/json"
}
```

</div>
<div class="lang-content" data-lang="node" markdown="1">

```javascript
// Override default unauthenticated response (default is 401)
ts.default_responses["unauthenticated"] = {
    "status_code": 403,
    "response_body": { "error": "Access Denied", "code": 1001 },
    "mime_type": "application/json"
};
```

</div>

## deception primitives

We currently support two core primitives: **Decoy Routes** and **Honey Fields**. Each primitive should be paired with a lure strategy (bait, breadcrumbs, etc.) to effectively attract attackers.

### 1. Decoy Routes
Fake endpoints that are not part of your real API but are designed to blend in. When a request hits a decoy route, trappsec intercepts it, sends a realistic dummy response, and generates a high-fidelity alert.

<div class="lang-content" data-lang="python" markdown="1">

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

</div>
<div class="lang-content" data-lang="node" markdown="1">

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

### 2. Honey Fields (Watches)
Fake fields or parameters that appear contextually relevant. trappsec monitors these fields on legitimate routes. It can alert on the specific *presence* of a field or if its value *deviates* from a default.

<div class="lang-content" data-lang="python" markdown="1">

```python
# Alert if 'is_admin' is present (regardless of value)
ts.watch("/api/profile/update").body("is_admin", intent="Privilege Escalation")

# Alert if 'role' is present AND not equal to 'user'
ts.watch("/auth/register") \
    .body("role", default="user", intent="Role Tampering")
```

</div>
<div class="lang-content" data-lang="node" markdown="1">

```javascript
// Alert if 'is_admin' is present
ts.watch("/api/profile/update").body("is_admin", { intent: "Privilege Escalation" });

// Alert if 'role' is present AND not equal to 'user'
ts.watch("/auth/register")
    .body("role", { defaultValue: "user", intent: "Role Tampering" });
```

</div>

## attribution
To make alerts actionable, trappsec needs to know *who* is attacking.

<div class="lang-content" data-lang="python" markdown="1">

```python
# Extract user info from headers, session, etc.
ts.identify_user(lambda r: {
    "user_id": r.headers.get("x-user-id"),
    "role": r.headers.get("x-user-role")
})

# Handle proxies / load balancers
ts.override_source_ip(lambda r: r.headers.get("x-real-ip", r.remote_addr))
```

</div>
<div class="lang-content" data-lang="node" markdown="1">

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

<div class="lang-content" data-lang="python" markdown="1">

```python
ts.add_webhook("https://hooks.slack.com/services/...")
```

</div>
<div class="lang-content" data-lang="node" markdown="1">

```javascript
ts.add_webhook("https://hooks.slack.com/services/...");
```

</div>

### OpenTelemetry
Emit alerts as OTEL spans to visualize attacks in your existing observability platform (Jaeger, Honeycomb, Datadog).

<div class="lang-content" data-lang="python" markdown="1">

```python
# Ensure OTEL is instrumented first
ts.add_otel()
```

</div>
<div class="lang-content" data-lang="node" markdown="1">

```javascript
ts.add_otel();
```

</div>



## support

Contact us at [nikhil@ftfy.co](mailto:nikhil@ftfy.co) or open an issue on GitHub.

