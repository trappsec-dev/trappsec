
## installation

{% if page.language == 'python' %}
```bash
pip install trappsec
```
{% elsif page.language == 'node' %}
```bash
npm install trappsec
```
{% endif %}

## minimal example
 
Copy-paste this into a file to see Trappsec in action immediately.

{% if page.language == 'python' %}
1. **Save as `app.py`**:

```python
from flask import Flask, request
import trappsec

app = Flask(__name__)
ts = trappsec.Sentry(app, "DemoApp", "Dev")
ts.identify_user(lambda r: {"user_id": "guest"})

# 1. Decoy Route (Trap)
ts.trap("/admin/config").methods("GET").respond(200, {"debug": True})

# 2. Honey Field (Watch)
ts.watch("/profile").body("is_admin", intent="PrivEsc")

@app.route("/profile", methods=["POST"])
def update_profile():
    return {"status": "updated"}

if __name__ == "__main__":
    app.run(port=5000)
```

2. **Run**:

```bash
pip install flask trappsec
python app.py
```

3. **Attack**:

```bash
# Trigger Trap
curl http://localhost:5000/admin/config

# Trigger Watch
curl -X POST http://localhost:5000/profile -H "Content-Type: application/json" -d '{"is_admin": true}'
```

{% elsif page.language == 'node' %}
1. **Save as `app.js`**:

```javascript
const express = require('express');
const { Sentry } = require('trappsec');

const app = express();
app.use(express.json());

const ts = new Sentry(app, "DemoApp", "Dev");
ts.identify_user((req) => ({ user_id: "guest" }));

// 1. Decoy Route (Trap)
ts.trap("/admin/config").methods("GET").respond({ status: 200, body: { debug: true } });

// 2. Honey Field (Watch)
ts.watch("/profile").body("is_admin", { intent: "PrivEsc" });

app.post("/profile", (req, res) => res.json({ status: "updated" }));

app.listen(3000, () => console.log("Running on port 3000"));
```

2. **Run**:

```bash
npm install express trappsec
node app.js
```

3. **Attack**:

```bash
# Trigger Trap
curl http://localhost:3000/admin/config

# Trigger Watch
curl -X POST http://localhost:3000/profile -H "Content-Type: application/json" -d '{"is_admin": true}'
```
{% endif %}

## quick start

Initialize the Sentry in your application. This is the main entry point for defining your traps.

{% if page.language == 'python' %}
```python
import trappsec
# app is your Flask or FastAPI instance
ts = trappsec.Sentry(app, service="PaymentService", environment="Production")
```
{% elsif page.language == 'node' %}
```javascript
const { Sentry } = require('trappsec');
// app is your Express instance
const ts = new Sentry(app, "PaymentService", "Production");
```
{% endif %}


## configuration

You can globally configure how Trappsec responds to events.

### Default Responses
Trappsec uses default responses when you don't explicitly define one for a trap. You can override these to match your application's error schema.

{% if page.language == 'python' %}
```python
# Override default unauthenticated response (default is 401)
ts.default_responses["unauthenticated"] = {
    "status_code": 403,
    "response_body": {"error": "Access Denied", "code": 1001},
    "mime_type": "application/json"
}
```
{% elsif page.language == 'node' %}
```javascript
// Override default unauthenticated response (default is 401)
ts.default_responses["unauthenticated"] = {
    "status_code": 403,
    "response_body": { "error": "Access Denied", "code": 1001 },
    "mime_type": "application/json"
};
```
{% endif %}

## deception primitives

We currently support two core primitives: **Decoy Routes** and **Honey Fields**. Each primitive should be paired with a lure strategy (bait, breadcrumbs, etc.) to effectively attract attackers.

### 1. Decoy Routes
Fake endpoints that are not part of your real API but are designed to blend in. When a request hits a decoy route, Trappsec intercepts it, sends a realistic dummy response, and generates a high-fidelity alert.

{% if page.language == 'python' %}
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
{% elsif page.language == 'node' %}
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
{% endif %}

#### Response Templates
You can define reusable templates for common responses (e.g., deprecated API errors).

{% if page.language == 'python' %}
```python
ts.template("deprecated_api", 410, {"error": "Gone", "message": "API v1 is deprecated"})

ts.trap("/api/v1/users").methods("GET").respond(template="deprecated_api")
```
{% elsif page.language == 'node' %}
```javascript
ts.template("deprecated_api", 410, { "error": "Gone", "message": "API v1 is deprecated" });

ts.trap("/api/v1/users").methods("GET").respond({ template: "deprecated_api" });
```
{% endif %}

### 2. Honey Fields (Watches)
Fake fields or parameters that appear contextually relevant. Trappsec monitors these fields on legitimate routes. It can alert on the specific *presence* of a field or if its value *deviates* from a default.

{% if page.language == 'python' %}
```python
# Alert if 'is_admin' is present (regardless of value)
ts.watch("/api/profile/update").body("is_admin", intent="Privilege Escalation")

# Alert if 'role' is present AND not equal to 'user'
ts.watch("/auth/register") \
    .body("role", default="user", intent="Role Tampering")
```
{% elsif page.language == 'node' %}
```javascript
// Alert if 'is_admin' is present
ts.watch("/api/profile/update").body("is_admin", { intent: "Privilege Escalation" });

// Alert if 'role' is present AND not equal to 'user'
ts.watch("/auth/register")
    .body("role", { defaultValue: "user", intent: "Role Tampering" });
```
{% endif %}

## attribution
To make alerts actionable, Trappsec needs to know *who* is attacking.

{% if page.language == 'python' %}
```python
# Extract user info from headers, session, etc.
ts.identify_user(lambda r: {
    "user_id": r.headers.get("x-user-id"),
    "role": r.headers.get("x-user-role")
})

# Handle proxies / load balancers
ts.override_source_ip(lambda r: r.headers.get("x-real-ip", r.remote_addr))
```
{% elsif page.language == 'node' %}
```javascript
ts.identify_user((req) => ({
    "user_id": req.headers["x-user-id"],
    "role": req.headers["x-user-role"]
}));

ts.override_source_ip((req) => req.headers["x-real-ip"] || req.ip);
```
{% endif %}

## alerts & integrations

### Webhooks
Send alerts to Slack, Discord, or custom incident response tools.

{% if page.language == 'python' %}
```python
ts.add_webhook("https://hooks.slack.com/services/...")
```
{% elsif page.language == 'node' %}
```javascript
ts.add_webhook("https://hooks.slack.com/services/...");
```
{% endif %}

### OpenTelemetry
Emit alerts as OTEL spans to visualize attacks in your existing observability platform (Jaeger, Honeycomb, Datadog).

{% if page.language == 'python' %}
```python
# Ensure OTEL is instrumented first
ts.add_otel()
```
{% elsif page.language == 'node' %}
```javascript
ts.add_otel();
```
{% endif %}



## support

Contact us at [nikhil@ftfy.co](mailto:nikhil@ftfy.co) or open an issue on GitHub.
