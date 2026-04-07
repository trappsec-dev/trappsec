---
layout: default
title: API Deception with trappsec
nav_exclude: true
permalink: /blogposts/api-deception-with-trappsec/
---

*Feb 8, 2026*

![Photo by Mick Haupt on Unsplash](https://miro.medium.com/v2/resize:fit:1400/format:webp/0*VFiYu9u1KleswWoZ)

Deception is not new in cybersecurity. Canary tokens and honeypots have been around for years. But most of these techniques live at the infrastructure layer: fake servers, fake credentials, fake files.

Attackers today, however, increasingly target APIs and business logic. They are no longer just scanning ports, but are enumerating and exploring endpoints, tampering with parameters, testing entitlement boundaries and impossible states. This is a blind spot in traditional perimeter defenses and observability, and also where [trappsec](https://trappsec.dev), an open-source application-layer deception framework, comes in. Instead of deploying separate honeypot systems, it embeds realistic decoys that are indistinguishable from real API constructs directly inside your application.

Apart from decoy API routes, [trappsec](https://trappsec.dev) also supports honey fields: non-functional parameters embedded within legitimate API endpoints that act as invisible tripwires. In this article, we only focus on decoy routes. At the core, it involves placing a fake endpoint which, when interacted with, raises an alert.

A good trap must blend into your application like a boring, standard part of your API. It must also behave like a real API. If real APIs react differently to authentication status, so must the traps.

Example: consider a subscription upgrade decoy that appears to accept a plan change for a user subscription. This is what the decoy configuration would look like in a Python Flask web application:

```python
import trappsec
from flask import Flask

# initialize your web framework
app = Flask(__name__)

# initialize trappsec to wire up your app object
ts = trappsec.Sentry(app, service="BillingService", environment="Production")

# define a decoy
ts.trap("/api/subscription/upgrade") \
    .methods("POST") \
    .intent("Entitlement Manipulation") \
    .respond(403, {"error": "Upgrade not permitted"})
```

It indicates a response that states that the operation was not permitted. Nothing here looks like a honeypot, and nothing leaks implementation detail. For ways to lure attackers to this, read [Baiting and Lures](https://trappsec.dev/baiting-and-lures/).

If an attacker probes this with curl, the output will be `401 Unauthorized` instead of the `upgrade not permitted` error.

```bash
# probe sent by attacker
curl -X POST https://api.example.com/api/subscription/upgrade \
  -H "Content-Type: application/json" \
  -d '{
    "plan": "enterprise",
    "billing_cycle": "annual",
    "source": "self_service"
  }'

# response seen by attacker
HTTP/1.1 401 Unauthorized
{
  "error": "Authentication required"
}
```

This is because trappsec [can look up authentication context](https://trappsec.dev/getting-started/?lang=python#attribution) for every request that interacts with a decoy route. It lets you [define global defaults](https://trappsec.dev/getting-started/?lang=python#default-responses) as well as endpoint-specific defaults for authenticated versus unauthenticated scenarios:

```python
ts.trap("/api/subscription/upgrade") \
    .methods("POST") \
    .intent("Entitlement Manipulation") \
    .if_unauthenticated(401, {"error": "Authentication required"}) \
    .respond(403, {"error": "Upgrade not permitted"})
```

A `401` is not a dead end, it is a fork. It prompts the attacker to make a choice: retry with credentials, or move on.

```bash
# probe sent by attacker
curl -X POST https://api.example.com/api/subscription/upgrade \
  -H "Authorization: Bearer eyJhbGciOi..." \
  -H "Content-Type: application/json" \
  -d '{
    "plan": "enterprise",
    "billing_cycle": "annual",
    "source": "self_service"
  }'

# response seen by attacker
HTTP/1.1 403 Forbidden
{
  "error": "Upgrade not permitted"
}
```

When the attacker authenticates and tries again, they are no longer anonymous noise. They have crossed an identity boundary. That is where API-level deception becomes useful: providing a high-confidence alert with context that makes response easier.

```json
{
  "timestamp": 1707135273.482,
  "event": "trappsec.trap_hit",
  "type": "alert",
  "path": "/api/subscription/upgrade",
  "method": "POST",
  "user_agent": "curl/8.5.0",
  "ip": "203.0.113.42",
  "app": {
    "service": "billing-api",
    "environment": "production",
    "hostname": "worker-03"
  },
  "user": "user_8f3a2c",
  "role": "user",
  "intent": "entitlement_manipulation"
}
```

{: .note }
trappsec alerts are created for authenticated interactions. Unauthenticated interactions are logged as signals.
