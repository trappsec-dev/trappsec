---
layout: default
title: Detect API Reconnaissance with a GraphQL Decoy
nav_exclude: true
permalink: /blogposts/graphql-decoy-with-trappsec/
---

# Detect API Reconnaissance with a GraphQL Decoy

*Feb 12, 2026*

![GraphQL decoy concept](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*cgF45518XKQmJ4pyO_tTCQ.png)

When discussing the [trappsec](https://trappsec.dev) philosophy, one key principle is that good traps must blend into business logic. They should look like an ordinary part of your API. If something looks unusual or overly sensitive, experienced attackers will avoid it.

At the same time, there are opportunities to design traps specific to certain technologies while preserving this principle. One such opportunity is a fake GraphQL interface, especially in an application that does not use GraphQL at all.

## Why GraphQL works well as a trap

GraphQL supports [schema introspection](https://graphql.org/learn/introspection/) via a standardized query interface. If enabled, this allows clients to retrieve full schema definitions, including types and operations. Because introspection can expose significant structural information, tooling and checklists often probe endpoints like `/graphql` or `/api/graphql`.

Since probes are already looking for it, deception around a fake GraphQL endpoint may not need additional [lure mechanisms](https://trappsec.dev/baiting-and-lures/).

![Simple GraphQL introspection query](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*yazViJeNa8_wxz3fBK7uEw.png)

## Building the trap

In this post, we implement a realistic but simple GraphQL decoy in a Python Flask application using trappsec. The goal is to detect authenticated users performing deep reconnaissance before they find real vulnerabilities.

> We highlight only key parts. The [full example code](https://github.com/trappsec-dev/trappsec/tree/main/examples/blog/graphql) is in the repository.

First, initialize `Sentry` and identity extraction. This ties reconnaissance attempts to authenticated accounts, not just IPs.

```python
# main.py
from flask import Flask, request, jsonify, g
import trappsec

app = Flask(__name__)
ts = trappsec.Sentry(app, service="SomeService", environment="Development")

# Link request context to your internal identity model
ts.identify_user(lambda r: {
    "user": g.user_id,
    "role": "user",
})

@app.before_request
def mock_auth():
    # Real apps should use actual session/JWT auth
    g.user_id = "user_12345"
```

Next, define the decoy route. This behaves like a normal `/graphql` endpoint but is managed by trappsec.

```python
# main.py (continued)
from custom import graphql_trap

ts.trap("/graphql") \
    .methods("POST") \
    .intent("GraphQL Reconnaissance") \
    .respond(200, graphql_trap) \
    .if_unauthenticated(
        401,
        {
            "errors": [{"message": "Unauthorized"}]
        }
    )
```

Now design a custom responder that behaves like GraphQL: parse query, validate against a schema, block introspection, and return GraphQL-style errors.

```python
# custom.py
from graphql import parse, validate, build_schema, GraphQLError, specified_rules
from graphql.validation import NoSchemaIntrospectionCustomRule
from flask import request

# Minimal schema for validation
dummy_schema = build_schema("""type Query { name: String }""")
validation_rules = specified_rules + (NoSchemaIntrospectionCustomRule,)

def graphql_trap(req):
    body = request.get_json(silent=True) or {}
    query = body.get("query", "")
    try:
        ast = parse(query)
    except GraphQLError as e:
        return {"data": None, "errors": [e.formatted]}

    errors = validate(dummy_schema, ast, rules=validation_rules)
    if errors:
        return {"data": None, "errors": [errors[0].formatted]}

    return {"data": None}
```

### Unauthenticated requests

```bash
curl -X POST http://127.0.0.1:8000/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name } } }"}'
```

```json
{
  "errors": [
    { "message": "Unauthorized" }
  ]
}
```

### Syntax or structural errors

```bash
curl -X POST http://127.0.0.1:8000/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <TOKEN>" \
  -d '{"query":"{ __schema types { name } } }"}'
```

```json
{
  "data": null,
  "errors": [
    {
      "message": "Syntax Error: Unexpected '}'.",
      "locations": [{ "line": 1, "column": 29 }]
    }
  ]
}
```

### Introspection attempts

```bash
curl -X POST http://127.0.0.1:8000/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <TOKEN>" \
  -d '{"query":"{ __schema { types { name } } }"}'
```

```json
{
  "data": null,
  "errors": [
    {
      "message": "GraphQL introspection has been disabled, but the requested query contained the field '__schema'.",
      "locations": [{ "line": 1, "column": 3 }]
    }
  ]
}
```

### Other valid queries

```bash
curl -X POST http://127.0.0.1:8000/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <TOKEN>" \
  -d '{"query":"mutation { updateUserRole(id: 1, role: \"admin\") { success error } }"}'
```

```json
{ "data": null }
```

If the trap returned generic JSON or plain HTTP errors, experienced attackers could quickly identify it as fake. By using GraphQL parsing and validation, responses follow expected GraphQL structures, reducing suspicion while giving defenders actionable context.

```json
{
  "timestamp": 1770922295.7872922,
  "event": "trappsec.trap_hit",
  "type": "alert",
  "path": "/graphql",
  "method": "POST",
  "user_agent": "curl/8.16.0",
  "ip": "127.0.0.1",
  "intent": "GraphQL Reconnaissance",
  "user": "user_12345",
  "role": "user",
  "app": {
    "service": "SomeService",
    "environment": "Development",
    "hostname": "ftfy-one"
  }
}
```

## Closing note

This technique leverages attacker thoroughness against itself. The more avenues an attacker probes to map your app, the more opportunities you have to detect reconnaissance. By emulating enough of the protocol, attackers cannot easily distinguish a real GraphQL endpoint from the trap.
