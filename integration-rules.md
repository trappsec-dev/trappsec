# Trappsec Integration Rules

Rules derived from architectural analysis of the Python (FastAPI, Flask) and Node.js (Express, NestJS) reference implementations. Any new framework or language integration must follow these rules.

---

## R1: Watch matching must use the resolved route pattern, not the request URL

The integration must hook into a lifecycle point where the framework has already matched the request to a route and exposes the **route definition pattern** (e.g., `/users/:id`, `/users/{id}`, `/users/<id>`). Watches are keyed by pattern — matching against the raw URL path would break parameterized routes.

**Reference:**
- FastAPI uses `request.scope.get("route").path` — the matched `APIRoute` object's pattern
- Flask uses `request.url_rule.rule` — Werkzeug's matched URL rule string
- Express uses `req.route.path` — set by Express after route matching
- NestJS-Fastify uses `req.routeOptions.url` / `req.routerPath` — Fastify's resolved route pattern

---

## R2: Trap routes must be registered with guaranteed priority over application routes

Use whatever mechanism the framework provides to ensure traps match before real routes: route list prepending, stack manipulation, priority/weight systems.

If the framework uses specificity-based routing (like Werkzeug/Flask), verify that trap paths won't lose to more-specific real routes. Order-based routers (Express, FastAPI) are more straightforward — prepend or insert traps before application routes.

**Reference:**
- FastAPI prepends `APIRoute` objects: `app.router.routes = new_routes + app.router.routes`
- NestJS-Express clears and restores the router stack to force trap-first ordering
- Flask uses `app.add_url_rule()` with no explicit ordering guarantee — this is the weakest approach

---

## R3: Setup must complete before any request is processed

Hook into app startup, server bind, or framework initialization — not first-request. First-request strategies create race conditions under concurrent load and add latency to the initial request.

If the framework provides a lifecycle hook (lifespan, onReady, beforeListen), use it. If you must patch, patch the `listen`/`serve`/`run` method.

**Reference:**
- FastAPI wraps the lifespan context manager — setup runs at app startup, before any requests (cleanest)
- Express/NestJS patches `app.listen()` / `httpAdapter.listen()` — setup runs at server bind time
- Flask wraps `app.wsgi_app` and runs setup on the first request — this is racy under concurrent startup load

---

## R4: Watched field deletion semantics must be deliberate and documented

Decide whether watched fields are **always stripped** from the request (regardless of value) or **only stripped when a violation is detected**.

Both are valid strategies:
- **Always strip** (Python behavior): the downstream handler never sees honey fields, even with expected values. The handler must supply its own defaults. More conservative.
- **Strip on violation only** (Node.js behavior): the handler receives normal values transparently. Only suspicious values are removed. More transparent.

This is currently inconsistent between the Python and Node.js reference implementations. New integrations must pick one and document it.

**Reference:**
- Python `core.py:243`: `del data[key]` is outside the detection condition — always deletes
- Node.js `core.js:191`: `delete data[key]` is inside the `if (expected === NO_DEFAULT || data[key] !== expected)` condition — only deletes on violation

---

## R5: Body parsing must be handled by the integration or be an explicit documented prerequisite

If the framework parses request bodies lazily (FastAPI's `await request.json()`, Flask's `request.get_json()`), the integration should trigger parsing itself.

If the framework requires explicit middleware for body parsing (Express's `express.json()`), the integration must either:
1. Ensure the body parser runs before watch inspection, or
2. Document the requirement prominently with a clear error when `req.body` is undefined

Silent failure on unparsed bodies is not acceptable.

**Reference:**
- FastAPI/Flask handle body parsing lazily — no ordering dependency
- Express requires `express.json()` / `body-parser` to have run before watched routes — `req.body` is `undefined` otherwise and body watches silently skip

---

## R6: Request mutation must use the most stable API available

Prefer public, documented attributes over private/cached internals. When private attribute mutation is unavoidable, document the framework version constraint and test against version upgrades.

When the framework may use getter-only properties (Fastify), prefer in-place object mutation over reference replacement.

**Reference:**
- FastAPI mutates `request._json`, `request._query_params`, `request._form` — private Starlette internals, brittle across versions
- Flask mutates `request.args` (public), `request._cached_json` (private cache tuple) — mixed stability
- Express uses `req.query = data`, `req.body = data` — simple reference replacement on plain objects
- NestJS uses `_replaceData()` which clears and reassigns properties in-place — most defensive approach for cross-adapter compatibility

---

## R7: Sub-router and nested module coverage must be explicit

If the framework supports nested routing (Express Router, Django URL includes, Go chi subrouters, Rails engines), the integration must either:
1. Recursively wrap nested routers/layers, or
2. Use a global lifecycle hook that fires after nested route resolution (e.g., Fastify `preHandler`)

If neither is possible, the limitation must be documented.

**Reference:**
- Express wraps `app._router.stack` at the top level only — routes inside sub-routers are silently missed because `req.route` isn't populated when the top-level wrapper runs
- NestJS-Express has the same limitation
- NestJS-Fastify uses `addHook('preHandler')` which fires globally after route resolution regardless of nesting — avoids the problem entirely

---

## R8: Guard against double initialization

Use flags to prevent:
- Double-wrapping route handlers
- Double-registering trap routes
- Double-registering watch hooks

This is critical when the startup mechanism could fire more than once (hot reload, WSGI wrapper race, test teardown/setup cycles).

**Reference:**
- NestJS uses `__trappsecWrapped` on handlers, `__trappsecWatchHookInstalled` on the app instance, and `_bootstrapped` on the integration
- Express has no double-init protection
- Flask's self-removing WSGI wrapper is the protection, but it's racy under concurrent first requests

---

## R9: Framework detection must fail loud

When the framework cannot be identified, throw an error immediately. Do not silently skip integration — this would leave the application unprotected with no indication.

**Reference:**
- Python raises `Exception("trappsec error: unknown framework.")`
- Node.js throws `new Error("trappsec error: unknown framework.")`

---

## R10: Trap registration must happen before watch setup

Traps add new routes. Watches wrap or hook existing routes/handlers. Order matters:

1. Register trap routes first
2. Set up watch hooks/wrappers second

If watches are set up before traps, the watch wrapper may unnecessarily wrap trap handlers. Worse, if the watch setup snapshots the current route table, traps registered afterward won't be visible to the watch logic.

**Reference:**
- All four integrations call `inject_traps()` before `setup_watches()` in their startup sequence

---

## R11: Identity and request context extraction must be adapter-specific

Each framework exposes IP, path, user-agent, and HTTP method through different APIs. The integration must set the appropriate extraction lambdas during construction. Do not assume a universal request interface.

**Reference:**
- FastAPI: `r.client.host`, `r.url.path`, `r.headers.get("user-agent")`, `r.method`
- Flask: `r.remote_addr`, `r.path`, `str(r.user_agent)`, `r.method`
- Express: `r.ip`, `r.path`, `r.get('User-Agent')`, `r.method`
- Fastify: `r.ip`, `r.url`, `r.headers['user-agent']`, `r.method`

---

## R12: Handler emission must be fire-and-forget, never blocking the request

All handler `.emit()` calls must be wrapped in try/catch. Failures must be logged, never propagated to the request lifecycle. A webhook timeout or OTEL export failure must never delay or error the HTTP response.

**Reference:**
- Both implementations wrap `h.emit(trigger_ctx)` in try/catch with `logger.error` on failure
- No handler failure affects the request response
