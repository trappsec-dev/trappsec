# Trappsec Integration Rules

Rules derived from architectural analysis of the Python (FastAPI, Flask) and Node.js (Express, NestJS) reference implementations. Any new framework or language integration must follow these rules.

---

## R1: Watch matching must use the resolved route pattern, not the request URL

The integration must hook into a lifecycle point where the framework has **already matched the request to a route** and exposes the **route definition pattern** (e.g., `/users/:id`, `/users/{id}`, `/users/<id>`). Watches are keyed by pattern — using the raw URL as the primary lookup key will miss every parameterized watch.

**Raw URL fallbacks are safe.** Most integrations end their pattern-resolution chain with a raw URL fallback (e.g. `req.routeOptions?.url || req.url`). This is not a bug. Because the hook runs after routing, the fallback only fires when no route was matched (a 404), in which case there is no watch to trigger anyway. The concern is using raw URL as the *only* or *primary* strategy — not as a last-resort fallback that is unreachable for matched routes.

**Reference:**
- FastAPI uses `request.scope.get("route").path` — the matched `APIRoute` object's pattern
- Flask uses `request.url_rule.rule` — Werkzeug's matched URL rule string
- Express uses `req.route.path` — set by Express after route matching
- NestJS-Fastify uses `req.routeOptions.url` / `req.routerPath` — Fastify's resolved route pattern

---

## R2: Trap routes must not be silently shadowed by application routes

The requirement differs based on how the framework resolves route conflicts:

**Order-based routers** (first-registered wins): an explicit priority mechanism is required — prepend trap routes before application routes, or manipulate the route list/stack so traps are evaluated first. Registering traps after app routes without reordering will silently shadow them.

**Specificity-based routers** (pattern specificity wins): registering traps as native routes is sufficient. The framework's routing engine guarantees that a static trap path beats a wildcard or catch-all regardless of registration order. If a trap path exactly duplicates a real app route, the framework will raise a route conflict error — this is the correct outcome, forcing the developer to resolve the ambiguity explicitly rather than silently picking a winner.

**Middleware-based trap interception** (traps handled in middleware rather than as native routes): explicit priority is always required, and the ordering of middleware registration matters regardless of router type.

**Reference:**
- FastAPI prepends `APIRoute` objects: `app.router.routes = new_routes + app.router.routes` — required because Starlette is order-based
- Express, Koa and NestJS-Express insert trap routes **immediately before the first route layer**, i.e. after ordinary middleware (auth, session, body parsers) so `identify_user` can see the user, but before any application route so traps are never shadowed. Never prepend ahead of middleware, and never append after routes.
- If a trap path+method exactly duplicates an existing app route, fail loud (throw/panic with a clear message); never silently replace or shadow either side (see R20).
- Sanic, Gin, Echo, Hapi, net/http: native `add_route()` / `engine.Handle()` / `app.route()` registration is sufficient — specificity-based routing provides the guarantee implicitly

---

## R3: Setup must complete before any request is processed

Hook into app startup, server bind, or framework initialization. Where the framework allows, *additionally* expose an idempotent public `bootstrap()` and call it lazily from the first request (R15) so test clients and custom servers are protected too. Lazy first-request setup must be guarded by a lock / `sync.Once`.

If the framework provides a lifecycle hook (lifespan, onReady, beforeListen), use it. If you must patch, patch the `listen`/`serve`/`run` method.

**Reference:**
- FastAPI wraps the lifespan context manager — setup runs at app startup, before any requests (cleanest)
- Express/NestJS patches `app.listen()` / `httpAdapter.listen()` — setup runs at server bind time
- Flask wraps `app.wsgi_app` and runs setup on the first request — this is racy under concurrent startup load

---

## R4: Watched field deletion semantics are always-strip

The required behavior is **always strip**: watched fields must be removed from the request whenever present, regardless of whether the value matches the configured default.

Detection and mutation are separate:
- Emit a watch event only when a violation is detected (`default` missing or value mismatch)
- Still remove watched fields even when no violation is emitted
- To avoid no-op work, track whether any watched key was present (`touched`)
- Only rewrite/reset request data when `touched` is true; skip mutation when no watched key exists in the request

All integrations must follow this behavior consistently.

**Reference:**
- Python `core.py:243`: `del data[key]` is outside the detection condition — always deletes

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
- Express recurses into sub-routers (`Router` layers mounted with `app.use`) when wrapping the stack, so watches on nested routes fire. Routes registered *before* Sentry is installed are covered too (the stack is walked at bootstrap)
- NestJS-Express follows the same recursive walk
- Where a framework makes covering pre-install routes impossible, emit a loud warning at install time naming the uncovered routes and document the limitation
- NestJS-Fastify uses `addHook('preHandler')` which fires globally after route resolution regardless of nesting — avoids the problem entirely

---

## R8: Guard against double initialization — first-request strategies only

Bootstrap guards are **required only for first-request initialization strategies**, where setup runs inside a request handler or WSGI/ASGI middleware on the first incoming request. These strategies create genuine double-init risk: concurrent initial requests race to initialize, and test suites that process multiple requests against the same app instance will re-trigger setup.

**Startup-hook strategies do not need guards.** When setup runs inside a framework lifecycle hook (`before_server_start`, lifespan context manager) or a patched server-start method (`app.listen()`, `app.start()`, `app.run()`, `ListenAndServe()`), the hook fires once per server start by definition. Calling `listen()` twice in the same process is an application-level error that results in an "address already in use" OS error — defending against it is not trappsec's responsibility.

**Per-handler deduplication is a separate concern.** When `setup_watches()` iterates existing route handler layers and wraps them (e.g. the Express router stack), each layer must be tagged to prevent double-wrapping if the same stack happens to be inspected more than once within a single bootstrap pass. This is not an init guard — it is structural idempotency at the handler level.

**Reference:**
- Django requires `_bootstrapped` (class-level) + `threading.Lock` — setup runs on the first request, which is racy under concurrent startup load
- Flask's self-removing WSGI wrapper is the guard — required for the same reason
- FastAPI (lifespan), Sanic (`before_server_start`), Express/Fastify/Koa/Hapi (`app.listen`/`app.start` patch), Gin (`Run*`), Echo (`Start*`), net/http (`ListenAndServe*`): **no init guard needed or present**
- NestJS uses `__trappsecWrapped` on individual Express handler layers — this is per-handler deduplication within a single bootstrap pass, not an init guard

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

---

## R13: Trap and watch lookups must be O(1) per request

The integration must maintain a hash map (dict/object/map) indexed by route pattern for both traps and watches. Per-request lookup must be a single key access — never a linear scan through all configured traps or watches.

The index must be built exactly once — at startup or on the first request via a one-time initializer (e.g., `sync.Once`). Trap and watch configuration is immutable after the server starts listening; no versioning, cache invalidation, or locking is needed for lookups.

**Reference:**
- Python FastAPI/Flask: `watch_map = dict()` built once in `setup_watches()`, looked up via `watch_map[route.path]`
- Node.js Express/NestJS: `watchMap = {}` built once in `setup_watches()`, looked up via `watchMap[routePath]`

**What to avoid:**
```python
# Wrong — O(n) scan on every request
for watch in self.watches:
    if watch.path == request.path:
        ...

# Correct — O(1) map lookup
watch = watch_map.get(request.path)
```

---

## R14: Traps must be registered as real framework routes to resist fingerprinting

Traps must be indistinguishable from real API endpoints during unauthenticated scanning.
Intercepting trap paths in middleware rather than registering them as routes introduces
observable behavioral differences that allow attackers to identify traps.

**Reference implementations**:
- FastAPI: `app.router.routes = new_routes + app.router.routes`, called from a patched
  lifespan context at startup
- Express/Koa/NestJS-Express: real route layers inserted before the first route layer (after middleware), called from bootstrap (R3/R15)
- Go Gin: `engine.Handle(method, path, handler)`, called from the `*App.Run*()` wrappers
  returned by `InstallSentry`
- Go Echo: `app.Add(method, path, handler)`, called from the `*App.Start*()` wrappers
  returned by `InstallSentry`
- Go net/http: `mux.HandleFunc("GET /path", handler)` using Go 1.22+ method-qualified
  patterns, called from `*App.ListenAndServe*()` / `Serve*()` wrappers returned by
  `InstallSentry`; `App.ServeHTTP` is shadowed to inject watch inspection before dispatch

**Documented exception:** Go `handler` (chi, gorilla/mux, any `http.Handler`) cannot add
routes to a router it knows only as an `http.Handler`, so it intercepts traps in
`App.ServeHTTP` before the router. R2's explicit priority comes from `MatchRoutes`
(a real route at least as specific as a trap wins; an exact duplicate panics). The
observable difference: a trap path requested with a method the trap does not declare gets
the router's answer for an unknown path (usually 404), where a real route would answer
405. Prefer a framework-specific adapter where one exists.

---

## R15: Bootstrap is public, idempotent and lazy

Every language exposes a public `bootstrap()` (Go: `Bootstrap()`) on the integration/App that installs traps and watches. It must be safe to call multiple times and concurrently (lock / `sync.Once`). The startup hook (lifespan, `listen`, `Run`, `Start`) calls it. Where the framework allows, the first request also calls it (guarded) so that test clients and custom servers (`httptest`, `http.Server{Handler: app}`, supertest, `fastify.inject`, a `TestClient` without lifespan) are protected. If lazy install is impossible, log a loud warning on the first request that hits an un-bootstrapped Sentry. Routes registered before Sentry is installed must still be watched, or the uncovered routes must be named in a loud warning and documented.

## R16: Delivery is asynchronous, bounded and flushable

Webhook and Slack delivery never runs on the request path. Use a bounded in-memory queue (capacity 1000) drained by a background worker (Python: daemon thread + `queue.Queue`; Go: goroutine + buffered channel; Node: un-awaited `fetch` with an in-flight cap of 100). When full, drop the event and log a warning at most once per 60 s. Retries (at most 2, short backoff) happen in the worker. Non-2xx responses are logged; Go drains and closes response bodies. Expose `close()` / `Close()` which stops the heartbeat and flushes the queue with a timeout (default 5 s). Every user callback (`identify_user`, `override_source_ip`, callable defaults, dynamic bodies, webhook templates) runs in try/catch (Go: `recover`); on failure log and fall back (identity: none; ip: default extractor; callable default: no default; dynamic body: `{}`; template: drop the event for that handler, never send the raw event). Any exception inside trappsec's watch/trap code is caught and logged; the request continues unmodified (watch) or gets the normal unauthenticated decoy response (trap).

## R17: Value matching is canonical and identical across languages

`values_match(actual, expected)` is true when the values are equal; or both are numeric (booleans excluded) and numerically equal (`1` equals `1.0`); or one side is a string and the other a bool/number and the string equals the other's canonical form (`true`/`false` lowercase, integers in decimal, floats exactly as ECMAScript `Number::toString` writes them: `5` not `5.0`, `0.1`, `1e-7`, `1e+21`; `NaN`, `Infinity`). Strings compare exactly. Arrays match when they have the same length and every element matches in order; objects match when they have the same keys and every value matches; an array or object never matches a scalar. Python and Node match JSON keys case-sensitively; Go matches case-insensitively (`strings.EqualFold`) because `encoding/json` binds case-insensitively. Rule lookup uses own-property semantics (Node: `Object.hasOwn`/null-prototype maps; `constructor`, `__proto__` never match unless configured). Top-level JSON object: inspect; array: inspect each object element; anything else: skip, never crash. Always strip every occurrence of a watched key (R4), even when a callable default throws.

The cases in `tests/conformance/` are the executable form of R17 and R18. Each SDK's unit tests load them, so a change to matching semantics must update the fixtures and pass in all three languages.

## R18: Multi-valued fields

Integrations pass multi-valued query/form fields as a list. The whole list is first compared with the expected value (so a list default matches an equal list); otherwise a non-empty list is clean only if **every** element matches the expected value, and an empty list is a violation. A single-element list is therefore compared as its scalar, and it is recorded in `found_fields[].value` as that scalar. All occurrences of a watched key are stripped; non-watched multi-valued fields must be preserved intact on rewrite. Duplicate keys in a query string or form are therefore never a way to bypass a watch.

## R19: Recorded values are sanitized; events always serialize

`found_fields[].value` is passed through `safe_value`: null/bool/number unchanged; string truncated to 1024 chars (append `...`); list limited to the first 20 elements, each sanitized; dict/map rendered as compact JSON (no spaces) with sorted keys and no HTML escaping, truncated to 1024 (append `...`); anything else (uploads, files, bytes) becomes `"<TypeName>"`. `path` and `user_agent` are truncated the same way as strings (1024 chars, then `...`). Each event has exactly the common keys plus its own (`trap_hit`: `intent`; `watch_hit`: `found_fields`, never null; `rule_hit`: `reason`, `intent`, `metadata`). `tests/conformance/safe_value.json` and `event_keys.json` are the executable form. Event serialization never fails (Python `default=str`, Node/Go equivalents). All event keys are always present, with `null` for absent values, including `user`/`role` on signals. `found_fields[].type` is `"query"` or `"body"`. Slack output escapes `&`, `<`, `>` in every request-derived value and sets a non-empty top-level `text`. OTel span attributes are limited to string/bool/int/float or homogeneous arrays; nulls are dropped and everything else stringified.

## R20: Fail loud on duplicate traps

If a trap path+method exactly duplicates an existing application route, throw/panic with a clear message at bootstrap. Never silently replace or shadow either route.

## R21: Client IP extraction must not trust spoofable headers by default

Default IP extractors use the transport peer address (Go gin/echo: `RemoteAddr` host) unless the framework is explicitly configured to trust proxies (Express `req.ip` respects `trust proxy`). Users override with `override_source_ip`. Never read `X-Forwarded-For` or `X-Real-IP` by default.

## R22: Traps are exempt from CSRF protection

Framework CSRF middleware must not block trap routes, otherwise a scanner's POST gets a CSRF error instead of the decoy response (a fingerprint). Django: `csrf_exempt`. Litestar: `opt={exclude_from_csrf_key: True}` on trap handlers. Tornado: traps override `check_xsrf_cookie`. Echo: the user's CSRF middleware runs before routes, so the adapter exposes `App.IsTrap` as a `Skipper`. Every Go adapter's `App.IsTrap` takes that framework's request type, and every SDK's `is_trap` / `IsTrap` gives the same answer for the same method and path. Other frameworks: register traps outside, or exempt them from, CSRF middleware, and test it with the framework's CSRF protection switched on.

## R23: Responses

Trap response bodies that are strings are sent raw regardless of mime type; other values are JSON-encoded for `application/json`. Builder `respond(...)` uses "was provided" checks (None/undefined/nil sentinel), not truthiness, so `body={}`, `""`, `0`, `false` and status `0` are honored. Default responses are resolved when traps are built (bootstrap), not when `.trap()` is called, so configuration order does not matter. Node template cloning is a shallow copy that preserves function bodies.
