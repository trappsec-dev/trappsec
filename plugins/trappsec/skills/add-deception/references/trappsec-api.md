# trappsec API cheat sheet

Full documentation: https://trappsec.dev/api/. If anything here disagrees with the installed version, the installed package wins: read its README or source.

Contents
1. Install and initialize per framework
2. Identity on trap routes
3. Traps
4. Watches (honey fields)
5. Default responses and templates
6. Alert outputs and logging
7. CSRF, proxies, shutdown, workers
8. Gotchas
9. Versions and known issues

**Check the installed version first** (`npm ls trappsec`, `pip show trappsec`, `go list -m all | grep trappsec`). The docs and this sheet follow the repository; a registry can still serve an older release that behaves differently (§9). The examples below use forms that work on every release.

## 1. Install and initialize per framework

| Stack | Install | Initialize |
|---|---|---|
| Python 3.10+ | `pip install trappsec` (or the project's tool: uv, poetry...) | `ts = trappsec.Sentry(app, "billing-api", env)` |
| Node 20+ | `npm install trappsec` (or pnpm/yarn) | `const { Sentry } = require('trappsec'); const ts = new Sentry(app, 'billing-api', env);` (ESM: `import { Sentry } from 'trappsec'`) |
| Go 1.26+ | `go get github.com/trappsec-dev/trappsec/packages/go/<gin\|echo\|nethttp>` | `app := trappsec.InstallSentry(router, "billing-api", env)` |

What `app` is and where initialization goes:
- **Flask, FastAPI, Starlette, Litestar, Sanic:** the application object. Tornado: the `tornado.web.Application`.
- **Django:** the WSGI or ASGI application. Wrap it in `wsgi.py`/`asgi.py`: `application = get_wsgi_application()`, then `ts = trappsec.Sentry(application, ...)`. Put trap and watch definitions in a module imported there.
- **Express:** `app`. Initialize after `express.json()` / `urlencoded()` and global auth/session middleware. Traps are inserted after middleware and before the first route, so global middleware runs for them.
- **Koa:** `app` (with `@koa/router`). Initialize after `koa-bodyparser`.
- **Hono:** `app` (`new Hono()`), before `serve({ fetch: app.fetch })` or `export default app`: trappsec hooks `app.fetch`. No body parser needed. The request object is the Hono `Context` `c` (`c.req.header(...)`, `c.get(...)`). Outside `@hono/node-server`, set `override_source_ip` (Hono's `getConnInfo`).
- **Fastify:** the fastify instance.
- **Hapi:** the `server`.
- **NestJS:** the app returned by `NestFactory.create(...)`, before `app.listen()`. Works with the Express and Fastify adapters.
- **Gin:** `*gin.Engine`. Call `InstallSentry` *before* creating route groups. Groups created earlier don't inherit the watch middleware.
- **Echo:** `*echo.Echo`.
- **net/http:** `*http.ServeMux`. Serve `app` (it implements `http.Handler`) or call `app.ListenAndServe(...)`.

The framework startup hook (lifespan, `listen`, `Run`, `Start`) bootstraps traps, and so does the first request. Call `ts.bootstrap()` / `app.Bootstrap()` explicitly if the app uses a custom server. Bootstrap raises if a trap duplicates a real route's path and method.

Go: the framework package re-exports `ResponseConfig`, `AuthContext`, `WebhookOptions`, `SlackOptions` and `NoDefault`, so one import is enough.

## 2. Identity on trap routes

`identify_user(cb)` receives the framework's request object. It must return an object with the keys **`user`** and **`role`** (other key names are ignored), or null/None/nil when anonymous. With a user, events are `alert`s and traps send the authenticated response. Without one, events are `signal`s and traps send the anonymous response.

**Trap routes run only global middleware.** Per-route middleware, guards, decorators and dependencies never run for them. So:

| How the app authenticates | What to do in the callback |
|---|---|
| Global session/auth middleware sets the user (Express `app.use(passport.session())`, Django `AuthenticationMiddleware`, Starlette middleware setting `request.state.user`) | Read the user it set |
| Per-route auth (Express route middleware, NestJS guards, FastAPI `Depends(...)`, DRF authentication classes, Gin group middleware, Hapi route auth) | Verify the session cookie or bearer token yourself with the app's own helper (the same JWT verify / session lookup), return null on failure |

Keep the callback cheap and side-effect free. It runs on every trap and watch hit, and failures are caught and treated as "no user".

```python
# Python (any framework): reuse the app's own token verification
def identify(request):
    claims = verify_access_token(request.headers.get("authorization"))  # the app's helper; None if invalid
    return {"user": claims["sub"], "role": claims.get("role", "member")} if claims else None
ts.identify_user(identify)
```

```javascript
// Node: Express with per-route JWT middleware
ts.identify_user((req) => {
  const claims = verifyAccessToken(req.headers.authorization); // the app's helper; null if invalid
  return claims ? { user: claims.sub, role: claims.role } : null;
});
```

```go
// Go (Gin): req is *gin.Context; Echo: *echo.Context; net/http: *http.Request
app.IdentifyUser(func(req any) *trappsec.AuthContext {
	c := req.(*gin.Context)
	claims, err := auth.VerifyToken(c.GetHeader("Authorization")) // the app's helper
	if err != nil {
		return nil
	}
	return &trappsec.AuthContext{User: claims.Subject, Role: claims.Role}
})
```

## 3. Traps

```python
ts.trap("/api/v2/workspaces/{workspace_id}/<decoy>") \
    .methods("POST") \
    .intent("privilege_escalation") \
    .respond(403, {"error": {"code": "forbidden", "message": "..."}}) \
    .if_unauthenticated(401, {"error": {"code": "unauthenticated", "message": "..."}})
```

```javascript
ts.trap('/api/v2/workspaces/:workspaceId/<decoy>')
  .methods('POST')
  .intent('privilege_escalation')
  .respond({ status: 403, body: { error: { code: 'forbidden', message: '...' } } })
  .if_unauthenticated({ status: 401, body: { error: { code: 'unauthenticated', message: '...' } } });
```

```go
app.Trap("/api/v2/workspaces/:workspaceId/<decoy>").
	Methods("POST").
	Intent("privilege_escalation").
	Respond(trappsec.ResponseConfig{Status: 403, Body: map[string]any{"error": "..."}}).
	IfUnauthenticated(trappsec.ResponseConfig{Status: 401, Body: map[string]any{"error": "..."}})
```

- **Path syntax** is the framework's own: `{id}` (FastAPI/Starlette/Litestar), `<id>` (Flask), `<str:id>` (Django), `:id` (Express/Koa/Hono/Fastify/NestJS/Gin/Echo), `{id}` (Hapi and Go net/http). Use the full public path, including mount prefixes.
- **Methods** default to `["GET", "POST"]`. Set them explicitly.
- **Body** is a dict/object, a string, or a function of the request returning one of those (Python `lambda r: {...}`, Node `(req) => ({...})`, Go `func(any) any`; Echo also accepts `func(*echo.Context) any`). String bodies are sent raw. Set `mime_type` / `MIMEType` for anything that isn't `application/json`.
- **Failing bodies.** A function body that throws falls back to `{}`. Keep it simple and deterministic.
- **Headers.** Responses cannot set custom headers (see backend-traps.md §3).

## 4. Watches (honey fields)

```python
ts.watch("/api/v2/me") \
    .body("role", intent="privilege_escalation") \
    .body("plan", default="free", intent="entitlement_abuse") \
    .body("org_id", default=lambda r: current_org_id(r), intent="cross_tenant_access") \
    .query("<param>", intent="reconnaissance")
```

```javascript
ts.watch('/api/v2/me')
  .body('role', { intent: 'privilege_escalation' })
  .body('plan', { defaultValue: 'free', intent: 'entitlement_abuse' })
  .body('orgId', { defaultValue: (req) => currentOrgId(req), intent: 'cross_tenant_access' })
  .query('<param>', { intent: 'reconnaissance' });
```

```go
app.Watch("/api/v2/me").
	Body("role", trappsec.NoDefault, "privilege_escalation").
	Body("plan", "free", "entitlement_abuse").
	Body("org_id", func(req any) any { return currentOrgID(req) }, "cross_tenant_access").
	Query("<param>", trappsec.NoDefault, "reconnaissance")
```

- **Defaults.** No default means any presence alerts. With a default, only a different value alerts. A callable default is evaluated per request; if it throws, it is treated as "no default".
- **Callables are synchronous.** Callable defaults, dynamic bodies and `identify_user` are called synchronously in every language. They cannot await a database call. A callback that returns a Promise or coroutine is treated as failed:
  - a failed callable default means "no default", so every request alerts;
  - a failed `identify_user` means anonymous.

  Use data already on the request, such as session claims or values set by middleware.
- **Callables can run before route-level middleware.** Watches are inspected when the route is entered, which can be before route-level middleware runs (Express does this when the body was parsed by app-level middleware). A callable default that reads `req.user` set by per-route auth will throw, fall back to "no default", and alert on every legitimate echo. Derive the value from the request itself, verifying the token or session the way `identify_user` does. Then confirm with the real UI's request that no event fires.
- **Path.** The watch path must equal the route pattern the app registered (same parameter names and converters, full prefix).
- **Stripping.** Every occurrence of a watched key is stripped before the handler runs. Duplicate parameters alert unless every value matches.
- **Matching.** Values match canonically: `"true"` equals `true`, `"5"` equals `5`; strings compare exactly. Python and Node keys are case-sensitive. Go keys are case-insensitive, so never watch a name that differs from a real field only by case.
- **What is inspected.** JSON objects, arrays of objects, urlencoded and multipart text fields. Express/Koa need their body parsers registered before `Sentry`. Go inspects bodies up to 1 MiB by default (`app.SetMaxBodyBytes(n)`; set it at least as large as the route's own limit).

## 5. Default responses and templates

Set both defaults to the app's real shapes, so no trap ever emits trappsec's defaults (`401 {}` and `200 {}`):

```python
ts.default_responses["unauthenticated"] = {"status_code": 401, "response_body": REAL_401_BODY, "mime_type": "application/json"}
ts.default_responses["authenticated"] = {"status_code": 403, "response_body": REAL_403_BODY, "mime_type": "application/json"}
ts.template("legacy_gone", 410, REAL_410_BODY, "application/json")   # then .respond(template="legacy_gone")
```

```javascript
ts.default_responses.unauthenticated = { status_code: 401, response_body: REAL_401_BODY, mime_type: 'application/json' };
ts.default_responses.authenticated = { status_code: 403, response_body: REAL_403_BODY, mime_type: 'application/json' };
ts.template('legacy_gone', 410, REAL_410_BODY);                       // then .respond({ template: 'legacy_gone' })
```

```go
app.SetDefaultUnauthenticated(401, real401Body, "application/json")
app.SetDefaultAuthenticated(403, real403Body, "application/json")
app.Template("legacy_gone", 410, real410Body, "application/json")    // then Respond(trappsec.ResponseConfig{Template: "legacy_gone"})
```

Defaults resolve at bootstrap, so the order of calls doesn't matter. A template can't be combined with status/body/mime in the same call.

## 6. Alert outputs and logging

- **Log handler: always on.** One JSON line per event on the `trappsec` logger. Python never configures logging, so make sure a handler at INFO receives the `trappsec` logger. Node logs to `console`. Go uses a standard `log.Logger`.
- **Webhooks:**
  - Python: `ts.add_webhook(url, secret=..., headers=..., heartbeat_interval=..., template=..., alerts_only=True)`.
  - Node: the same keys in an options object.
  - Go: `app.AddWebhook(url, &trappsec.WebhookOptions{...})`.

  Read URLs and secrets from the environment. Set `secret` so deliveries are signed.
- **Slack:** `ts.add_slack(url)` / `app.AddSlack(url, nil)`. Don't point `add_webhook` at Slack.
- **OpenTelemetry:** `ts.add_otel()` / `app.AddOTEL()`.
- **Alerts vs. signals.** Webhook and Slack forward only alerts (identified users) by default; logs and OTel get everything.
- **Event shapes:** `trappsec.trap_hit` (`intent`), `trappsec.watch_hit` (`found_fields[]` with type/field/value/intent), plus common fields (`type`, `path`, `method`, `ip`, `user`, `role`, `user_agent`, `app`). Full schema: https://trappsec.dev/events/.
- **`trigger`.** `ts.trigger(request, reason, intent, metadata)` emits a `rule_hit` from your own code. It suits impossible states you can recognize in real handlers. Only add it when the plan calls for it.

## 7. CSRF, proxies, shutdown, workers

- **CSRF.** Django, Flask-WTF, Litestar and Tornado CSRF exempt traps automatically. Other CSRF middleware needs a skip for traps:
  - Express: `app.use((req, res, next) => ts.is_trap(req) ? next() : csrfProtection(req, res, next))`.
  - Fastify: `onRequest` hook with `ts.is_trap(req)`.
  - Echo: `middleware.CSRFWithConfig(middleware.CSRFConfig{Skipper: app.IsTrap})`.
  - gorilla/csrf and net/http `CrossOriginProtection`: check `app.Sentry.IsTrap(r)` in a wrapping handler.
  - starlette-csrf: wrap it so trap requests bypass it.
- **Client IP.** trappsec never trusts forwarding headers by default. Behind a proxy, configure the framework's trusted proxies (Express `trust proxy`, Gin `SetTrustedProxies`, uvicorn `forwarded_allow_ips`) or set `override_source_ip(cb)` to a header your edge overwrites.
- **Shutdown.** Call `close()` to flush queued deliveries: Python `atexit.register(ts.close)`, Node `await ts.close()`, Go `app.Close(ctx)`. Hook it into the app's existing graceful-shutdown code. In Node, adding a bare `process.on('SIGTERM', ...)` replaces the default exit, so the handler must call `process.exit` itself.
- **Workers.** Create the Sentry inside each worker, after fork (app factory, worker init). With gunicorn `preload_app`, don't create it in the master.

## 8. Gotchas

- Trap paths that exactly duplicate a real route and method fail at bootstrap. That's intended; rename the decoy.
- NestJS: a handler that reads `req.body` via `@Req()` without any `@Body()` parameter still produces the event, but the honey field is not stripped. Prefer `@Body()`.
- Litestar before 2.13 and Sanic before 24.6 miss honey fields.
- Global middleware that rejects anonymous requests also answers anonymous requests to traps. That matches real routes, but you get no signals.
- uvicorn trusts `X-Forwarded-For` from 127.0.0.1 by default. Set `forwarded_allow_ips` correctly or alerts carry the wrong IP.

## 9. Versions and known issues

### Newer releases

Releases after 0.2.0 add consistent aliases alongside the portable forms used in this sheet. The portable forms keep working.
- **Default-response setters:** `default_response(...)` and `default_unauthenticated_response(...)`, with the same arguments as `respond` (Go: `DefaultResponse` / `DefaultUnauthenticatedResponse`).
- **Node:** `{ default, intent }` on watch fields, and `close(seconds)`.
- **Go:** option helpers such as `trappsec.Default(x)` and `trappsec.Intent(s)`.

### trappsec 0.2.0

These behaviors were verified against 0.2.0 as published on npm and PyPI. They are fixed in later releases. If 0.2.0 is all the registry offers, tell the user, and either wait for or pin a newer release, or apply the workarounds below.

**Node:**
- **Express 4 crash.** Declaring any watch makes `app.listen()` throw `'app.router' is deprecated!`.
- **Traps behind catch-alls.** Traps are appended after all existing routes when `listen()` runs, so a catch-all route or 404 middleware (`app.use('/api', notFound)`) answers instead of them.
- **Missing APIs.** There is no `is_trap`, `bootstrap()`, `close()` or `trigger()`.

**Python:**
- **FastAPI order.** Create the Sentry before `include_router(...)` and run with lifespan (`with TestClient(app)`). Otherwise watches never fire, or routes fail until startup has run.
- **String bodies.** A string body with `application/json` is JSON-encoded a second time.
- **Logging.** trappsec calls `logging.basicConfig`, which can reconfigure the app's root logger.
- **Missing APIs.** There is no `is_trap`, `bootstrap()` or `close()`.

**Both:**
- **Order matters.** Default responses are copied when `.trap()` is called, so set them before declaring traps.
- **Exact matching.** Value matching is exact (`!=` / `!==`). Form and query values are strings (`"800"` does not match `800`; `"false"` does not match `false`), and Node compares arrays by reference.
- **Unguarded callbacks.** A throwing `identify_user`, callable default or dynamic body can fail the request or leave the field unstripped. Catch inside your callbacks.
- **Event shape.** Signals omit `user`/`role`, and webhook signatures are a bare hex HMAC of the body.

If you must ship on 0.2.0, the integration's own install steps can be called from a thin adapter at the right point. For Express: mount the traps on a router before the catch-all, and wrap the watched routes. This relies on internals, so pin the exact version and cover the adapter with tests that fire every tripwire.
