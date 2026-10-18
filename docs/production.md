---
layout: default
title: Production Deployment
permalink: /production/
tagline: "Proxies, workers, shutdown, performance and framework caveats."
---

## Proxies and client IP

Alerts are only useful if the `ip` is the real client. By default trappsec uses the transport peer address (and Express `req.ip`, which honors Express' `trust proxy`). It never trusts `X-Forwarded-For` or `X-Real-IP` on its own, because anyone can forge them. Behind a load balancer or CDN, tell the framework which proxies to trust, or override the extractor:

<div class="lang-switcher">
  <button class="lang-btn active" onclick="switchLang('python')">Python</button>
  <button class="lang-btn" onclick="switchLang('node')">Node.js</button>
  <button class="lang-btn" onclick="switchLang('go')">Go</button>
</div>

<div class="lang-content" data-lang="python" markdown="1">

```python
# Only if your proxy overwrites this header and clients cannot reach the app directly
ts.override_source_ip(lambda r: r.headers.get("x-real-ip") or r.remote_addr)
```

</div>
<div class="lang-content" data-lang="node" markdown="1">

```javascript
app.set("trust proxy", 1);                 // number of proxy hops you control
ts.override_source_ip((req) => req.ip);    // req.ip now honors trust proxy
```

</div>
<div class="lang-content" data-lang="go" markdown="1">

```go
// Gin and Echo default to the RemoteAddr host.
ts.OverrideSourceIP(func(req any) string {
    c := req.(*gin.Context)
    return c.ClientIP() // honors gin's SetTrustedProxies
})
```

</div>

If your override reads a header, make sure your edge strips client-supplied copies of it. An override that throws falls back to the default extractor.

## Multiple workers and heartbeats

Each worker process (gunicorn/uvicorn workers, Node cluster, multiple pods) has its own Sentry, its own queue and its own heartbeat. Consequences:

*   A heartbeat arrives once per worker per interval. Key your receiver on `service` + `environment` (heartbeats carry no hostname) and alert on *no heartbeat at all*, not on a count.
*   Set `heartbeat_interval` to at least a minute or two, and alert after several missed intervals.
*   Events are never aggregated across workers; deduplicate in your SIEM if needed.
*   Create the Sentry **after** forking (inside the app factory / worker init), not in the master process, so the background delivery thread exists in each worker. Threads do not survive `fork()`.

## Async delivery and shutdown

Webhook and Slack events are queued in memory (capacity 1000) and sent by a background worker; the request path is never blocked and failures never reach users. This means:

*   Call `close()` / `Close()` during graceful shutdown to flush pending events (default timeout 5 s; Python and Node take the timeout in seconds, Go a context). A hard kill loses queued events. Every example app in `examples/` shows the shutdown hook for its framework.
*   If the receiver is down for long, the queue fills and further events are dropped with a warning (at most once per 60 s). Watch your logs for it.
*   Up to 2 retries with short backoff happen in the worker.

```python
import atexit
atexit.register(ts.close)  # runs on a normal interpreter exit; uvicorn, gunicorn and Sanic turn SIGTERM into one
```

```javascript
for (const sig of ["SIGINT", "SIGTERM"]) {
    process.once(sig, async () => { await ts.close(); process.exit(0); });
}
```

```go
sig := make(chan os.Signal, 1)
signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
go func() {
    <-sig
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    _ = app.Close(ctx)
    os.Exit(0)
}()
```

## Performance

*   Trap and watch lookups are O(1) hash lookups per request.
*   Requests with no matching watch are untouched: no body read, no parsing.
*   For watched routes the body is parsed once and restored for your handler. The Go adapters buffer bodies up to 1 MiB by default (`SetMaxBodyBytes`); larger bodies are passed through uninspected. Set the limit to at least your watched routes' own maximum body size, so padding a request past it cannot bypass inspection. Litestar and Starlette/FastAPI bodies over 10 MiB are also passed through uninspected; Litestar's default `request_max_body_size` (10 MB) already rejects them, so do not raise it above 10 MiB on apps with body watches. With Gin, middleware registered before `InstallSentry` runs before inspection, so `IdentifyUser` sees what it sets; routes registered earlier, including routes in groups created earlier, are still watched. Unwatched routes pay nothing extra unless a watched route lacks the watch middleware (registered before `InstallSentry`). In Echo, a watched request that an earlier middleware rejects (auth, rate limit, CSRF) is still reported, after the chain returns; its honey fields cannot be stripped because the response is already decided. net/http requests that the mux answers with a redirect are not inspected; the redirected request is.
*   Handlers run off the request path; the cost of an alert on the request thread is building and enqueueing one small event.
*   Callbacks (`identify_user`, `override_source_ip`) run on every trap/watch hit, so keep them cheap and non-blocking. They are wrapped in try/catch and never break the request.

## Body parsers

Watches on request bodies need a parsed body.

*   **Express / Koa:** app-level parsers (`express.json()`, `express.urlencoded()`, `koa-bodyparser`) and route-level ones (`app.post('/x', multer().none(), handler)`, `router.post('/x', bodyParser(), handler)`) both work. When a watched route is entered before its body is parsed, body inspection finishes right before the route's own handler, after route-level middleware has run; if a route middleware answers first, what was already found is still reported. Traps are inserted before the first route layer and after ordinary middleware, so your auth and body-parser middleware run first and `identify_user` can see `req.user`.
*   **Fastify:** bodies parsed by a content-type parser or by a `preValidation` hook (e.g. `@fastify/multipart` with `attachFieldsToBody`) are inspected, whether that plugin is registered before or after Sentry.
*   **NestJS:** JSON and form bodies are parsed by the platform; multipart bodies parsed by `FileInterceptor` / `AnyFilesInterceptor` are inspected from a global pipe that runs after all interceptors, so honey fields are stripped before the controller receives `@Body()` (a single `@Body('field')` that is a honey field receives `undefined`). A handler that reads `req.body` through `@Req()` without any `@Body()` parameter still gets the event, but the field is not stripped.
*   **Hapi:** the framework parses bodies before the trappsec hook runs.
*   **Hono:** trappsec reads JSON, urlencoded and multipart bodies itself (up to 10 MiB) through `c.req`, so a body a middleware already read is still inspected, and rebuilds `c.req.raw` without the honey fields: `c.req.json()`, `parseBody()`, `formData()`, validators and `c.req.raw` all see the stripped request.
*   **Python / Go:** the integration reads and restores the body itself.

## Startup and test clients

Traps are installed at bootstrap: the framework startup hook (lifespan, `listen`, `Run`, `Start`) calls it, and the first request calls it lazily so test clients and custom servers are covered. You may also call `bootstrap()` / `Bootstrap()` explicitly. In Go, `http.Server{Handler: app}` works and protects the server.

Order does not matter for configuration: default responses are resolved at bootstrap, so you may set them after `.trap()` calls. A trap whose path and method exactly duplicate a real route fails at bootstrap with a clear error; rename or remove one.

## Framework caveats

*   **Django:** traps are `csrf_exempt` so scanners get the decoy response instead of a CSRF error. Under WSGI with multiple threads, bootstrap is lock-guarded. Call `ts.bootstrap()` at the end of `wsgi.py` / `asgi.py` so a trap that conflicts with a real route fails at startup; on the lazy first-request bootstrap it is only logged and skipped ([details](/supported-frameworks/#django-traps-on-real-urls)).
*   **CSRF protection elsewhere:** Litestar traps are excluded from `CSRFConfig` automatically and Tornado traps from `xsrf_cookies`. Hono's `hono/csrf` middleware runs before traps, so skip it for them: `const protect = csrf(); app.use('*', (c, next) => ts.is_trap(c) ? next() : protect(c, next))`. Echo's `middleware.CSRF` runs before every route, so pass the trap skipper: `e.Use(middleware.CSRFWithConfig(middleware.CSRFConfig{Skipper: app.IsTrap}))`. Every Go `App` has an `IsTrap` that takes its framework's request type (`*echo.Context`, `*gin.Context`, `*http.Request`). Flask-WTF's `CSRFProtect` exempts traps automatically too. With other CSRF middleware (csurf, csrf-csrf, `@fastify/csrf-protection`, crumb, koa-csrf, starlette-csrf, gorilla/csrf, net/http's `CrossOriginProtection`), skip it for traps with `is_trap(request)` / `app.IsTrap(req)` (see the API reference and the per-framework table in [Supported Frameworks](/supported-frameworks/#framework-differences)); otherwise a POST to a trap gets a CSRF error instead of the decoy, which disables the trap and gives it away.
*   **Express / NestJS-Express:** sub-routers are covered. Routes registered before Sentry is installed are covered too; where a framework cannot do that, a startup warning names the uncovered routes.
*   **Koa / Express / Hono trap placement:** traps sit after middleware and before your first route (on Hono, middleware is `app.use()` or an `app.all()` handler that takes `next`). Middleware that rejects unauthenticated users before routes will also reject unauthenticated scanners, hiding the decoy; keep the decoy reachable if you want `signal` events.
*   **Gin / Echo:** the default IP is the RemoteAddr host; configure trusted proxies or `OverrideSourceIP`.
*   **uvicorn (FastAPI, Starlette, Litestar):** uvicorn rewrites the client address from `X-Forwarded-For` for requests from `127.0.0.1` by default (`proxy_headers=True`, `forwarded_allow_ips="127.0.0.1"`). That is right behind a local reverse proxy and wrong if anything local can reach the app directly; set `forwarded_allow_ips` to your proxy's address, or `proxy_headers=False` when there is none.
*   **Go:** all modules require Go 1.26+ (the OpenTelemetry dependency requires it). net/http traps use method-qualified mux patterns.
*   **Tornado, Sanic, Litestar, Starlette:** run the app normally; no extra configuration beyond the usual `Sentry(app, ...)` call.
*   **Logging:** trappsec uses the `trappsec` logger and never calls `logging.basicConfig`. Attach a handler at INFO or above or alerts will not appear in your logs.
