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

*   Call `close()` / `Close()` during graceful shutdown to flush pending events (default timeout 5 s). A hard kill loses queued events.
*   If the receiver is down for long, the queue fills and further events are dropped with a warning (at most once per 60 s). Watch your logs for it.
*   Up to 2 retries with short backoff happen in the worker.

```python
import atexit
atexit.register(ts.close)
```

```javascript
process.on("SIGTERM", async () => { await ts.close(); process.exit(0); });
```

```go
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()
_ = ts.Close(ctx)
```

## Performance

*   Trap and watch lookups are O(1) hash lookups per request.
*   Requests with no matching watch are untouched: no body read, no parsing.
*   For watched routes the body is parsed once and restored for your handler. The Go adapters buffer bodies up to 1 MiB by default (`SetMaxBodyBytes`); larger bodies are passed through uninspected. Set the limit to at least your watched routes' own maximum body size, so padding a request past it cannot bypass inspection. With Gin, call `InstallSentry` before creating route groups.
*   Handlers run off the request path; the cost of an alert on the request thread is building and enqueueing one small event.
*   Callbacks (`identify_user`, `override_source_ip`) run on every trap/watch hit, so keep them cheap and non-blocking. They are wrapped in try/catch and never break the request.

## Body parsers

Watches on request bodies need a parsed body.

*   **Express / Koa:** register `express.json()` / `express.urlencoded()` (or `koa-bodyparser`) *before* installing Sentry or declaring watches. Traps are inserted before the first route layer and after ordinary middleware, so your auth and body-parser middleware run first and `identify_user` can see `req.user`.
*   **Fastify, Hapi, NestJS:** the framework parses bodies before the trappsec hook runs.
*   **Python / Go:** the integration reads and restores the body itself.

## Startup and test clients

Traps are installed at bootstrap: the framework startup hook (lifespan, `listen`, `Run`, `Start`) calls it, and the first request calls it lazily so test clients and custom servers are covered. You may also call `bootstrap()` / `Bootstrap()` explicitly. In Go, `http.Server{Handler: app}` works and protects the server.

Order does not matter for configuration: default responses are resolved at bootstrap, so you may set them after `.trap()` calls. A trap whose path and method exactly duplicate a real route fails at bootstrap with a clear error; rename or remove one.

## Framework caveats

*   **Django:** traps are `csrf_exempt` so scanners get the decoy response instead of a CSRF error. Under WSGI with multiple threads, bootstrap is lock-guarded.
*   **Express / NestJS-Express:** sub-routers are covered. Routes registered before Sentry is installed are covered too; where a framework cannot do that, a startup warning names the uncovered routes.
*   **Koa / Express trap placement:** traps sit after middleware and before your first route. Middleware that rejects unauthenticated users before routes will also reject unauthenticated scanners, hiding the decoy; keep the decoy reachable if you want `signal` events.
*   **Gin / Echo:** the default IP is the RemoteAddr host; configure trusted proxies or `OverrideSourceIP`.
*   **Go:** all modules require Go 1.26+ (the OpenTelemetry dependency requires it). net/http traps use method-qualified mux patterns.
*   **Tornado, Sanic, Litestar, Starlette:** run the app normally; no extra configuration beyond the usual `Sentry(app, ...)` call.
*   **Logging:** trappsec uses the `trappsec` logger and never calls `logging.basicConfig`. Attach a handler at INFO or above or alerts will not appear in your logs.
