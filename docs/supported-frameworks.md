---
layout: default
title: Supported Frameworks
permalink: /supported-frameworks/
tagline: "All frameworks supported across Python, Node.js, and Go."
---

<table>
  <thead>
    <tr>
      <th>Language</th>
      <th>Framework</th>
      <th>Minimum version</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td rowspan="7"><b>Python</b><br>3.10+</td>
      <td>Flask</td>
      <td>2.0</td>
    </tr>
    <tr>
      <td>FastAPI</td>
      <td>0.95</td>
    </tr>
    <tr>
      <td>Starlette</td>
      <td>0.24</td>
    </tr>
    <tr>
      <td>Litestar</td>
      <td>2.13</td>
    </tr>
    <tr>
      <td>Django</td>
      <td>3.2</td>
    </tr>
    <tr>
      <td>Sanic</td>
      <td>24.6</td>
    </tr>
    <tr>
      <td>Tornado</td>
      <td>6.0</td>
    </tr>
    <tr>
      <td rowspan="5"><b>Node.js</b><br>20+</td>
      <td>Express</td>
      <td>4.17 (and 5.x)</td>
    </tr>
    <tr>
      <td>NestJS</td>
      <td>10</td>
    </tr>
    <tr>
      <td>Fastify</td>
      <td>4</td>
    </tr>
    <tr>
      <td>Hapi</td>
      <td>20</td>
    </tr>
    <tr>
      <td>Koa</td>
      <td>2.13 with @koa/router 10</td>
    </tr>
    <tr>
      <td rowspan="4"><b>Go</b><br>1.26+</td>
      <td>net/http</td>
      <td>standard library</td>
    </tr>
    <tr>
      <td>Gin</td>
      <td>1.12</td>
    </tr>
    <tr>
      <td>Echo</td>
      <td>5.2</td>
    </tr>
    <tr>
      <td>chi, gorilla/mux and other <code>http.Handler</code> routers</td>
      <td>any; tested with chi 5.4 and gorilla/mux 1.8.1</td>
    </tr>
  </tbody>
</table>

Minimum versions are the oldest releases the integration tests pass on. CI checks them on every change: each Python framework on Python 3.10, every Node framework on Node 20. Go adapters require these versions in their `go.mod`, so Go's minimum version selection enforces them; the `handler` adapter has no router dependency and is tested against current chi and gorilla/mux releases. Older releases may work but are not tested; Litestar before 2.13 and Sanic before 24.6 are known to miss honey fields.

## Framework differences

The API is the same in every framework; these are the places where the framework shows through. "Request object" is what trappsec passes to `identify_user`, `override_source_ip`, callable defaults and dynamic bodies, and what you pass to `trigger` and `is_trap`.

| Framework | Request object | Body parsing for `body` watches | CSRF middleware and traps | Known limits |
|---|---|---|---|---|
| Flask | `flask.request` | by trappsec | Flask-WTF `CSRFProtect`: exempt automatically | |
| FastAPI / Starlette | `starlette.requests.Request` | by trappsec | starlette-csrf: route traps around it with `ts.is_trap` ([example](/api/#is_trap--istrap)) | |
| Litestar | `litestar.Request` | by trappsec | `CSRFConfig`: exempt automatically | bodies over 10 MiB pass uninspected; 2.13+ |
| Django | `django.http.HttpRequest` | by trappsec | `CsrfViewMiddleware`: exempt automatically | WSGI and ASGI |
| Sanic | `sanic.Request` | by trappsec | no built-in CSRF; skip third-party middleware with `ts.is_trap` | 24.6+ |
| Tornado | `tornado.httputil.HTTPServerRequest` (`self.request`) | by trappsec | `xsrf_cookies`: exempt automatically | |
| Express | `req` | your parser (`express.json()`, multer, …), app- or route-level | csurf / csrf-csrf: skip with `ts.is_trap(req)`, registered at app level | sub-routers (also under parameterised mounts) are covered; mounted sub-apps (`app.use('/x', express())`) are not, and a warning names them: install trappsec on the sub-app |
| Fastify | `request` | Fastify content-type parsers and `@fastify/multipart` | `@fastify/csrf-protection`: skip with `ts.is_trap(req)` in an `onRequest` hook | |
| Koa | `ctx` | your parser (`koa-bodyparser`, …), app- or route-level | koa-csrf: skip with `ts.is_trap(ctx)` | register `router.routes()` directly: routers wrapped in `koa-compose` or `koa-mount` are not seen (a warning says so) |
| Hapi | `request` | Hapi | crumb: skip with `ts.is_trap(request)` | |
| NestJS | the platform's request (Express `req` or Fastify `request`) | the platform; multipart via `FileInterceptor` / `AnyFilesInterceptor` | as for the underlying platform | a handler reading `req.body` through `@Req()` with no `@Body()` parameter gets the event, but the multipart honey field is not stripped |
| net/http | `*http.Request` | by trappsec (up to `SetMaxBodyBytes`, 1 MiB) | gorilla/csrf, `CrossOriginProtection`: skip with `app.IsTrap(r)` | serve through `app`; watches inside a mounted sub-mux are logged as unreachable |
| Gin | `*gin.Context` | by trappsec (up to `SetMaxBodyBytes`, 1 MiB) | skip with `app.IsTrap(c)` in your CSRF middleware | serve through `app` (`app.Run*`, or `app.Handler()`, which honours `UseH2C`) |
| chi, gorilla/mux, any `http.Handler` (`handler` package) | `*http.Request` | by trappsec (up to `SetMaxBodyBytes`, 1 MiB) | wrap your CSRF middleware around the router, or skip with `app.IsTrap(r)` if it wraps the App | serve through `app`; pass `app.MatchRoutes(...)` so real routes beat look-alike traps, duplicates fail at bootstrap, and watches follow the matched route ([example](/api/#installsentryrouter-service-environment-string-app)); traps and watches run before the router's middleware, so `IdentifyUser` sees headers and cookies but not values that middleware adds; traps are not router routes, so a trap path requested with a method the trap does not declare gets the router's 404 where a real route would answer 405: declare every method a real route at that path would plausibly accept; with `MatchRoutes`, a trap does not answer its path with a trailing slash (chi and gorilla/mux answer those 404) |
| Echo | `*echo.Context` | by trappsec (up to `SetMaxBodyBytes`, 1 MiB) | `middleware.CSRF`: `Skipper: app.IsTrap` | serve through `app` (`app.Start`, `echo.StartConfig{...}.Start(ctx, app)`, or `app` as the handler); requests rejected by earlier middleware are reported but not stripped; Echo v4 is not supported, and Echo before 5.2 has a route-protection bypass (GO-2026-6293) |

In Go, every adapter's `App.IsTrap` takes that framework's request type, as in the table; `app.Sentry.IsTrap(req any)` accepts any of them. Every adapter has `InstallSentry(router, service, environment)` and `Use(sentry, router)` (to wire a Sentry you created with `trappsec.NewSentry`).

> Missing your favorite framework? [Raise a request here](https://github.com/trappsec-dev/trappsec/discussions/new?category=feature-requests).
