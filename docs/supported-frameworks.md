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
      <td rowspan="7"><b>Python</b><br>3.11+</td>
      <td>Flask</td>
      <td>3.0</td>
    </tr>
    <tr>
      <td>FastAPI</td>
      <td>0.115.3</td>
    </tr>
    <tr>
      <td>Starlette</td>
      <td>0.40</td>
    </tr>
    <tr>
      <td>Litestar</td>
      <td>2.13</td>
    </tr>
    <tr>
      <td>Django</td>
      <td>5.2 (LTS)</td>
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
      <td rowspan="6"><b>Node.js</b><br>22+</td>
      <td>Express</td>
      <td>4.17 (and 5.x)</td>
    </tr>
    <tr>
      <td>NestJS</td>
      <td>11</td>
    </tr>
    <tr>
      <td>Fastify</td>
      <td>5</td>
    </tr>
    <tr>
      <td>Hapi</td>
      <td>21</td>
    </tr>
    <tr>
      <td>Koa</td>
      <td>3.0 with @koa/router 13</td>
    </tr>
    <tr>
      <td>Hono</td>
      <td>4.2 (any runtime; the default client IP is read from @hono/node-server)</td>
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

Minimum versions are the oldest releases the integration tests pass on. CI checks them on every change: each Python framework on Python 3.11, every Node framework on Node 22. Go adapters require these versions in their `go.mod`, so Go's minimum version selection enforces them; the `handler` adapter has no router dependency and is tested against current chi and gorilla/mux releases. Older releases may work but are not tested; Litestar before 2.13 and Sanic before 24.6 are known to miss honey fields.

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
| Hono | `c` (the Hono `Context`) | by trappsec (JSON, urlencoded, multipart; up to 10 MiB): `c.req.json()`, `parseBody()`, `formData()` and `c.req.raw` all see the stripped request | `hono/csrf`: skip with `app.use('*', (c, next) => ts.is_trap(c) ? next() : protect(c, next))` | install Sentry before `serve()` / `export default app`: it hooks `app.fetch`. Middleware (`app.use()`, or `app.all()` with a `(c, next)` handler) runs before traps; `app.all()` with a `(c)` handler is a route. Outside `@hono/node-server`, set `override_source_ip` (e.g. with Hono's `getConnInfo`), or every event records `0.0.0.0` |
| NestJS | the platform's request (Express `req` or Fastify `request`) | the platform; multipart via `FileInterceptor` / `AnyFilesInterceptor` | as for the underlying platform | a handler reading `req.body` through `@Req()` with no `@Body()` parameter gets the event, but the multipart honey field is not stripped |
| net/http | `*http.Request` | by trappsec (up to `SetMaxBodyBytes`, 1 MiB) | gorilla/csrf, `CrossOriginProtection`: skip with `app.IsTrap(r)` | serve through `app`; watches inside a mounted sub-mux are logged as unreachable |
| Gin | `*gin.Context` | by trappsec (up to `SetMaxBodyBytes`, 1 MiB) | skip with `app.IsTrap(c)` in your CSRF middleware | serve through `app` (`app.Run*`, or `app.Handler()`, which honours `UseH2C`) |
| chi, gorilla/mux, any `http.Handler` (`handler` package) | `*http.Request` | by trappsec (up to `SetMaxBodyBytes`, 1 MiB) | wrap your CSRF middleware around the router, or skip with `app.IsTrap(r)` if it wraps the App | serve through `app`; pass `app.MatchRoutes(...)` so real routes beat look-alike traps, duplicates fail at bootstrap, and watches follow the matched route ([example](/api/#installsentryrouter-service-environment-string-app)); traps and watches run before the router's middleware, so `IdentifyUser` sees headers and cookies but not values that middleware adds; with `MatchRoutes`, a trap does not answer its path with a trailing slash (chi and gorilla/mux answer those 404); see [trap responses](#where-a-trap-can-still-differ-from-a-real-route) for middleware and 405s |
| Echo | `*echo.Context` | by trappsec (up to `SetMaxBodyBytes`, 1 MiB) | `middleware.CSRF`: `Skipper: app.IsTrap` | serve through `app` (`app.Start`, `echo.StartConfig{...}.Start(ctx, app)`, or `app` as the handler); requests rejected by earlier middleware are reported but not stripped; Echo v4 is not supported, and Echo before 5.2 has a route-protection bypass (GO-2026-6293) |

### Where a trap can still differ from a real route

Traps are registered where each framework's routing treats them like your own routes, and the integration tests compare a trap with a real sibling route on the same probe (wrong method, `Allow`, trailing slash, case, doubled slash, escaped path, header order). These differences remain. Each is measured against a real route next to the trap, and each has an app-side fix.

| Framework | Difference | What to do |
|---|---|---|
| Express | A trap goes into the mounted router (`app.use('/api/v1', api)`) that serves its path, so it follows that router's `strict` / `caseSensitive` options and Allow header. A trap whose path no mounted router serves, or whose router is mounted at more than one path or under a mount parameter the trap fills with a literal, gets its own router at `/`. Router-level middleware (`api.use(...)`) runs before a trap placed in that router, as it does for the real routes. | Put traps under a prefix that a mounted router serves, next to the routes they imitate. |
| Fastify | Traps are registered in the root context, so hooks (`onSend`, `onRequest`), `setErrorHandler` and `setNotFoundHandler` registered inside an encapsulated plugin do not run for them: a header that plugin adds (such as `cache-control: no-store`) is missing, and malformed JSON gets Fastify's default error body instead of yours. | Register response-shaping hooks and the error handler on the root instance, or wrap that plugin with `fastify-plugin` so they apply app-wide. |
| Fastify | A trap has no body schema. A real route with one answers an invalid body such as `{}` with `400` before `preHandler` auth runs; the trap answers with its `401`/`403`. | Authenticate in an `onRequest` hook (the Fastify recommendation), so real routes also answer `401` before validation. |
| Gin | Traps are registered on the engine, so middleware attached to a route group (`api := r.Group("/api", cors, secHeaders)`) does not run for them. | Register response-shaping middleware (CORS, security headers, request IDs) with `engine.Use` before `InstallSentry`; keep only route-specific middleware on groups. |
| chi, gorilla/mux (`handler`) | The App answers traps before the router, so middleware added with `r.Use` (CORS, request IDs, security headers) does not run for them. | **Wrap that middleware around the App** instead of registering it with `r.Use`: `http.ListenAndServe(addr, cors(requestID(app)))`. |
| chi, gorilla/mux (`handler`) | Traps are not router routes: a method the trap does not declare, including `HEAD` and `OPTIONS`, gets the router's `404` where chi answers `405` with `Allow`. A real route at the same path keeps its own `405`, but its `Allow` header does not list the trap's methods. | Declare every method a real route at that path would plausibly accept. |
| chi (`handler`) | Traps match the decoded path by default (as gorilla/mux does), but chi routes the escaped one: `/projects/p1/%74ransfers` or `/projects/prj_x%2Ftransfers` would reach the trap where chi answers `404` or `405`. | Call `app.UseRawPath()` and pass the raw path to chi's `Find` in `MatchRoutes` ([example](/api/#installsentryrouter-service-environment-string-app)). Do the same for gorilla/mux with `Router.UseEncodedPath()`. |
| FastAPI | Traps are not in `/openapi.json`, while a lure in your client bundle may name them. App-level `dependencies=[...]` do run for traps; router-level ones (`include_router(..., dependencies=...)`) do not, since traps belong to the app. | If you publish the schema, add the lure endpoints to it with a custom `app.openapi()`, or do not serve the schema in production (`FastAPI(openapi_url=None)`). Put dependencies that shape every response at app level. |
| Django REST framework | The trap view answers a method it does not declare with Django's empty `text/html` `405`. DRF authenticates first, so it answers an anonymous wrong-method request with `401` JSON and a signed-in one with `405 {"detail": "Method \"GET\" not allowed."}`; a signed-in `OPTIONS` gets `200` with DRF metadata. | Declare every method a real view at that path accepts, including `OPTIONS` if your API serves it, so wrong-method probes get the decoy response (and an event); give the decoy a DRF-shaped body. |

In Go, every adapter's `App.IsTrap` takes that framework's request type, as in the table; `app.Sentry.IsTrap(req any)` accepts any of them. Every adapter has `InstallSentry(router, service, environment)` and `Use(sentry, router)` (to wire a Sentry you created with `trappsec.NewSentry`).

> Missing your favorite framework? [Raise a request here](https://github.com/trappsec-dev/trappsec/discussions/new?category=feature-requests).
