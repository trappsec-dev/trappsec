# Changelog

All notable changes to trappsec are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/).

## Unreleased

### Dependencies

- Go: OpenTelemetry v1.47.0 (all modules now require **Go 1.26+**), golang.org/x/net v0.61.0, x/crypto v0.58.0 and quic-go v0.59.1 (GO-2026-5676); govulncheck reports no reachable vulnerabilities.
- Node integration tests now run against Koa 3, @koa/router 15, Fastify 5 and NestJS 12.
- GitHub Actions: checkout v7, setup-python v7, upload-artifact v7, download-artifact v8, configure-pages v6. Dependabot now groups updates per ecosystem.

### Fixed

- **Docs:** `identify_user` examples returned `user_id` / `id`, but the SDKs read only `user` and `role`, so copied examples never produced alerts. Fixed everywhere. The Node quickstart now logs the port it listens on, and the `add_webhook` example no longer targets Slack with a raw payload (use `add_slack`).
- **Never break or stall the host request:** all user callbacks (`identify_user`, `override_source_ip`, callable defaults, dynamic bodies, webhook templates) are guarded and fall back safely; exceptions inside trappsec's own watch/trap code are logged and the request proceeds.
- **Honey-field detection:** canonical value matching (`1` = `1.0`, `true` = `"true"`); duplicate and multi-valued query/form fields can no longer bypass a watch and are fully stripped without data loss on other fields; own-property rule lookup in Node (`constructor`, `__proto__` never match); case-insensitive JSON keys in Go; top-level JSON arrays are inspected and odd body shapes never crash.
- **Traps:** no longer silently shadowed by app routes; Express, Koa and NestJS-Express insert them after ordinary middleware and before the first route; Express recurses into sub-routers; exact duplicates of app routes fail loudly at bootstrap; Django traps are CSRF-exempt; string trap bodies are sent raw regardless of mime type.
- **Responses:** `respond(...)` honors falsy-but-provided values (`{}`, `""`, `0`, `false`, status 0); Node template cloning preserves function bodies; default responses are resolved at bootstrap so configuration order no longer matters.
- **Honey-field detection, cross-language parity:** list and object defaults now match equal values in Node (previously every request alerted) and in Python (`[True]` no longer matches `[1]`, `["5"]` now matches `[5]`). A one-element list that equals a list default is clean in Python and Node. Go now records a one-element list in `found_fields[].value` as its element, as Python and Node already did.
- **Go: JSON bodies with trailing data no longer bypass a watch.** Only the first JSON value was inspected and a body with anything after it was skipped, but Gin's and Echo's binders (`json.Decoder`) read the first value and ignore the rest, so `{"is_admin":true} x` reached the handler without an alert. Every top-level value is now inspected and stripped; an unparseable tail is kept byte-for-byte.
- **Python: webhooks after `fork()`** (gunicorn `--preload`): a forked worker no longer re-sends events that were still queued in the parent, and starts with a fresh queue, lock and HTTP session.
- **Events, cross-language parity:** every SDK now sends exactly the documented keys per event. Go no longer adds `reason`, `metadata` and `found_fields` to every event, and sends `found_fields: []` rather than `null` on an empty `watch_hit`. Python no longer adds `intent: null` to `watch_hit`. Object values in `found_fields[].value` render as compact JSON with sorted keys in all three (Python dropped its spaces, Node now sorts keys, Go no longer HTML-escapes `<>&`). Go truncates `path` and `user_agent` to 1024 characters plus `...`, like Python and Node.
- **Value matching and truncation, last parity gaps:** Python and Go now write floats exactly as JavaScript does when comparing a form/query string to a numeric default (`"1e-7"` matched in Node only; Python expected `"1e-07"`, Go `"0.0000001"`). Node truncates long strings by code points like Python and Go instead of UTF-16 units, so it no longer splits emoji.
- **Traps under CSRF protection:** Litestar traps are now excluded from `CSRFConfig` (they returned 403 and emitted nothing, so the trap was silently disabled). Echo gains `App.IsTrap` to use as the CSRF middleware's `Skipper`.
- **Gin: routes in groups created before `InstallSentry` are watched.** A route added to such a group never got the watch middleware, so honey fields reached the handler with no alert. `App.ServeHTTP` now inspects any watched route until it has seen the middleware cover it.
- **Go: unreachable watches are logged.** At bootstrap the net/http, Gin and Echo adapters log every watch that matches no registered route (a typo, a missing group prefix, or a route inside a mounted sub-mux, with the mount pattern to watch instead).
- **Examples:** Gin and Echo no longer trust forwarded headers for the client IP, and the uvicorn-based examples run with `proxy_headers=False`; the e2e suite now checks that a forged `X-Forwarded-For` is not recorded as the client IP.
- **Supported versions are now stated and tested:** the oldest framework versions the integration tests pass on are listed in Supported Frameworks and checked in CI (Python 3.10 for each Python framework, Node 20 for the Node ones). The Litestar and Sanic integrations log an error at startup on versions below 2.13 and 24.6, where honey fields are missed.
- **Tests:** shared conformance fixtures in `tests/conformance/` (value matching, honey-field detection, `safe_value`, event keys) run in the Python, Node and Go unit tests. The e2e suite verifies every webhook's HMAC signature and exact event keys, catches duplicate or late events, and reports unsupported multipart as skipped. `tests/package/run.sh` (new CI job) smoke-tests the built wheel, sdist and npm tarball.
- **Slack:** `&`, `<`, `>` are escaped in all request-derived values; a non-empty fallback `text` is always set.
- **OpenTelemetry:** span event attributes use valid OTel types (nulls dropped, other values stringified).
- **Go:** default client IP in Gin/Echo no longer trusts spoofable proxy headers; `http.Server{Handler: app}` is supported; request body size is bounded.
- **Logging:** Python no longer calls `logging.basicConfig`; Node logging has no escaped template literals.
- **E2E harness:** `requires-python` lowered to `>=3.10`; `--log-dir` and a CSV summary are implemented; Node examples are installed (`--install`, on in CI); `--kill-port-blockers` is opt-in; bare `except` and duplicate imports removed.

### Changed

- **Webhook signing:** requests now carry `x-trappsec-timestamp` and `x-trappsec-signature: sha256=<hex HMAC-SHA256(secret, "<timestamp>.<body>")>`. Update receivers; the old bare-digest header is gone. Heartbeats are signed the same way. See the Event Reference for verification snippets.
- **Delivery is asynchronous:** webhook/Slack events go through a bounded queue (1000) with background retries (max 2); when full they are dropped with a rate-limited warning.
- **Events:** all keys are always present, with `null` for absent values (including `user`/`role` on signals). `found_fields[].type` is `"query"` or `"body"`. Recorded values are sanitized and truncated; `path` and `user_agent` are capped at 1024 characters.

### Added

- `close()` / `Close()` to stop heartbeats and flush pending deliveries.
- Public, idempotent `bootstrap()` / `Bootstrap()` in every integration, also invoked lazily on the first request where the framework allows.
- `trigger()` in Node (emits `trappsec.rule_hit`, parity with Python and Go).
- Docs: Threat Model, Production Deployment and Tuning False Positives pages; expanded API and Event references.
- Integration rules R15 to R23 (bootstrap, async delivery, value matching, multi-value, sanitization, duplicate traps, IP extraction, CSRF, responses).
- CI for Python (3.9, 3.11, 3.13), Node (18, 20, 22, 24), Go (core and adapters) and e2e; release-triggered publish workflows with test gates and environments; Go module tagging workflow; Dependabot; issue and PR templates; CONTRIBUTING.
- Removed the hard-coded version badge from the README.
