# Changelog

All notable changes to trappsec are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/).

## Unreleased

### Fixed

- **Docs:** `identify_user` examples returned `user_id` / `id`, but the SDKs read only `user` and `role`, so copied examples never produced alerts. Fixed everywhere. The Node quickstart now logs the port it listens on, and the `add_webhook` example no longer targets Slack with a raw payload (use `add_slack`).
- **Never break or stall the host request:** all user callbacks (`identify_user`, `override_source_ip`, callable defaults, dynamic bodies, webhook templates) are guarded and fall back safely; exceptions inside trappsec's own watch/trap code are logged and the request proceeds.
- **Honey-field detection:** canonical value matching (`1` = `1.0`, `true` = `"true"`); duplicate and multi-valued query/form fields can no longer bypass a watch and are fully stripped without data loss on other fields; own-property rule lookup in Node (`constructor`, `__proto__` never match); case-insensitive JSON keys in Go; top-level JSON arrays are inspected and odd body shapes never crash.
- **Traps:** no longer silently shadowed by app routes; Express, Koa and NestJS-Express insert them after ordinary middleware and before the first route; Express recurses into sub-routers; exact duplicates of app routes fail loudly at bootstrap; Django traps are CSRF-exempt; string trap bodies are sent raw regardless of mime type.
- **Responses:** `respond(...)` honors falsy-but-provided values (`{}`, `""`, `0`, `false`, status 0); Node template cloning preserves function bodies; default responses are resolved at bootstrap so configuration order no longer matters.
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
