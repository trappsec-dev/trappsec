# Integration rule coverage

Which automated tests exercise each rule in [`integration-rules.md`](../integration-rules.md), per framework. It was built by reading the test bodies: a cell counts only if some test would fail when that framework broke the rule. Update it when you add a framework, a rule, or a test that closes a gap.

**Legend:** ✅ framework-specific or core test · **e2e** only the shared black-box suite (`tests/e2e`), which runs against every example app · **N/A** not applicable · **—** gap: applicable, no test.

Columns: Fl Flask · FA FastAPI · St Starlette · Li Litestar · Dj Django · Sa Sanic · To Tornado · Ex Express · Fy Fastify · Ha Hapi · Ko Koa · Ho Hono · Ne NestJS · NH net/http · Gi Gin · Ec Echo.

| Rule | Fl | FA | St | Li | Dj | Sa | To | Ex | Fy | Ha | Ko | Ho | Ne | NH | Gi | Ec | core py / node / go |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| R1 watch uses route pattern | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | N/A |
| R2 traps not shadowed | ✅ | ✅ | ✅ | e2e | ✅ | e2e | ✅ | ✅ | e2e | ✅ | ✅ | ✅ | ✅ | ✅ | e2e | e2e | N/A |
| R3 setup before first request | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | N/A |
| R4 always strip | ✅ | e2e | ✅ | e2e | ✅ | ✅ | e2e | ✅ | e2e | e2e | e2e | ✅ | e2e | e2e | e2e | e2e | ✅ / ✅ / ✅ |
| R5 body parsing | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | N/A |
| R6 stable mutation API | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | N/A |
| R7 nested routers | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅¹ | ✅ | ✅ | N/A |
| R8 double-init guard | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | N/A |
| R9 unknown framework fails loud | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A | ✅ / ✅ / N/A² |
| R10 traps before watches | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | N/A |
| R11 adapter-specific context | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | N/A |
| R12 emit is fire-and-forget | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A | ✅ / ✅ / ✅ |
| R13 O(1) lookups | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | N/A |
| R14 traps are real routes | e2e | e2e | e2e | e2e | e2e | e2e | ✅ | e2e | e2e | e2e | e2e | e2e | e2e | e2e | e2e | e2e | N/A |
| R15 bootstrap public, idempotent, lazy | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ / ✅ / N/A |
| R16 async delivery; callbacks never throw | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ / ✅ / ✅ |
| R17 canonical value matching | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | e2e | ✅ | e2e | e2e | ✅ | ✅ | ✅ | ✅ / ✅ / ✅ (shared fixtures) |
| R18 multi-valued fields | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ / ✅ / ✅ (shared fixtures) |
| R19 sanitized values, event shape | e2e | e2e | e2e | e2e | e2e | e2e | e2e | e2e | e2e | e2e | e2e | e2e | e2e | e2e | e2e | e2e | ✅ / ✅ / ✅ (shared fixtures) |
| R20 duplicate trap fails loud | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅³ | ✅ | ✅ | ✅ | N/A |
| R21 no spoofable IP by default | e2e | e2e | e2e | e2e | e2e | e2e | e2e | e2e | e2e | e2e | e2e | ✅ | e2e | ✅ | ✅ | ✅ | N/A |
| R22 traps exempt from CSRF | ✅ | N/A⁴ | ✅⁶ | ✅ | ✅ | N/A⁴ | ✅ | ✅⁶ | ✅⁶ | N/A⁴ | N/A⁴ | ✅⁷ | N/A⁴ | ✅⁶ | N/A⁴ | ✅⁵ | N/A |
| R23 trap responses | e2e | e2e | e2e | ✅ | e2e | e2e | e2e | ✅ | ✅ | e2e | e2e | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ / ✅ / ✅ |

1. A sub-mux mounted with `Handle("/prefix/", sub)` is opaque to the adapter: a watch on a route inside it cannot fire. Bootstrap logs a warning naming the mount pattern to watch instead (`TestUnreachableWatchIsLogged`). Gin and Echo log the same warning for any watch that matches no route.
2. Go has no runtime framework detection; each adapter has its own typed `InstallSentry`.
3. NestJS R20 is tested on the Express adapter only.
4. No built-in CSRF middleware; third-party ones are listed under gaps.
5. Echo's CSRF middleware runs before routing, so it cannot be bypassed automatically: `App.IsTrap` is provided as its `Skipper`, and the test shows both outcomes.
6. Third-party CSRF middleware, made to skip traps with `is_trap` / `IsTrap` and tested with the real library: csrf-csrf (Express 4 and 5), `@fastify/csrf-protection`, starlette-csrf and net/http's `CrossOriginProtection`. Each test also shows the trap blocked without the skip.
7. Hono's built-in `hono/csrf` runs before traps; the test wraps it to skip traps with `is_trap` and shows both outcomes.

## Open gaps

Ordered by risk to detection.

- **R22 remaining CSRF libraries:** crumb (Hapi), koa-csrf and csurf (deprecated) are untested. The documented gorilla/csrf pattern was checked by hand but is not in CI, to keep the net/http adapter's go.mod free of third-party modules.
- **R14 response bodies and headers:** the e2e suite compares a trap with a real route for wrong methods (status and `Allow`), trailing slashes and HEAD; error bodies and other headers are compared only in Tornado's unit test.
- **NestJS, `@Req()` without `@Body()` on a multipart route:** the body is parsed by a route-level interceptor after every hook trappsec can use without patching Nest internals, and Nest runs pipes only for `@Body`/`@Query`/`@Param`/custom parameters. The event is sent but the field is not stripped (documented in `docs/production.md`).

Notes: R10 and R13 are checked per framework by declaring watches before traps and then, after the first request, making the configuration unreadable (Python, Node) or adding a watch (Go): a per-request scan of the configuration fails the test (`test_startup_invariants.py`, `startup_invariants.test.js`, `TestWatchesBeforeTrapsAndIndexBuiltOnce`). R1, R6 and R11 are checked together per framework by one request to a watched parameterised route (`test_request_context.py`, `request_context.test.js`, `TestParameterisedWatchAndEventContext`); on Node it also checks that every raw-URL accessor lost the honey field. R5 multipart is now covered end to end on every framework (the Express, Koa and NestJS examples parse it on the route). R8 is tested under concurrent first requests in Go, Flask and Django; the other Python integrations bootstrap from a startup hook or their first request under the same lock.
