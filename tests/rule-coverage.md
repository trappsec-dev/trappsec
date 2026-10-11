# Integration rule coverage

Which automated tests exercise each rule in [`integration-rules.md`](../integration-rules.md), per framework. It was built by reading the test bodies: a cell counts only if some test would fail when that framework broke the rule. Update it when you add a framework, a rule, or a test that closes a gap.

**Legend:** ✅ framework-specific or core test · **e2e** only the shared black-box suite (`tests/e2e`), which runs against every example app · **N/A** not applicable · **—** gap: applicable, no test.

Columns: Fl Flask · FA FastAPI · St Starlette · Li Litestar · Dj Django · Sa Sanic · To Tornado · Ex Express · Fy Fastify · Ha Hapi · Ko Koa · Ne NestJS · NH net/http · Gi Gin · Ec Echo.

| Rule | Fl | FA | St | Li | Dj | Sa | To | Ex | Fy | Ha | Ko | Ne | NH | Gi | Ec | core py / node / go |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| R1 watch uses route pattern | e2e | e2e | e2e | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | e2e | ✅ | e2e | N/A |
| R2 traps not shadowed | ✅ | ✅ | ✅ | e2e | ✅ | e2e | ✅ | ✅ | e2e | ✅ | ✅ | ✅ | ✅ | e2e | e2e | N/A |
| R3 setup before first request | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | N/A |
| R4 always strip | ✅ | e2e | ✅ | e2e | ✅ | ✅ | e2e | ✅ | e2e | e2e | e2e | e2e | e2e | e2e | e2e | ✅ / ✅ / ✅ |
| R5 body parsing | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | N/A |
| R6 stable mutation API | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | e2e | e2e | ✅ | ✅ | ✅ | N/A |
| R7 nested routers | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅¹ | ✅ | ✅ | N/A |
| R8 double-init guard | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | N/A |
| R9 unknown framework fails loud | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A | ✅ / ✅ / N/A² |
| R10 traps before watches | — | — | — | — | — | — | — | — | — | — | — | — | — | — | — | N/A |
| R11 adapter-specific context | ✅ | e2e | e2e | e2e | e2e | e2e | e2e | e2e | e2e | e2e | e2e | e2e | ✅ | ✅ | ✅ | N/A |
| R12 emit is fire-and-forget | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A | ✅ / ✅ / ✅ |
| R13 O(1) lookups | — | — | — | — | — | — | — | — | — | — | — | — | — | — | — | — / — / — |
| R14 traps are real routes | e2e | e2e | e2e | e2e | e2e | e2e | ✅ | e2e | e2e | e2e | e2e | e2e | e2e | e2e | e2e | N/A |
| R15 bootstrap public, idempotent, lazy | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ / ✅ / N/A |
| R16 async delivery; callbacks never throw | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ / ✅ / ✅ |
| R17 canonical value matching | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | e2e | ✅ | e2e | ✅ | ✅ | ✅ | ✅ / ✅ / ✅ (shared fixtures) |
| R18 multi-valued fields | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ / ✅ / ✅ (shared fixtures) |
| R19 sanitized values, event shape | e2e | e2e | e2e | e2e | e2e | e2e | e2e | e2e | e2e | e2e | e2e | e2e | e2e | e2e | e2e | ✅ / ✅ / ✅ (shared fixtures) |
| R20 duplicate trap fails loud | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅³ | ✅ | ✅ | ✅ | N/A |
| R21 no spoofable IP by default | e2e | e2e | e2e | e2e | e2e | e2e | e2e | e2e | e2e | e2e | e2e | e2e | ✅ | ✅ | ✅ | N/A |
| R22 traps exempt from CSRF | ✅ | N/A⁴ | ✅⁶ | ✅ | ✅ | N/A⁴ | ✅ | ✅⁶ | N/A⁴ | N/A⁴ | N/A⁴ | N/A⁴ | ✅⁶ | N/A⁴ | ✅⁵ | N/A |
| R23 trap responses | e2e | e2e | e2e | ✅ | e2e | e2e | e2e | ✅ | ✅ | e2e | e2e | ✅ | ✅ | ✅ | ✅ | ✅ / ✅ / ✅ |

1. A sub-mux mounted with `Handle("/prefix/", sub)` is opaque to the adapter: a watch on a route inside it cannot fire. Bootstrap logs a warning naming the mount pattern to watch instead (`TestUnreachableWatchIsLogged`). Gin and Echo log the same warning for any watch that matches no route.
2. Go has no runtime framework detection; each adapter has its own typed `InstallSentry`.
3. NestJS R20 is tested on the Express adapter only.
4. No built-in CSRF middleware; third-party ones are listed under gaps.
5. Echo's CSRF middleware runs before routing, so it cannot be bypassed automatically: `App.IsTrap` is provided as its `Skipper`, and the test shows both outcomes.
6. Third-party CSRF middleware: the `is_trap` / `IsTrap` skip hook is tested with a stand-in middleware.

## Open gaps

Ordered by risk to detection.

- **R22 third-party CSRF middleware:** Flask-WTF is exempted automatically and tested; for the rest (csurf, csrf-csrf, `@fastify/csrf-protection`, crumb, koa-csrf, starlette-csrf, gorilla/csrf) the `is_trap` / `IsTrap` skip hook is tested with stand-in middleware (Express, Starlette, net/http), not with each library.
- **R1, R6, R11** on the frameworks marked e2e: covered end to end only.
- **R14 response bodies and headers:** the e2e suite compares a trap with a real route for wrong methods (status and `Allow`), trailing slashes and HEAD; error bodies and other headers are compared only in Tornado's unit test.
- **R10 and R13:** correctness and performance invariants with no test; low risk.

Notes: R5 multipart is now covered end to end on every framework (the Express, Koa and NestJS examples parse it on the route). R8 is tested under concurrent first requests in Go, Flask and Django; the other Python integrations bootstrap from a startup hook or their first request under the same lock.
