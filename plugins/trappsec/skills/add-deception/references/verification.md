# Verification

A tripwire you haven't fired is a tripwire you don't have. A lure the bundler dropped doesn't exist.

Contents
1. Fire every trap
2. Exercise every honey field
3. Response parity
4. Frontend survival and tells
5. False-positive audit
6. Report template

## 1. Fire every trap

Start the app the way its developers run it locally, with logging that shows the `trappsec` logger. Then, for each trap:

**Anonymous:**
```bash
curl -s -i -X POST "http://localhost:$PORT/<trap-path>" -H 'Content-Type: application/json' -d '{}'
```
Expect the real anonymous response, plus a `trappsec.trap_hit` event with `"type": "signal"` in the log.

**Signed in as a normal user** (get a cookie or token through the app's real login flow or its test fixtures):
```bash
curl -s -i -X POST "http://localhost:$PORT/<trap-path>" -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{}'
```
Expect the designed response, plus a `trap_hit` with `"type": "alert"` and the expected `user`, `role` and `intent`.

If the signed-in call gets the anonymous response, `identify_user` can't see the user on trap routes. Fix that before anything else (trappsec-api.md §2).

Then poke each trap the way a skeptic would: `OPTIONS`, `HEAD`, wrong method, empty body, garbage body, another ID, trailing slash, different case. Compare with a real sibling. Any difference should be one a real endpoint could plausibly have.

If the project has integration tests, add tests that fire each trap and honey field and assert on both the response and the event, so a future refactor can't silently break them. Follow the project's test conventions. trappsec bootstraps on the first request, so test clients work.

## 2. Exercise every honey field

For each watched field:
1. **Normal use.** Perform the real UI action, or replay the exact request the frontend sends. Expect no `watch_hit` and unchanged behavior.
2. **Explicit default.** Send the default value explicitly. Expect no event.
3. **Tampering.** Send a tampered value. Expect a `watch_hit` alert naming the field, value and intent. The handler must behave as if the field were absent (the role didn't change, the price wasn't used).
4. **Repetition.** For query honey fields, also send the parameter twice (`?x=a&x=b`).

## 3. Response parity

`scripts/compare_responses.mjs` sends the same request to a real endpoint and to a decoy. It reports differences in status, content type, header names and JSON shape, plus median latency. It needs only Node 18+.

```bash
node ${CLAUDE_SKILL_DIR}/scripts/compare_responses.mjs \
  --real "http://localhost:3000/api/v2/<real-protected-path>" \
  --trap "http://localhost:3000/api/v2/<trap-path>" \
  [--method POST] [--data '{"a":1}'] [-H 'Authorization: Bearer ...'] [--runs 5] [--json]
```

Run it at least twice per trap:
- **Anonymous:** expect identical status and body.
- **Signed in:** against a real sibling that denies a normal user; expect the same shape.

Volatile headers (date, request IDs, ETag, content length) are ignored. Investigate every other difference. Headers that only per-handler code sets are a known trappsec limitation; record them as residual risks.

The exit code is 0 when status, content type and body shape match, and 1 otherwise.

## 4. Frontend survival and tells

Build for production with the project's own build command (e.g. `npm run build`), then:

```bash
node ${CLAUDE_SKILL_DIR}/scripts/scan_bundle.mjs --dir dist \
  --lure '/api/v2/<decoy-path>' --lure '<flagName>' --lure '<GatedComponentName>'
```

Pass every distinctive string a lure depends on: the decoy path (or its static prefix, if it's built from template literals), the flag name, the gated component's name. Then read the result:

- **Found.** Every lure must appear in the shipped files. MISSING means it was tree-shaken, dead-code-eliminated, or lives in a server-only module.
- **HIGH findings.** A revealing word near a lure, or trappsec mentioned anywhere in client files. Fix them. LOW findings (the same words far from any lure, often inside libraries such as focus-trap) are counted but usually harmless.
- **Source maps.** If maps are present, the report shows each lure's original source file and any comments next to it, as an attacker holding the maps would see them.

For server-rendered apps, scan what browsers receive, not the raw templates. Template comments (`{# #}`, `{% comment %}`, `<%# %>`) never ship, while server-side role checks decide who sees what. So save the rendered pages as each kind of user (anonymous, customer, staff...) into a directory, then scan it together with the static assets:

```bash
mkdir -p /tmp/rendered
curl -s -b "$COOKIE" "http://localhost:$PORT/checkout" > /tmp/rendered/customer_checkout.html
# ...one file per page and user type...
node ${CLAUDE_SKILL_DIR}/scripts/scan_bundle.mjs --dir /tmp/rendered --dir static --lure '<string>'
```

If the gate can be satisfied locally (flipping the flag in devtools, a local-only role), also exercise the gated UI by hand and confirm the decoy fires from the browser.

## 5. False-positive audit

**For every lure:**
- List every call site of the lure method or component. Each one must sit behind the gate.
- Show why the gate can never pass for a real user: role-assignment code, flag definition, database enum.
- Walk the hazard list in frontend-lures.md §5: links, prefetch, effects, loaders, retries, nav arrays, crawlers, tests.

**For every honey field:**
- Show the code that builds the real write payload, and what it sends for this field: nothing, or the default.
- Check other clients of the endpoint: mobile apps, partner integrations, scripts, e2e tests.

Run the project's test suites (unit, integration, e2e). Tests that snapshot API responses need updating for bait fields. Update them; don't delete them.

## 6. Report template

```markdown
## Deception added
<one paragraph: the threat narrative and what was added>

| # | Tripwire | Kind | Cover story | Lure location(s) | See → Think → Do | Response (anon / authed) | Intent |
|---|---|---|---|---|---|---|---|

### Fire each tripwire
<curl commands, anonymous and signed in, with the expected event>

### Alerts
<where events go, alert vs. signal, how to change it>

### Verification results
<what you ran and what came out, including summaries of scan_bundle and compare_responses>

### False-positive analysis
<per tripwire: why legitimate traffic can't reach it>

### Assumptions and residual risks
<e.g. private repo assumed; per-handler headers a trap can't reproduce; source maps are public>

### Maintenance
<symbols the team must not delete or call, where the inventory lives, notes added to AGENTS.md/CODEOWNERS, when to revisit (API version bump, new roles, flag cleanups)>
```
