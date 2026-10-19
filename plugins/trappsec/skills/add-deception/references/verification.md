# Verification

A tripwire you haven't fired is a tripwire you don't have. A lure the bundler dropped doesn't exist. A decoy that changed data isn't a decoy.

Contents
1. Fire every decoy, probed like its sibling
2. Exercise every honey field
3. Response parity
4. Frontend survival and tells
5. Inert, and real routes unchanged
6. False-positive audit
7. Report template

## 1. Fire every decoy, probed like its sibling

Start the app the way its developers run it locally, with logging that shows the tripwire helper's logger. Get credentials through the app's real login flow or its test fixtures for at least: a normal user, and the owner of their own workspace (or whatever the most privileged self-service role is).

For each decoy, send every probe below to the decoy and to its sibling, and compare:

| Probe | Expect |
|---|---|
| Anonymous | Identical responses (the sibling's authentication answers both). No event, or a `signal` if you record anonymous hits. |
| Expired token, malformed token | Identical responses. |
| Normal user | Identical responses where the sibling denies; an `alert` event with the right `user`, `role` and `intent`. |
| Owner of their own workspace | The decoy's final denial where the sibling succeeds; an `alert` event. The denial must make sense for an owner. |
| Unknown, foreign and malformed IDs | Identical responses (the sibling's loader answers both); an `alert` event. |
| Malformed JSON, empty body, wrong content type, a body missing required fields | Identical status and shape, in the same order relative to authentication. |
| Other methods, HEAD, OPTIONS, a CORS preflight | Identical, including `Allow`. |
| Trailing slash, different case, `Accept: text/html` | Identical. |

```bash
curl -s -i -X POST "http://localhost:$PORT/<decoy-path>" -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{"<field>":"<value>"}'
```

Any difference other than the final denial and field names in validation messages is a tell. Fix the chain, not the response.

If the project has tests, add one per decoy that fires it as a normal user and as an owner and asserts the response, the recorded event, and that no data changed. Follow the project's test conventions.

## 2. Exercise every honey field

For each honey field:
1. **Normal use.** Perform the real UI action, or replay the exact request the frontend sends. Expect no event and unchanged behavior.
2. **Explicit expected value.** Send the expected value explicitly. Expect no event.
3. **Tampering.** Send a tampered value. Expect a `field_hit` event naming the field, value and intent. The handler must behave as if the field were absent (the role didn't change, the price wasn't used).
4. **Repetition and types.** For query fields, send the parameter twice (`?x=a&x=b`). For JSON fields, try the value as a string and as its typed form (`"true"` and `true`).
5. **Unknown-field behavior.** Send an unrelated unknown field the same way. The endpoint must treat it exactly as it treats the honey field (both ignored, or both rejected).

## 3. Response parity

`scripts/compare_responses.mjs` sends the same request to a real endpoint and to a decoy over raw HTTP, so header names keep the case and order the server wrote. It reports differences in the status line, header presence, case, order and values, body bytes, JSON key order and values, stability across repeated requests, and median latency with the requests interleaved. Only the values of per-request headers (date, request IDs, ETag, content length) are ignored; their presence is still compared. It needs only Node 18+.

```bash
node ${CLAUDE_SKILL_DIR}/scripts/compare_responses.mjs \
  --real "http://localhost:3000/api/v2/<sibling-path>" \
  --decoy "http://localhost:3000/api/v2/<decoy-path>" \
  [--method POST] [--data '{"a":1}'] [-H 'Authorization: Bearer ...'] [--identical] [--runs 5] [--json]
```

Run it for every probe in §1 where the decoy and its sibling must agree, at least:
- anonymous and with an expired token, with `--identical`: the bodies must be byte-identical;
- signed in as a normal user, where the sibling denies too.

Values that differ are listed separately; they're expected only where the decoy's final denial or validation names its own feature. The exit code is 0 when nothing differs.

## 4. Frontend survival and tells

Build for production with the project's own build command (e.g. `npm run build`), then:

```bash
node ${CLAUDE_SKILL_DIR}/scripts/scan_bundle.mjs --dir dist \
  --lure '/api/v2/<decoy-path>' --lure '<flagName>' --lure '<GatedComponentName>'
```

Pass every distinctive string a lure depends on: the decoy path (or its static prefix, if it's built from template literals), the flag name, the gated component's name. Then read the result:

- **Found.** Every lure must appear in the shipped files. MISSING means it was tree-shaken, dead-code-eliminated, or lives in a server-only module.
- **HIGH findings.** A revealing word near a lure. Fix them. LOW findings (the same words far from any lure, often inside libraries such as focus-trap) are counted but usually harmless.
- **Source maps.** If maps are present, the report shows each lure's original source file and any comments next to it, as an attacker holding the maps would see them. Read those comments yourself: the scanner only matches single words.

For server-rendered apps, scan what browsers receive, not the raw templates. Save the rendered pages as each kind of user (anonymous, customer, staff...) into a directory, then scan it together with the static assets.

If the gate can be satisfied locally (flipping the flag in devtools, a local-only role), also exercise the gated UI by hand and confirm the decoy records from the browser.

## 5. Inert, and real routes unchanged

- **No state change.** Snapshot the data the decoy's sibling would change (or the whole store, in a test), hit every decoy as every role with valid bodies, and show the snapshot is unchanged.
- **Real routes unchanged.** Run the app's existing test suites. For every real route on a path a decoy shares (inferred decoys), replay the real UI's requests and compare with the responses before your change.
- **Recording never breaks a request.** Make the tripwire helper's logger raise (monkeypatch or a test double) and fire each decoy and honey field: responses must be unchanged.

## 6. False-positive audit

**For every lure:**
- List every call site of the lure method or component. Each one must sit behind the gate.
- Show why the gate can never pass for a real user: role-assignment code, flag definition, database enum.
- Walk the hazard list in frontend-lures.md §5: links, prefetch, effects, loaders, retries, nav arrays, crawlers, tests.

**For every decoy route:** show that no real client calls it: search the frontend, mobile apps, SDKs, scripts, partner integrations, e2e tests and monitoring.

**For every honey field:**
- Show the code that builds the real write payload, and what it sends for this field: nothing, or the expected value.
- Check other clients of the endpoint: mobile apps, partner integrations, scripts, e2e tests.

Run the project's test suites (unit, integration, e2e). Tests that snapshot API responses need updating for bait fields. Update them; don't delete them.

## 7. Report template

```markdown
## Deception added
<one paragraph: the threat narrative and what was added>

| # | Tripwire | Kind | Cover story | Lure location(s) | See → Think → Do | Chain copied / final denial | Intent |
|---|---|---|---|---|---|---|---|

### Fire each tripwire
<curl commands, as a normal user and as an owner, with the expected response and event>

### Alerts
<where events go, alert vs. signal, how to change it>

### Verification results
<what you ran and what came out: the probe comparison per decoy, compare_responses, scan_bundle, the inertness and robustness tests, the app's own tests>

### False-positive analysis
<per tripwire: why legitimate traffic can't reach it>

### Assumptions and residual risks
<e.g. private repo assumed; source maps are public>

### Maintenance
<the inventory location, markers, the tests that guard each tripwire, notes added to AGENTS.md/CODEOWNERS, when to revisit (API version bump, new roles, flag cleanups, changes to a sibling's chain)>
```
