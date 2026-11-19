---
name: add-deception
description: Design and add deception to an application the user owns: decoy API routes, honey fields and frontend lures that blend into the app's real code, wired to identity-attributed alerts and verified never to affect legitimate users. Use this whenever the user wants to add decoys, honeypots, honey fields, canary endpoints, tripwires or lures to their own web app or API; wants to detect signed-in users probing business logic (hidden admin routes, mass assignment, privilege escalation, cross-tenant access); wants bait in their frontend that leads to decoys; or wants an existing deception setup reviewed, extended or made more convincing. Inputs the app already refuses are add-detection's. Not for anti-spam form honeypots, UI focus traps, WAFs, rate limiting or vulnerability scanning.
license: MIT
---

# Add deception

You are adding a detection layer to an application the user owns, written in the app's own code:
- decoy routes are real routes in the app's own router, built from the same authentication, loaders, validation, serializers and error helpers as the routes beside them;
- honey fields are checks inside real handlers;
- every hit is recorded as one standard OpenTelemetry finding, joined to the caller's identity on the request's server span.

A decoy that runs the same code as its neighbors answers every probe the way they do: unknown IDs, bad bodies, expired tokens, other methods, headers and bytes all come from the app itself. The judgment calls are yours:
- which decoys *this* app should have;
- making them indistinguishable from its real API and frontend;
- placing lures where attackers actually look;
- proving that no legitimate user can ever trip one, and that no decoy can ever do anything.

The bar: a seasoned tester who reads the JavaScript bundle, replays API calls and diffs responses cannot tell the tripwires and lures from the real thing, even on a careful second look. A decoy that looks planted is worse than none. It tells the attacker the app is instrumented, and they become careful.

Tripwires are hidden from attackers, never from the team. Everything you add appears in your final report and stays easy for maintainers to recognize (see "Keep the team in on it").

## What makes deception work

Check every tripwire and lure against these properties:

| Property | In practice |
|---|---|
| Believable | Matches this codebase's real constructs: naming, structure, response shapes, behavior. |
| Enticing | Worth an attacker's time. It points at privilege, money, other tenants' data, or hidden features. |
| Discoverable | Sits on a path attackers already walk: the bundle, API responses, specs, old versions. |
| Non-interfering | Has no effect on real users or real behavior. A false positive is a bug: when unsure, pick the placement with no false-positive risk. |
| Inert | Performs no real action. Its last step is a denial; it writes, sends and calls out nothing. |
| Detectable | Every touch produces an attributed alert, and you have fired it to prove it. |
| Variable | Shares no fingerprint with other decoys, other apps, or this skill's examples. |
| Differentiable | The team can tell decoys from real code, so nobody deletes one or wires it into the UI. |

Believable and enticing pull against each other. The attackers worth catching skip anything that looks too good to be true. Aim for *mundane in detail, interesting in shape*.

Seven habits produce that:

1. **Extrapolate, don't invent.** Derive every decoy from something real in this codebase. Candidates: a sibling of a real resource, the previous version of a real route, a role adjacent to the real roles, a field that sits naturally beside real fields, a feature the team plausibly built next or half-retired. Use the app's own vocabulary (workspace vs. organization, member vs. seat).
2. **Confirm what attackers already believe.** Reinforcing an existing belief is far easier than creating a new one. Attackers expect these things, so lures that match them get acted on:
   - single-page apps ship admin screens to everyone;
   - old API versions linger;
   - serializers accept fields they shouldn't;
   - feature flags hide unreleased endpoints;
   - support tooling is over-privileged.
3. **Give every lure an innocent reason to exist.** Real dead code always has a story: deprecated, behind a flag, role-gated, or kept for an older client. Write the one-sentence cover story first. It decides naming, location and response.
4. **Let them discover it.** A full URL next to a "do not use" comment reads as planted. A role-gated button, a flag-gated code path or an extra response field is something the attacker feels clever for finding, and people trust what they discover. From least to most suspicious to someone reading the client:
   1. nothing new in the client: honey fields on values the client already reads or sends back, decoys at a strong inference from a route the attacker has already used (references/backend-traps.md §1–2);
   2. one flag- or role-gated entry point to a decoy;
   3. an uncalled client method for a powerful capability;
   4. a hidden or disabled field of a kind the app's other forms don't carry;
   5. something nothing uses: a `data-` attribute no script reads, a handler for a form no page renders, a commented-out form.

   Suspicion is relative: what stands out is what has no precedent. In an otherwise clean client, a gated high-value feature unlike anything else in it is the obvious place to look. So give every visible lure a precedent: copy a pattern the client already uses for a real feature, and vary which pattern each lure copies.

   Someone probing the running app sees something else. Honey fields leave nothing to observe from outside. Decoy routes can be found by elimination (Design step 5).
5. **Keep every layer consistent.** Frontend calls a decoy with POST → the decoy route accepts POST. There is a client method → there is a type. The app translates every string → the lure's strings are translated. Give a lure the care a real feature with the same stakes would get: one name across method, flag, handler and strings; its own place in the layout; a gate as strict as the value warrants; the states, copy and typed responses the real feature would have.
6. **Chain the breadcrumbs.** Along each attack path, let touching one tripwire lead to the next. Example: a decoy's 403 names a permission, a response field shows where permissions live, and sending that permission trips a honey field. Each step is another alert, and the second step removes doubt about intent.
7. **Leave no fingerprints, including this skill's.** Names in this skill and its references only illustrate patterns. Never reuse them: a decoy path shared by many apps becomes a signature attackers learn.

### See → Think → Do

Before writing code, write these three lines for every tripwire:

- **See**: the exact artifact the attacker meets, and where (bundle chunk, response body, form field).
- **Think**: the belief it should create. Example from the worked example: "bulk ledger export exists, and only a client-side flag hides it."
- **Do**: the action that belief leads to. It must be the action that fires the alert (e.g. an authenticated POST to the decoy).

If you can't name a belief an attacker would plausibly form, the tripwire won't convince anyone. And if acting on that belief doesn't raise the alert, the tripwire never fires.

## Workflow

### 0. Check fit and ask what you can't infer

- **OpenTelemetry traces and logs are a prerequisite.** Check them first, as references/telemetry.md describes, including how the app samples traces. If they aren't in place, stop and tell the user.
- **Ownership and scope.** Confirm this is the user's own application. Deception belongs only in systems you operate. Change only what the plan says, and ask before touching auth, infrastructure or CI.
- **Layout.** Find which service is the public API, where the frontend lives (same repo, another repo, none), and how each is built and run.
- **Questions.** Ask in one batch, and only what the code cannot tell you:
  1. Is the source repository public? Decoys in public source are visible to everyone (see references/implementation.md §7).
  2. Do external testers (bug bounty, pentests) use this app? Their findings need a triage path.
  3. Do older clients (mobile builds, partner integrations, scripts) still call older API versions or paths?
  4. What sits in front of the app in production (load balancer, CDN, ingress, API gateway), if the repo doesn't say? An alert is only as useful as the client IP it records.

  If the user wants you to proceed without questions, assume: private repo, no legacy clients, and whatever the deployment config in the repo shows about proxies. State those assumptions in the report.

### 1. Reconnaissance: see the app as an attacker, then as its authors

**The attacker's view** (what is visible from outside):
- Build the frontend for production and inspect the output: chunk names, API path strings, role/permission names, feature-flag names, locale strings, inline bootstrap state, and whether source maps are emitted and served.
- Run the app locally (never against production) and call the API both anonymously and as a normal signed-in user. Save the real responses (status, body, content type, headers) for:
  - an anonymous call to a protected endpoint;
  - a call with an expired credential;
  - a forbidden call;
  - an unknown resource;
  - a wrong method;
  - a validation failure.

  You will compare every decoy with these. If the app can't run locally, derive the shapes from its error handlers and tests, and say so in the report.
- Note where the valuable things are:
  - privilege: roles, permissions, impersonation;
  - money: plans, credits, prices, refunds;
  - other tenants' data: exports, org switching, IDs in URLs;
  - hidden features.

**The authors' view** (the texture of the code):
- **House-style dossier.** Write down:
  - API: URL scheme (prefix, versioning, plurals, casing, trailing slashes, ID formats, action-route style), JSON casing and envelope, pagination, timestamp and money formats, error shape per status, and the error codes the app already uses.
  - Auth: mechanism, role/permission model, tenancy model, domain vocabulary, and the order in which a typical route authenticates, loads, authorizes and validates.
  - Frontend: HTTP client wrapper, folder layout, file naming, typing, i18n, role-gating idiom, feature-flag system, comment style.
- **Story material.** Read the history: `git log --oneline`, deprecated folders, version migrations, TODOs, flags, renamed features. The best tripwires continue a story the codebase already tells.
- **Request pipeline.** Trace how a request gets authenticated and authorized: global middleware, per-route middleware, guards, dependencies, permission classes. Decoys reuse this pipeline, so you need to know it exactly.
- **Who and where from.** Find where the authenticated principal lives after authentication (the user, their tenant or workspace, the session, token or API key that authenticated them, and whether an admin can act as another user), and how the real client IP reaches the app: the proxies in front of it, and the framework's setting for which proxies to trust. Note the request or trace ID the app already logs.

If there is a frontend, read references/frontend-lures.md now.

### 2. Design

1. **Threat narrative.** In two or three sentences: who would attack this app, and what do they want? Examples: a B2B SaaS draws privilege escalation and cross-tenant access; a marketplace draws price and payout manipulation; a fintech app draws limit and balance tampering. Pick the intents that matter.
2. **Attack paths.** Deception is laid like a minefield: along the routes an attacker must take, where each tripwire looks like the ground around it. Map the routes and their chokepoints as references/attack-paths.md describes, starting from add-detection's map and hand-offs if it has run. Then classify every input at each chokepoint by what the app does with it today. Deception covers the inputs the app ignores; inputs it refuses go to add-detection, and inputs it wrongly accepts are vulnerabilities to report.
3. **Placement.** Give every chokepoint input that falls to deception a tripwire wherever one passes the bar: derived from this app (habit 1), safe from every legitimate client, and for a decoy route, able to survive elimination (step 5). The measure is how completely the paths are covered, not how many tripwires there are.
   - **Honey fields** on every real endpoint along a path where an attacker would try a field: privilege, entitlement, ownership and tenancy, price and state (references/backend-traps.md §2). Nothing about them can be observed from outside, so placing one more never exposes another.
   - **Honey query parameters** on the list and read endpoints that lead to other users' or other tenants' data.
   - **Decoy routes** wherever a lure, or a strong inference from a route the attacker has already used, leads to a route they would reach for at that stage (references/backend-traps.md §1). A route reachable only by guessing a name is not placed. Each decoy route needs the camouflage in step 5: design it rather than placing fewer decoys.
   - **Visible lures** that each copy a pattern the client already uses for real (a real role-gated button, a real flag-gated method, a real extra response field), so none is the only one of its kind (habit 4).
   - **Chains** along the path: a tripwire's response points toward the tripwire at the next stage, so stepping on one channels the attacker into the next (habit 6).

   Leave a chokepoint uncovered only for a reason about effectiveness, and write it down: every candidate there would look planted, a legitimate client could trip it, or it would give away a tripwire next to it. Parts of the app no path crosses need nothing.
4. **The final denial.** A caller who passes every one of the sibling's checks reaches the decoy's end, and that caller is often the owner of their own workspace, the most privileged account an attacker can create. Choose a denial that fits every such caller (references/implementation.md §2).
5. **Decoy routes that survive elimination.** A tester with the accounts a customer can create writes data and reads it back, which clears every real endpoint; whatever never works for any account is left over. A decoy route never works, so make sure that isn't what singles it out:
   - **Share a gate with real routes.** Deny through a check that real routes also apply and that the tester can see failing elsewhere: a role or permission the app already uses. A role or permission only the decoys mention is a tell.
   - **Hide among real refusals.** For the accounts a tester can create, many real routes already refuse: role-gated actions, plan-gated features, modules switched off for the account. A decoy behind one of those gates is one refusal among many. Where the API has few such refusals, choose gates from the ones it does have, and check every decoy against them in Verify step 4.
   - **Give it neighbors.** A route shape with no siblings stands out: a DELETE on an item that has no GET, a write method on a resource the API never writes.
   - **Treat the spec the same way.** If the app publishes a generated spec, a decoy missing from it while its siblings appear is the first thing a tester diffs. Either list it like its siblings, or put it where the app already keeps undocumented routes.
   - **Avoid the obvious picks**, such as a write method on a read-only billing resource or a user lookup by ID behind a staff role. What every app could have is what testers check first; start from this app's story material.
   - **Vary them against each other.** Two decoys must not share what could single them out: give each its own sibling, cover story and final denial, so finding one doesn't reveal the pattern behind the rest.
6. **Specification.** For each tripwire, write down:
   - the attack path, stage and chokepoint it covers;
   - cover story and See → Think → Do;
   - path and method in house style;
   - lure placements;
   - the sibling whose chain it copies, the point where the tripwire records, and the final denial;
   - intent (references/telemetry.md) and tripwire ID;
   - the guard that keeps legitimate traffic away.
7. **Review.** Look at the design through five sets of eyes, and revise until it passes each:
   - **An attacker walking each path.** At every stage, what would I try next? Does each of those tries reach a tripwire, and does the one I reach point me toward the next stage?
   - **A skeptical tester who has seen honeypots before.** Why does this exist? Why here? Why written like this? What happens if I poke it differently: no auth, wrong method, garbage body, another ID, as the owner of my own workspace? Does anything differ from its neighbors? If I clear every endpoint I can make work, what's left?
   - **A stranger holding the diff.** Shown the change without context, could they point at the decoy? If so, it doesn't blend in.
   - **A future maintainer or coding agent.** Will they delete this as dead code, or "fix" it by wiring it into the real UI or finishing the feature? What stops that?
   - **An ordinary user.** Could any normal action, browser behavior or client retry send this request or this field?

### 3. Present the plan

Unless the user already told you to go ahead, show the plan and wait. It changes product code the whole team will see. Keep it scannable:

| # | Path / stage | Tripwire | Kind | Cover story | Lure(s) | See → Think → Do | Chain copied / final denial | Intent |
|---|---|---|---|---|---|---|---|---|

Then list, from the attack-path map, the inputs handed off to add-detection, the vulnerabilities found and the chokepoints left uncovered and why, the files you will touch, your assumptions, and anything the user must decide.

### 4. Implement

The rules for each piece are in references/implementation.md, and the event every tripwire emits is in references/telemetry.md. Build them with the app's own idioms.

**Backend.**
- **Recording and attribution.** One small module sets the caller's identity on the server span and records every hit as the standard finding, as references/telemetry.md describes. Who and from where never come from anything the caller sent.
- **Decoy routes.** Each is a real route beside its sibling that runs the sibling's chain, records right after authentication, and ends in the final denial. It writes, sends and calls out nothing.
- **Inferred decoys.** A new method on a route the attacker has already used, listed by the framework like any real method.
- **Honey fields.** Checked after authentication and before the input is used. The endpoint behaves exactly as before, and the field can never reach the logic.
- **Bait fields.** Added to the real serializer with the smallest idiomatic change; the real write handler never reads them.
- **Inventory.** Every tripwire has a stable ID, a marker in server code and an entry in one inventory in server code.

**Frontend** (references/frontend-lures.md):

- Write lures in the files, helpers, types and idioms the codebase already uses, so they read as the same team's work. Add no dependency or pattern the app doesn't already have.
- **Plant no credentials or secrets of any kind**, even fake ones. They set off secret scanners and incident processes well beyond this app.
- Give each lure its natural footprint and nothing more: the client method, its type, the gate that keeps it unreachable, and strings if the app translates strings.
- Make every lure unreachable for real users. Either gate it on something no real user can satisfy (a role the backend never grants, a flag that is never enabled), or leave it uncalled on a class or object the bundler keeps.
- Nothing shipped to the browser may hint at its purpose. Check identifiers, strings, comments, file and chunk names, CSS classes, test IDs, storage keys, flag names and locale keys for the words `scripts/scan_bundle.mjs` looks for, such as decoy, honeypot and tripwire.

### 5. Verify

A tripwire you haven't fired is a tripwire you don't have. Commands and details: references/verification.md. `${CLAUDE_SKILL_DIR}` below means the directory that contains this SKILL.md.

1. **Project checks.** Lint, type checks and the app's existing tests pass. Decoys must not change any real route.
2. **Each decoy, probed like its sibling.** Send every probe in references/verification.md §1 to the decoy and its sibling through `node ${CLAUDE_SKILL_DIR}/scripts/compare_responses.mjs`: anonymous and with an expired token using `--identical`, a normal user, the owner of their own workspace, an unknown, foreign and malformed ID, a bad body, other methods. Every response matches the sibling's except the final denial, and the tripwire records every authenticated hit with the right user, role and intent.
3. **Inert.** Hit each decoy as every role, then show that no data changed (write it as a test).
4. **Elimination.** As a tester with the accounts a customer can create, list every endpoint you can make work, and check every decoy route left over against Design step 5.
5. **Each honey field.**
   - The real UI's exact request produces no event and no change in behavior.
   - A tampered value produces an event.
   - The handler never sees the field.
6. **Frontend survival.** Build for production, then run `node ${CLAUDE_SKILL_DIR}/scripts/scan_bundle.mjs --dir <build-output> --lure <string> ...`. Every lure must survive the bundler, with nothing near it that reveals intent. Also search the HTML shell and anything served outside the build directory for the words the scan looks for.
7. **False positives.** For each lure, show that no real code path calls it and no real user can pass its gate. For each honey field, show exactly what the real UI sends. Run the e2e suite if there is one.
8. **Attribution and schema.** For one hit per tripwire, the finding matches references/telemetry.md and shares its trace and span IDs with the request's server span, which names the right user, tenant and credential. The recorded IP passes the `client.address` check in references/telemetry.md.
9. **Tripwire robustness.** Make your own recording module fail in a test (not the OpenTelemetry API, which the instrumentation shares), and send an oversized or deeply nested body to every honey-field endpoint; responses and response times must not change.

### 6. Report

Finish with a report the user can hand to their security team, following the template in references/verification.md §8.

## Keep the team in on it

Tripwires only work if the people who maintain the app know about them. Otherwise someone deletes a lure as dead code, or wires a decoy into the real UI and floods the alert channel. The markers, inventory, tests and notes that prevent this are in references/implementation.md §6.

## When deception is already in place

Review before adding:
- fire every existing tripwire;
- run the parity and bundle checks;
- look for tells, tripwires that no longer match current conventions, decoys whose chain has drifted from their sibling's, and tripwires that record no identity.

Propose fixes in the plan format, then extend. Walk the attack paths again, and read add-detection's inventory: a path the app has grown since, a chokepoint left uncovered, or an input handed off to deception is where to extend. For a request about one specific decoy or field, skip the path map. Still capture the real responses for that area, review the design and verify it.

## Reference files

- **references/implementation.md**: rules for decoy routes, final denials, inferred decoys, honey fields, recording and attribution, keeping decoys recognizable to the team (inventory, markers, tests), and public repositories.
- **references/telemetry.md**: the OpenTelemetry prerequisite, the request context and records shared with add-auditing and add-detection, and the deception findings.
- **references/frontend-lures.md**: how attackers read frontends, lure patterns, build survival, false-positive hazards, tells, what ships to the client.
- **references/attack-paths.md**: the attack-path map and the test that divides its inputs between add-detection and add-deception, shared with add-detection.
- **references/backend-traps.md**: cover stories, honey-field design and expected values, responses, breadcrumb chains, directions by domain, infrastructure gotchas.
- **references/verification.md**: verification commands, the bundled scripts, the false-positive audit, the report template.
- **references/worked-example.md**: one end-to-end example contrasting an obvious design with a convincing one.
