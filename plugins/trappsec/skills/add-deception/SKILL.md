---
name: add-deception
description: Design and add deception to an application the user owns: decoy API routes, honey fields and frontend lures that blend into the app's real code, wired to identity-attributed alerts and verified never to affect legitimate users. Use this whenever the user wants to add decoys, honeypots, honey fields, canary endpoints, tripwires or lures to their own web app or API; wants to detect signed-in users probing business logic (hidden admin routes, mass assignment, privilege escalation, cross-tenant access); wants bait in their frontend that leads to decoys; or wants an existing deception setup reviewed, extended or made more convincing. Not for anti-spam form honeypots, UI focus traps, WAFs, rate limiting or vulnerability scanning.
license: MIT
---

# Add deception

You are adding a detection layer to an application the user owns, written in the app's own code:
- decoy routes are real routes in the app's own router, built from the same authentication, loaders, validation, serializers and error helpers as the routes beside them;
- honey fields are checks inside real handlers;
- a small tripwire helper, written into the app, records each hit with the caller's identity.

A decoy that runs the same code as its neighbors answers every probe the way they do: unknown IDs, bad bodies, expired tokens, other methods, headers and bytes all come from the app itself. The judgment calls are yours:
- which decoys *this* app should have;
- making them indistinguishable from its real API and frontend;
- placing lures where attackers actually look;
- proving that no legitimate user can ever trip one, and that no decoy can ever do anything.

The bar: a seasoned tester who reads the JavaScript bundle, replays API calls and diffs responses cannot tell the decoys from the real thing, even on a careful second look. A decoy that looks planted is worse than none. It tells the attacker the app is instrumented, and they become careful.

Decoys are hidden from attackers, never from the team. Everything you add appears in your final report and stays easy for maintainers to recognize (see "Keep the team in on it").

## What makes deception work

Check every decoy against these properties:

| Property | In practice |
|---|---|
| Believable | Matches this codebase's real constructs: naming, structure, response shapes, behavior. |
| Enticing | Worth an attacker's time. It points at privilege, money, other tenants' data, or hidden features. |
| Discoverable | Sits on a path attackers already walk: the bundle, API responses, specs, old versions. |
| Non-interfering | Has no effect on real users or real behavior. A false positive is a bug. |
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
4. **Let them discover it.** A full URL next to a "do not use" comment reads as bait. A role-gated button, a flag-gated code path or an extra response field is something the attacker feels clever for finding, and people trust what they discover. From least to most suspicious to someone reading the client:
   1. nothing new in the client: honey fields on values the client already reads or sends back, values the forms never offer, decoys inferred from the API's conventions (references/backend-traps.md §1–2);
   2. one flag- or role-gated entry point to a decoy;
   3. an uncalled client method for a powerful capability;
   4. a hidden or disabled field of a kind the app's other forms don't carry;
   5. something nothing uses: a `data-` attribute no script reads, a handler for a form no page renders, a commented-out form.

   Suspicion is relative: in an otherwise clean client, the one gated high-value feature is the obvious place to look. Keep visible lures few, and vary their patterns.

   Someone probing the running app sees something else. Honey fields leave nothing to observe from outside. Decoy routes are found by elimination: a tester writes data and reads it back, which clears every real endpoint, and whatever never works for any account is left over. Design step 4 deals with this.
5. **Keep every layer consistent.** Frontend calls a decoy with POST → the decoy route accepts POST. There is a client method → there is a type. The app translates every string → the lure's strings are translated. Give a lure the care a real feature with the same stakes would get: one name across method, flag, handler and strings; its own place in the layout; a gate as strict as the value warrants; the states, copy and typed responses the real feature would have.
6. **Chain the breadcrumbs.** Design at least one path where touching one tripwire leads to the next. Example: a decoy's 403 names a permission, a response field shows where permissions live, and sending that permission trips a honey field. Each step is another alert, and the second step removes doubt about intent.
7. **Leave no fingerprints, including this skill's.** Names in this skill and its references only illustrate patterns. Never reuse them: a decoy path shared by many apps becomes a signature attackers learn.

### See → Think → Do

Before writing code, write these three lines for every tripwire:

- **See**: the exact artifact the attacker meets, and where (bundle chunk, response body, form field).
- **Think**: the belief it should create. Example from the worked example: "bulk ledger export exists, and only a client-side flag hides it."
- **Do**: the action that belief leads to. It must be the action that fires the alert (e.g. an authenticated POST to the decoy).

If you cannot write a plausible Think, the tripwire is not believable. If the Do is not the alerting action, the tripwire will not fire.

## Workflow

### 0. Check fit and ask what you can't infer

- **Ownership.** Confirm this is the user's own application. Deception belongs only in systems you operate.
- **Layout.** Find which service is the public API, where the frontend lives (same repo, another repo, none), and how each is built and run.
- **Questions.** Ask in one batch, and only what the code cannot tell you:
  1. Is the source repository public? Decoys in public source are visible to everyone (see references/implementation.md §9).
  2. Where should alerts go: logs only, OpenTelemetry, the app's existing error tracker or SIEM?
  3. Do external testers (bug bounty, pentests) use this app? Their findings need a triage path.
  4. Do older clients (mobile builds, partner integrations, scripts) still call older API versions or paths?

  If the user wants you to proceed without questions, assume: private repo, logs-only alerts, no legacy clients. State those assumptions in the report.

### 1. Reconnaissance: see the app as an attacker, then as its authors

**The attacker's view** (what is visible from outside):
- Build the frontend for production and inspect the output: chunk names, API path strings, role/permission names, feature-flag names, locale strings, inline bootstrap state, and whether source maps are emitted and served.
- Run the app locally (never against production) and call the API both anonymously and as a normal signed-in user. Save the real responses (status, body, content type, headers) for:
  - an anonymous call to a protected endpoint;
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
- **Story material.** Read the history: `git log --oneline`, deprecated folders, version migrations, TODOs, flags, renamed features. The best decoys continue a story the codebase already tells.
- **Request pipeline.** Trace how a request gets authenticated and authorized: global middleware, per-route middleware, guards, dependencies, permission classes. Decoys reuse this pipeline, so you need to know it exactly.

If there is a frontend, read references/frontend-lures.md now.

### 2. Design

1. **Threat narrative.** In two or three sentences: who would attack this app, and what do they want? Examples: a B2B SaaS draws privilege escalation and cross-tenant access; a marketplace draws price and payout manipulation; a fintech app draws limit and balance tampering. Pick the 3–5 intents that matter.
2. **Portfolio.** For a typical app, 4–8 tripwires in total, led by the ones that live inside real endpoints:
   - 2–4 honey fields and value rules on real endpoints: fields real responses already show, and values the real forms never offer (references/backend-traps.md §2). They leave nothing to observe from outside;
   - 1–2 decoy routes, each reached through a frontend lure or inferred from the API's own conventions (references/backend-traps.md §1). In an API with fewer than about 30 endpoints, use one at most: every decoy route is one more endpoint that never works, and a tester who eliminates the working ones finds it;
   - optionally, a honey query parameter;
   - at least one breadcrumb chain linking two of the above.

   More is not better. Every decoy adds maintenance, false-positive risk and another chance of discovery. Attackers judge the client as a whole, and three anomalies in a small client make each one look more deliberate. So in a small client, add something new and visible for one or two tripwires at most, each with a different pattern.
3. **The final denial.** A decoy runs its sibling's real checks, so a caller who passes them all reaches its end. That caller is often the owner of their own workspace, the most privileged account an attacker can create. End there with a denial every such caller would plausibly get, through the app's own error mechanism and with an error code the app already uses: a feature that isn't enabled for the account, or a function handled elsewhere. Don't use a plan gate if a self-serve trial of that plan exists. Don't end with a success: a created object implies follow-ups (fetching it, listing it) that the rest of the API won't corroborate.
4. **Decoy routes that survive elimination.** A decoy route never works, so make sure that isn't what singles it out:
   - **Share a gate with real routes.** Deny through a check that real routes also apply and that the tester can see failing elsewhere: a role or permission the app already uses. A role or permission only the decoys mention is a tell.
   - **Give it neighbors.** A route shape with no siblings stands out: a DELETE on an item that has no GET, a write method on a resource the API never writes.
   - **Treat the spec the same way.** If the app publishes a generated spec, a decoy missing from it while its siblings appear is the first thing a tester diffs. Either list it like its siblings, or put it where the app already keeps undocumented routes.
   - **Avoid the obvious picks**, such as a write method on a read-only billing resource or a user lookup by ID behind a staff role. What every app could have is what testers check first; start from this app's story material.
5. **Specification.** For each tripwire, write down:
   - cover story and See → Think → Do;
   - path and method in house style;
   - lure placements;
   - the sibling whose chain it copies, the point where the tripwire records, and the final denial;
   - intent label;
   - the guard that keeps legitimate traffic away.
6. **Review.** Look at the design through four sets of eyes, and revise until it passes each:
   - **A skeptical tester who has seen honeypots before.** Why does this exist? Why here? Why written like this? What happens if I poke it differently: no auth, wrong method, garbage body, another ID, as the owner of my own workspace? Does anything differ from its neighbors? If I clear every endpoint I can make work, what's left?
   - **A stranger holding the diff.** Shown the change without context, could they point at the decoy? If so, it doesn't blend in.
   - **A future maintainer or coding agent.** Will they delete this as dead code, or "fix" it by wiring it into the real UI or finishing the feature? What stops that?
   - **An ordinary user.** Could any normal action, browser behavior or client retry send this request or this field?

### 3. Present the plan

Unless the user already told you to go ahead, show the plan and wait. It changes product code the whole team will see. Keep it scannable:

| # | Tripwire | Kind | Cover story | Lure(s) | See → Think → Do | Chain copied / final denial | Intent |
|---|---|---|---|---|---|---|---|

Then list the files you will touch, your assumptions, and anything the user must decide.

### 4. Implement

Patterns, reference code and per-framework notes are in references/implementation.md.

**Backend.**
- **Tripwire helper.** Add one small server-side module, in the app's style, that records a hit as one event in the event schema: through OpenTelemetry if the app already exports telemetry, otherwise through its own logger. It never raises, never blocks, does constant work per request, and never changes the request. If the user wants alerts beyond that, route it into the alerting the app already has.
- **Decoy routes.** Declare each decoy as a real route beside its sibling, in the same router, file and style. Copy the sibling's chain in order: authentication, then the tripwire, then the sibling's loaders and permission checks, then body validation in the sibling's style. End with the final denial through the app's own error mechanism. A decoy never writes, sends, enqueues or calls out, and reads nothing beyond what the sibling's loaders read.
- **Inferred decoys.** Add the method as a real handler on the existing path, in the same router or view, so the framework lists it in `Allow` and OPTIONS like any real method.
- **Honey fields.** In the real endpoint, before the body is validated or used: detect the field (present, or a value other than the expected one), record it, and make sure it can never reach the logic. Preserve exactly what the endpoint does with that field today: if it currently ignores unknown fields, discard it; if it rejects them, let it be rejected the same way. Inspect only the top-level field, never every element of an array, and treat values of any type without crashing.
- **Identity.** The tripwire runs after the app's own authentication, so pass it the authenticated user and their role.
- **Bait fields.** Add each bait field to the real serializer with the smallest idiomatic change. Confirm the real write handler never reads the honey field.
- **Inventory.** Keep one server-side list of every tripwire, and mark each decoy in server code the way the team marks deliberate code (a one-line comment naming the cover story, or a no-op decorator). Server code never reaches browsers, so clarity there costs nothing.

**Frontend** (references/frontend-lures.md):

- Write lures in the files, helpers, types and idioms the codebase already uses, so they read as the same team's work.
- Give each lure its natural footprint and nothing more: the client method, its type, the gate that keeps it unreachable, and strings if the app translates strings.
- Make every lure unreachable for real users. Either gate it on something no real user can satisfy (a role the backend never grants, a flag that is never enabled), or leave it uncalled on a class or object the bundler keeps.
- Nothing shipped to the browser may hint at its purpose. Check identifiers, strings, comments, file and chunk names, CSS classes, test IDs, storage keys, flag names and locale keys. Words to avoid include trap, decoy, honey, lure, bait, canary, tripwire, fake, sensor and deception.

### 5. Verify

A tripwire you haven't fired is a tripwire you don't have. Commands and details: references/verification.md. `${CLAUDE_SKILL_DIR}` below means the directory that contains this SKILL.md.

1. **Project checks.** Lint, type checks and the app's existing tests pass. Decoys must not change any real route.
2. **Each decoy, probed like its sibling.** Send the same probes to the decoy and its sibling: anonymous, a normal user, the owner of their own workspace, an unknown, foreign and malformed ID, a bad body, an expired token, other methods. Every response matches the sibling's except the final denial, and the tripwire records every authenticated hit with the right user, role and intent.
3. **Inert.** Hit each decoy as every role, then show that no data changed (write it as a test).
4. **Elimination.** As a tester with the accounts a customer can create, list every endpoint you can make work. Any decoy route left over must be denied by a gate that real routes also apply, not by something only decoys mention.
5. **Each honey field.**
   - The real UI's exact request produces no event and no change in behavior.
   - A tampered value produces an event.
   - The handler never sees the field.
6. **Response parity.** `node ${CLAUDE_SKILL_DIR}/scripts/compare_responses.mjs` against the sibling: anonymous and with an expired token using `--identical`, and signed in as a normal user.
7. **Frontend survival.** Build for production, then run `node ${CLAUDE_SKILL_DIR}/scripts/scan_bundle.mjs --dir <build-output> --lure <string> ...`. Every lure must survive the bundler, with nothing near it that reveals intent.
8. **False positives.** For each lure, show that no real code path calls it and no real user can pass its gate. For each honey field, show exactly what the real UI sends. Run the e2e suite if there is one.
9. **Tripwire robustness.** Make the helper's logger raise in a test, and send an oversized or deeply nested body to every honey-field endpoint; responses and response times must not change.

### 6. Report

Finish with a report the user can hand to their security team:
- the inventory table from the plan, with file:line for every decoy, honey-field check and lure;
- a curl command that fires each tripwire;
- where alerts go;
- the false-positive analysis;
- assumptions and residual risks;
- maintenance notes.

The inventory lives in the report and the server-side list, never in anything shipped to browsers.

## Keep the team in on it

Decoys only work if the people who maintain the app know about them. Otherwise someone deletes a lure as dead code. Worse, someone wires a decoy into real UI, or "finishes" a decoy route into a real feature, and floods the alert channel.

- The server-side tripwire list is the authoritative inventory, and each decoy carries a server-side marker.
- Each tripwire has a test that fails if it stops recording.
- In a private repository:
  - add a short note to the repo's agent instructions (AGENTS.md, CLAUDE.md) naming the decoys and lure symbols and asking agents not to remove, call or complete them;
  - suggest CODEOWNERS entries so the security team reviews changes to those files.
- Commit messages and PR descriptions describe the change accurately for reviewers.
- In a public repository, decoy code and notes are visible to attackers too. Follow references/implementation.md §9 and tell the user what remains visible.

## Ground rules

- **Never weaken the real application.** Decoys perform no real actions, read no data beyond their sibling's loaders, and change no state. Honey fields never influence logic. Bait exposes nothing real: no internal IDs, secrets or other users' data.
- **A false positive is a bug.** Nothing legitimate may trip a tripwire: real users, the real frontend, crawlers, link previews, prefetchers, uptime checks, or the team's own tests. When unsure, pick the placement with no false-positive risk.
- **The tripwire never breaks a request.** It catches its own errors, does constant work whatever the request contains, and adds no noticeable latency.
- **No new dependencies or patterns.** Decoys use only what the app already uses.
- **Don't plant credentials or secrets of any kind**, even fake ones. They set off secret scanners and incident processes well beyond this app.
- **Don't break clients.** Adding a response field can break strict decoders, response-schema validation and contract or snapshot tests. Check the consumers first.
- **Stay in scope.** Change only what the plan says. Ask before touching auth, infrastructure or CI.

## When deception is already in place

Review before adding:
- fire every existing tripwire;
- run the parity and bundle checks;
- look for tells, decoys that no longer match current conventions, decoys whose chain has drifted from their sibling's, and tripwires that record no identity.

Propose fixes in the plan format, then extend. For a request about one specific decoy or field, skip the portfolio. Still capture the real responses for that area, review the design and verify it.

## Reference files

- **references/implementation.md**: anatomy of a decoy route, final denials, inferred decoys, honey fields, the tripwire helper with reference code, inventory, public repositories, framework notes, safety checklist.
- **references/frontend-lures.md**: how attackers read frontends, lure patterns, build survival, false-positive hazards, tells, notes per framework.
- **references/backend-traps.md**: cover stories, honey-field design and expected values, responses, breadcrumb chains, intents, directions by domain, infrastructure gotchas.
- **references/verification.md**: verification commands, the bundled scripts, the false-positive audit, the report template.
- **references/worked-example.md**: one end-to-end example contrasting an obvious design with a convincing one.
