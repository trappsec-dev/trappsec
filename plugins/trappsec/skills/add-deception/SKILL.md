---
name: add-deception
description: Design and install trappsec deception in an application the user owns. Adds decoy API routes, honey fields and frontend lures that blend into the app's real code, wired to identity-attributed alerts and verified never to affect legitimate users. Use this whenever the user wants to add trappsec, decoys, honeypots, honey fields, canary endpoints, tripwires or lures to their own web app or API; wants to detect signed-in users probing business logic (hidden admin routes, mass assignment, privilege escalation, cross-tenant access); wants bait in their frontend that leads to decoys; or wants an existing trappsec setup reviewed, extended or made more convincing. Use it even if they never say "trappsec". Not for anti-spam form honeypots, UI focus traps, WAFs, rate limiting or vulnerability scanning.
license: MIT
---

# Add deception with trappsec

You are adding a detection layer to an application the user owns. trappsec supplies the runtime:
- decoy routes ("traps") that alert when touched;
- honey fields ("watches") that alert when a request tampers with them;
- alert delivery.

The judgment calls are yours:
- which decoys *this* app should have;
- making them indistinguishable from its real API and frontend;
- placing lures where attackers actually look;
- proving that no legitimate user can ever trip one.

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
| Detectable | Every touch produces an attributed alert, and you have fired it to prove it. |
| Variable | Shares no fingerprint with other decoys, other apps, or trappsec's defaults. |
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
4. **Let them discover it.** A full URL next to a "do not use" comment reads as bait. A role-gated button, a flag-gated code path or an extra response field is something the attacker feels clever for finding, and people trust what they discover. In blind reviews of agent-built deception, AI red-team reviewers rated how likely each lure was to be planted:

   | Lure | Rated likely planted |
   |---|---|
   | Nothing new in the client: decoys inferred from the API's conventions, honey fields on values the client already reads or sends back, values the forms never offer (references/backend-traps.md §1–2) | 2–35%; reviewers could only rate the app's own code |
   | One flag- or role-gated entry point to a decoy | 5–40% |
   | An uncalled client method for a powerful capability | 25–70% |
   | A hidden or disabled field of a kind the app's other forms don't carry | 20–80%, mostly above 40% |
   | Something nothing uses: a `data-` attribute no script reads, a handler for a form no page renders, a commented-out form | 40–80% |

   These come from blind reviews of two small apps, so read them as an ordering, not as measurements. Suspicion is also relative: in an otherwise clean client, reviewers rated the one gated high-value feature 35–40%, simply because it was the obvious place to look. So prefer the top of the list, keep visible lures few, and vary their patterns; reviewers noticed when two shared a template.
5. **Keep every layer consistent.** Frontend calls a decoy with POST → the trap accepts POST. There is a client method → there is a type. The app translates every string → the lure's strings are translated. Real 403s have a certain shape → the decoy's 403 has it too. Give a lure the care a real feature with the same stakes would get: one name across method, flag, handler and strings; its own place in the layout; a gate as strict as the value warrants; the states, copy and typed responses the real feature would have.
6. **Chain the breadcrumbs.** Design at least one path where touching one tripwire leads to the next. Example: a decoy's 403 names a permission, a response field shows where permissions live, and sending that permission trips a honey field. Each step is another alert, and the second step removes doubt about intent.
7. **Leave no fingerprints, including this skill's.** Names in this skill and its references only illustrate patterns. Never reuse them: a decoy path shared by many apps becomes a signature attackers learn. Never ship trappsec's default responses either.

### See → Think → Do

Before writing code, write these three lines for every tripwire:

- **See**: the exact artifact the attacker meets, and where (bundle chunk, response body, form field).
- **Think**: the belief it should create. Example from the worked example: "bulk ledger export exists, and only a client-side flag hides it."
- **Do**: the action that belief leads to. It must be the action that fires the alert (e.g. an authenticated POST to the decoy).

If you cannot write a plausible Think, the tripwire is not believable. If the Do is not the alerting action, the tripwire will not fire.

## Workflow

### 0. Check fit and ask what you can't infer

- **Supported backend.** trappsec supports:
  - Python: Flask, FastAPI, Django, Starlette, Litestar, Sanic, Tornado.
  - Node: Express, NestJS, Fastify, Hapi, Koa.
  - Go: net/http, Gin, Echo.

  If the API runs on anything else (Next.js route handlers, Rails, Spring...), tell the user and stop. Do not hand-roll a substitute. The user can request support at https://github.com/trappsec-dev/trappsec/discussions.
- **Ownership.** Confirm this is the user's own application. Deception belongs only in systems you operate.
- **Layout.** Find which service is the public API, where the frontend lives (same repo, another repo, none), and how each is built and run.
- **Questions.** Ask in one batch, and only what the code cannot tell you:
  1. Is the source repository public? Trap definitions in public source are visible to everyone (see references/backend-traps.md §8).
  2. Where should alerts go: logs only, a webhook/SIEM, Slack, OpenTelemetry?
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

  Decoys must reproduce these, so capture them from the running app rather than reading them off the code. If the app can't run locally, derive the shapes from its error handlers and tests, and say so in the report.
- Note where the valuable things are:
  - privilege: roles, permissions, impersonation;
  - money: plans, credits, prices, refunds;
  - other tenants' data: exports, org switching, IDs in URLs;
  - hidden features.

**The authors' view** (the texture of the code):
- **House-style dossier.** Write down:
  - API: URL scheme (prefix, versioning, plurals, casing, ID formats, action-route style), JSON casing and envelope, pagination, timestamp and money formats, error shape per status.
  - Auth: mechanism, role/permission model, tenancy model, domain vocabulary.
  - Frontend: HTTP client wrapper, folder layout, file naming, typing, i18n, role-gating idiom, feature-flag system, comment style.
- **Story material.** Read the history: `git log --oneline`, deprecated folders, version migrations, TODOs, flags, renamed features. The best decoys continue a story the codebase already tells.
- **Request authentication.** Trace how a request gets authenticated: global middleware, per-route middleware, guards, dependencies. This decides how `identify_user` must work (step 4).

If there is a frontend, read references/frontend-lures.md now.

### 2. Design

1. **Threat narrative.** In two or three sentences: who would attack this app, and what do they want? Examples: a B2B SaaS draws privilege escalation and cross-tenant access; a marketplace draws price and payout manipulation; a fintech app draws limit and balance tampering. Pick the 3–5 intents that matter.
2. **Portfolio.** For a typical app, 4–8 tripwires in total:
   - 1–3 decoy routes, each reached through a frontend lure or inferred from the API's own conventions (references/backend-traps.md §1);
   - 1–3 honey fields on real write endpoints, each baited by a field in a real response, or by a hidden input of a kind the app's forms already use;
   - optionally, a version-skew decoy, a honey query parameter, or a protocol decoy (e.g. GraphQL in an app that doesn't use it);
   - at least one breadcrumb chain linking two of the above.

   More is not better. Every decoy adds maintenance, false-positive risk and another chance of discovery. Reviewers judge the client as a whole, and three anomalies in a small client make each one look more deliberate. So in a small client, add something new and visible for one or two tripwires at most, each with a different pattern. Cover the rest with inferred decoys and with honey fields that real responses already bait.
3. **Specification.** For each tripwire, write down:
   - cover story and See → Think → Do;
   - path and method in house style;
   - lure placements;
   - anonymous and authenticated responses, copied from real shapes (references/backend-traps.md §3);
   - intent label;
   - the guard that keeps legitimate traffic away.
4. **Review.** Look at the design through four sets of eyes, and revise until it passes each:
   - **A skeptical tester who has seen honeypots before.** Why does this exist? Why here? Why written like this? What happens if I poke it differently: no auth, wrong method, garbage body, another ID? Does anything differ from its neighbors?
   - **A stranger holding the diff.** Shown the change without context, could they point at the decoy? If so, it doesn't blend in.
   - **A future maintainer or coding agent.** Will they delete this as dead code, or "fix" it by wiring it into the real UI? What stops that?
   - **An ordinary user.** Could any normal action, browser behavior or client retry send this request or this field?

### 3. Present the plan

Unless the user already told you to go ahead, show the plan and wait. It changes product code the whole team will see. Keep it scannable:

| # | Tripwire | Kind | Cover story | Lure(s) | See → Think → Do | Response (anon / authed) | Intent |
|---|---|---|---|---|---|---|---|

Then list the files you will touch, your assumptions, and anything the user must decide.

### 4. Implement

**Backend.** Exact syntax per language and framework is in references/trappsec-api.md.

- **Install and initialize.** Install trappsec with the project's package manager. Create one `Sentry` per public API service, at the point the framework requires (Express/Koa: after body parsers). Use the real service name and take the environment from config.
- **Version.** Check which release you installed. Registries can lag the docs, and 0.2.0 needs workarounds (references/trappsec-api.md §9). Tell the user if you hit one.
- **One module.** Put every trap and watch definition in one plainly named server-side module, with a one-line cover-story comment per tripwire. Server code never reaches browsers, so clarity there costs nothing and helps maintainers.
- **Defaults.** Set `default_responses` for both profiles to the app's real responses. That way no trap can ever emit trappsec's recognizable defaults.
- **Identity.** Wire `identify_user` to the app's real authentication, returning `user` and `role` (or nothing when anonymous). Trap routes run none of the app's per-route middleware, guards or dependencies. If authentication happens per route, verify the session or token inside the callback with the app's own helper.

  If this fails, a signed-in attacker receives the anonymous decoy response. That breaks the illusion and the attribution at once.
- **Outputs and plumbing.**
  - alert outputs, with secrets read from environment variables;
  - `override_source_ip` if the app sits behind a proxy;
  - `is_trap` exemptions for CSRF middleware that needs them;
  - `close()` on shutdown.
- **Bait fields.** Add each bait field to the real serializer with the smallest idiomatic change. Confirm the real handler never reads the honey field: trappsec strips it before the handler runs, so a field the handler needs cannot be a honey field.

**Frontend** (references/frontend-lures.md):

- Write lures in the files, helpers, types and idioms the codebase already uses, so they read as the same team's work. Add no dependencies and no patterns the app does not already have.
- Give each lure its natural footprint and nothing more: the client method, its type, the gate that keeps it unreachable, and strings if the app translates strings.
- Make every lure unreachable for real users. Either gate it on something no real user can satisfy (a role the backend never grants, a flag that is never enabled), or leave it uncalled on a class or object the bundler keeps.
- Nothing shipped to the browser may hint at its purpose. Check identifiers, strings, comments, file and chunk names, CSS classes, test IDs, storage keys, flag names and locale keys. Words to avoid include trap, decoy, honey, lure, bait, canary, tripwire, fake, and trappsec itself.

### 5. Verify

A tripwire you haven't fired is a tripwire you don't have. Commands and details: references/verification.md. `${CLAUDE_SKILL_DIR}` below means the directory that contains this SKILL.md.

1. **Project checks.** Lint, type checks and tests pass. The server boots (bootstrap raises if a trap duplicates a real route).
2. **Each trap, anonymous.** The response matches the real anonymous response, and a `signal` event is logged.
3. **Each trap, signed in as a normal test user.** You get the designed response and an `alert` event with the right user, role and intent.
4. **Each honey field.**
   - Sending the default, or the real UI's normal request, produces no event and no change in behavior.
   - A tampered value produces an alert.
   - The handler never sees the field.
5. **Response parity.** `node ${CLAUDE_SKILL_DIR}/scripts/compare_responses.mjs` against a real sibling endpoint, anonymous and authenticated.
6. **Frontend survival.** Build for production, then run `node ${CLAUDE_SKILL_DIR}/scripts/scan_bundle.mjs --dir <build-output> --lure <string> ...`. Every lure must survive the bundler, with nothing near it that reveals intent.
7. **False positives.** For each lure, show that no real code path calls it and no real user can pass its gate. For each honey field, show exactly what the real UI sends. Run the e2e suite if there is one.

### 6. Report

Finish with a report the user can hand to their security team:
- the inventory table from the plan, with file:line for every trap and lure;
- a curl command that fires each tripwire;
- where alerts go;
- the false-positive analysis;
- assumptions and residual risks (e.g. response headers a trap cannot reproduce);
- maintenance notes.

The inventory lives in the report and the server-side module, never in anything shipped to browsers.

## Keep the team in on it

Decoys only work if the people who maintain the app know about them. Otherwise someone deletes a lure as dead code. Worse, someone wires a decoy into real UI and floods the alert channel.

- The server-side trappsec module is the authoritative list.
- In a private repository:
  - add a short note to the repo's agent instructions (AGENTS.md, CLAUDE.md) naming the lure symbols and asking agents not to remove or call them;
  - suggest CODEOWNERS entries so the security team reviews changes to those files.
- Commit messages and PR descriptions describe the change accurately for reviewers.
- In a public repository, notes are visible to attackers too. Follow references/backend-traps.md §8 and tell the user what remains visible.

## Ground rules

- **Never weaken the real application.** Decoys perform no real actions, read no real data and change no state. Honey fields never influence logic. Bait exposes nothing real: no internal IDs, secrets or other users' data.
- **A false positive is a bug.** Nothing legitimate may trip a tripwire: real users, the real frontend, crawlers, link previews, prefetchers, uptime checks, or the team's own tests. When unsure, pick the placement with no false-positive risk.
- **Never ship trappsec defaults.** The default 401 and 200 bodies are identical across every trappsec deployment.
- **Don't plant credentials or secrets of any kind**, even fake ones. They set off secret scanners and incident processes well beyond this app.
- **Don't break clients.** Adding a response field can break strict decoders, response-schema validation and contract or snapshot tests. Check the consumers first.
- **Stay in scope.** Change only what the plan says. Ask before touching auth, infrastructure or CI.

## When trappsec is already installed

Review before adding:
- fire every existing tripwire;
- run the parity and bundle checks;
- look for tells, trappsec default responses, decoys that no longer match current conventions, and identity that falls back to `signal`.

Propose fixes in the plan format, then extend. For a request about one specific trap or field, skip the portfolio. Still capture the real responses for that area, review the design and verify it.

## Reference files

- **references/frontend-lures.md**: how attackers read frontends, lure patterns, build survival, false-positive hazards, tells, notes per framework.
- **references/backend-traps.md**: cover stories, honey-field design and defaults, responses that blend in, breadcrumb chains, intents, infrastructure gotchas, public repositories.
- **references/trappsec-api.md**: exact API for Python, Node and Go; per-framework setup; identity patterns; alert outputs.
- **references/verification.md**: verification commands, the bundled scripts, the false-positive audit, the report template.
- **references/worked-example.md**: one end-to-end example contrasting an obvious design with a convincing one.
