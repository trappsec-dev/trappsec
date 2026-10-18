---
layout: default
title: Baiting & Lures
permalink: /baiting-and-lures/
tagline: "A trap no one finds doesn't fire. Lead attackers to your decoys without showing them a decoy."
---

Traps are only effective if attackers find them. A lure is whatever leads an attacker there: a client-side reference, a field in a response, a path that follows from your API's conventions. A lure that looks planted is worse than none, though. It tells the attacker the app is instrumented, and they become careful.

This page summarizes the approach of the [`add-deception` agent skill](https://github.com/trappsec-dev/trappsec/tree/main/plugins/trappsec/skills/add-deception), which designs lures for your specific app and verifies them. The skill's references hold the detail: [frontend lures](https://github.com/trappsec-dev/trappsec/blob/main/plugins/trappsec/skills/add-deception/references/frontend-lures.md), [decoy routes, honey fields and responses](https://github.com/trappsec-dev/trappsec/blob/main/plugins/trappsec/skills/add-deception/references/backend-traps.md), and a [worked example](https://github.com/trappsec-dev/trappsec/blob/main/plugins/trappsec/skills/add-deception/references/worked-example.md) that contrasts an obvious design with a convincing one.

{: .warning }
> **Don't copy names.** This page deliberately gives no paths, field names or method names. Any concrete name that appears in public docs ends up in many deployments and becomes a signature attackers learn. Derive every name from your own codebase. The same goes for the apps in [`examples/`](https://github.com/trappsec-dev/trappsec/tree/main/examples): they are test fixtures for the end-to-end suite, not deception patterns.

### Lures that look discovered, not planted

In blind reviews of agent-built deception, red-team reviewers rated how likely each kind of lure was to be planted. Read it as an ordering, from least to most suspicious:

| Lure | Rated likely planted |
|---|---|
| Nothing new in the client: decoys inferred from the API's own conventions, honey fields on values the client already reads or sends back | 2–35% |
| One flag- or role-gated entry point to a decoy | 5–40% |
| An uncalled client method for a powerful capability | 25–70% |
| A hidden or disabled field of a kind the app's other forms don't carry | 20–80% |
| Something nothing uses: an unread `data-` attribute, a handler for a form no page renders, commented-out code, a dangling reference in docs | 40–80% |

So prefer the top of the list, keep visible lures few, and never give two of them the same pattern. Comments that point at a lure ("do not use", "remove before prod", an emoji marker) are the strongest tell of all.

### Principles

*   **Extrapolate, don't invent.** Derive each decoy from something real: a sibling of a real resource, the previous version of a real route, a role next to your real roles, a field that sits naturally beside real fields. Use your app's own vocabulary and URL scheme.
*   **Prefer decoys that need no lure.** Attackers enumerate around every resource they see: other methods on it, the collection behind an item, the previous API version. A decoy at such a path leaves nothing in the client to scrutinize and catches exactly the people who probe.
*   **Avoid paths generic scanners probe** (admin, debug, actuator-style paths). They draw anonymous noise and look generic. An application-specific path is found only by someone who studied your app.
*   **Give every lure an innocent reason to exist.** Real dead code has a story: behind a flag, gated on a role, kept for an older client. Write the one-sentence cover story first; it decides naming, placement and response.
*   **Bait honey fields with what's already there.** The best honey field is one an attacker would try on that endpoint anyway: a value the real client already reads in a response, or a value the real form never offers. A field foreign to your data model (say, a boolean admin flag in an app whose permissions are role-based) stands out.
*   **Keep every layer consistent.** If the client calls a decoy with POST, the trap accepts POST. The decoy's errors, IDs, timestamps and content type match its real siblings. Its responses are stable: derive synthetic values from the request rather than randomizing them per call, and prefer the app's real 403 over a success that looks too good to be true.
*   **Chain the breadcrumbs.** Let one tripwire lead to the next, for example a decoy's 403 that names a permission, and a honey field that accepts it. The second alert removes doubt about intent.
*   **Leave no fingerprints.** Nothing shipped to the browser may hint at its purpose: identifiers, strings, comments, file and chunk names, storage keys, flag names. Never ship trappsec's default responses; set [default responses](/api/#default-responses) to your app's real ones.
*   **A false positive is a bug.** No real user, crawler, prefetcher or test may ever reach a decoy or send a honey field. Gate client lures on something no real user can satisfy, and fire every tripwire yourself before relying on it.

### Before writing code: See → Think → Do

For every tripwire, write three lines:

*   **See**: the exact artifact the attacker meets, and where.
*   **Think**: the belief it should create.
*   **Do**: the action that belief leads to. It must be the action that fires the alert.

If you cannot write a plausible Think, the tripwire is not believable. If the Do is not the alerting action, it will not fire.
