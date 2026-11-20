---
name: add-response
description: Give an application the user owns a safe way to act on a detection: revoke a session or credential, require re-authentication, suspend an account, block or closely watch a caller, on a directive from an operator or the security backend, using the app's own mechanisms, with every directive expiring, audited and reversible. Use this whenever the user wants to respond to or contain an attacker from inside their app, block or sign out a flagged user, add a kill switch for accounts or API keys, wire findings from add-detection or add-deception to an action, or close the loop from detection to response. Not for deciding which detections deserve a response, rate limiting, WAF or bot rules, IP reputation feeds, or changing how authentication works.
license: MIT
---

# Add response

You are giving the application a way to act on what the other trappsec skills report. They are detect-only by design: they change no response. This skill is the one place where a caller's experience changes on purpose, so it is built to be narrow, slow to trust and quick to undo.

It adds three things: a list of **directives** (act on this account, credential, session, tenant or address, in this way, until this time), an **intake** through which an operator or the security backend issues and lifts them, and an **enforcement seam** where the app carries them out with mechanisms it already has. It does not decide who deserves one. That is a person's call, or the backend's policy.

The judgment calls are yours:
- which actions this app can carry out with code it already has, and which it can't;
- where the one seam goes, so no request can pass around it and none is slowed by it;
- who may issue a directive, and how the app knows it was them;
- proving that a wrong directive is cheap to undo, and that a broken response path changes nothing.

## What makes response safe

| Property | In practice |
|---|---|
| Native | Each action uses what the app already does: its own session invalidation, key revocation, account suspension, re-authentication prompt. The caller sees a response the app already gives. |
| Directed | The app acts only on a directive that names a target, an action, a reason and an expiry. It contains no detection logic and no thresholds. |
| Temporary | Every standing directive expires. Nothing this skill adds can lock someone out forever. |
| Reversible | Lifting a directive restores the caller, and the skill has shown that it does. |
| Fail-open | With the directive store unreachable, stale or corrupt, every request is served as if there were no directives. Response is never a way to take the app down. |
| Bounded | Protected targets can't be named. One directive can't reach a whole tenant or a shared address unless the user turned that on. |
| Authenticated | Only an operator with the app's own admin rights, or a signed request from the backend, can issue one. |
| Accounted for | Issuing, first enforcement, lifting and expiry are audit records. Every request a directive touched says so on its span. |

## Actions

Offer only the actions this app can carry out with code it already has. Prefer the ones that are done once and leave nothing standing.

| Action | What it does | Kind | Needs |
|---|---|---|---|
| `watch` | Nothing the caller can see. Marks the target's requests so the backend keeps every trace | Standing | Nothing |
| `revoke_session` | Ends the target's sessions through the app's own sign-out or invalidation; they sign in again | One-shot | A way to invalidate sessions server-side |
| `revoke_credential` | Disables one API key or token through the app's own revocation | One-shot | Revocable credentials |
| `step_up` | Requires the app's own re-authentication or second factor before the next sensitive action | Standing | An existing re-authentication flow |
| `suspend` | Suspends the account through the app's own suspension, restored when the directive ends | Standing | An existing suspended state |
| `block` | Refuses the target's requests at the seam with the app's own response for a suspended or forbidden caller | Standing | Nothing, which is why it is the last resort |

A one-shot action is carried out when the directive is issued, by calling the app's own function, and needs no check on later requests. A standing action is carried out at the seam on each request until the directive ends. `suspend` belongs to whichever the app's own suspension is: a flag the app already checks on every request needs nothing at the seam, only a lift when the directive ends.

An action whose mechanism the app lacks (stateless tokens that can't be revoked, no re-authentication flow) is left out and listed under Gaps with what it would take. Never build a new authentication feature to make an action possible.

Serving altered or decoy data to a flagged caller is not offered here: a mistake puts wrong data in front of a real customer, and nothing in the app can prove it never does.

## Workflow

### 0. Prerequisites and questions

- **OpenTelemetry traces and logs are a prerequisite.** Check them first, as references/telemetry.md describes. If they aren't in place, stop and tell the user.
- **Something to respond to.** This skill is useful once add-detection or add-deception reports on the app, or the user has another source of detections. Say so if neither is in place, and carry on if the user wants the kill switch on its own.
- **Ownership and scope.** Confirm this is the user's own application. This skill touches the request path and authentication's surroundings on purpose: show the plan and wait, even when the user said to go ahead on the other skills. Ask before touching infrastructure or CI.
- **Questions.** Ask in one batch, only what the code cannot tell you:
  1. Who issues directives: operators through the app's admin, the security backend automatically, or both? If the backend, how does it reach the app (a network path, and where the shared secret will live)?
  2. Which accounts must never be the target: break-glass and on-call accounts, service accounts other systems depend on, the customer's sole owner?
  3. May a directive target a whole tenant, or an address? Both reach people who did nothing: every member of an organization, everyone behind one office or carrier address. They stay off unless the user says otherwise.
  4. What should a blocked or suspended caller see: the app's existing suspended-account response, with its way to reach support, or its ordinary forbidden response?
  5. The longest a directive may last, per action (a starting point: a day for an account or credential, an hour for an address).

### 1. Reconnaissance

- **What the app can already do.** Its functions for ending sessions, revoking keys and tokens, suspending accounts and requiring re-authentication, who can call them today, and what each shows the caller.
- **Where a request's identity is settled.** The point after authentication where the user, credential, session and tenant are all known, on every surface: web, each API, WebSocket and subscription connections, background work a request starts.
- **Where state lives.** The store the app already uses for sessions, flags or cached configuration, and how other per-request lookups avoid a network call.
- **Existing admin and internal surfaces.** How operators authenticate, how internal or signed endpoints are built (a webhook receiver the app already has is the model for the intake), and how the app's commands are run.
- **The request context.** Whether the request-context module of references/telemetry.md is in place; the seam reads the same values it writes.

### 2. Design

1. **The directive.** One record: `id`, `target` (`type`: `user`, `credential`, `session`, `tenant` or `address`; and `id`), `action`, `reason` (a short code), `evidence` (the rule ID and trace ID of the finding it answers, when there is one), `issued_by`, `issued_at`, `expires_at`, and `mode` (`enforce` or `dry_run`). Stored in the app's own database or store, in a table of its own.
2. **The seam.** One function, called once per request right after identity is settled and before any handler, on every surface. It looks the request's keys up in an in-memory snapshot of the standing directives and carries out the first match by precedence (`block`, `suspend`, `step_up`, `watch`). The snapshot is refreshed in the background on an interval, never in a request. A directive therefore takes effect within one interval: state it.
3. **The intake.** Two doors, both ending in one function that validates and stores:
   - an operator's: a command in the app's command runner, and where the app has an admin area, a function behind its existing admin permission;
   - the backend's, only if the user wants it: one endpoint that accepts a signed request, built like the app's existing signed receivers.
4. **The rails**, checked by the intake on every directive, whoever sent it:
   - the action is one this app offers, and the target exists;
   - the target isn't protected (question 2), isn't the credential the intake itself uses, and isn't the last owner of a tenant;
   - `tenant` and `address` targets are refused unless turned on (question 3);
   - a standing directive has an expiry within the limit for its action; one with none gets the limit;
   - an `id` seen before changes nothing, so a retry is harmless.
5. **The switch.** One setting with three values: `off` (the seam returns at once and the intake refuses), `dry_run` (directives are stored and matched, nothing is carried out, and each match is reported) and `enforce`. It ships as `dry_run`. A directive's own `mode` can only make it gentler than the switch.
6. **What the caller sees**, per action, taken from question 4 and the app's existing responses, never a new page or message that names security or detection.

### 3. Present the plan

Always show the plan and wait:

| Action | Mechanism in the app (file:line) | Kind | What the caller sees | How it is undone |
|---|---|---|---|---|

Below it: where the seam goes on each surface and what could pass around it; the store and refresh interval; the intake's doors and who can use each; the protected targets and limits; the actions left out and why.

### 4. Implement

- **The seam does almost nothing.** A lookup by each of the request's keys in a map already in memory, and a return when none matches, which is nearly every request. No network, no database, no lock held across a request. Its errors are swallowed and the request goes on.
- **Fail open, visibly.** A snapshot that can't be refreshed is kept until each of its directives expires, then is empty. At startup with the store down, it is empty. Log one warning per failed refresh interval, never one per request.
- **One-shot actions run at intake**, through the app's own function, inside the same transaction as the directive where the app's store allows. If the function fails, the directive records the failure and nothing is retried silently.
- **Standing actions use the app's own response.** `block` returns what the app returns for a suspended or forbidden caller, built by the app's own error helper. `step_up` hands the request to the existing re-authentication flow and lets it resume. `watch` sets `security.flagged` on the server span and nothing else.
- **Long-lived connections.** A WebSocket or subscription opened before a directive is closed at the next refresh, where the app can enumerate a target's connections; otherwise say so under Gaps.
- **The backend's door.** Verify a signature over the timestamp and the exact body with a secret from the app's secret store, before parsing; refuse a timestamp more than five minutes old, a body over a few kilobytes and an `id` already stored; answer every refusal alike. Put it on the app's internal listener where it has one. The secret never appears in the repo, a log or a record.
- **Lifting.** Lifting a directive ends it now. For `suspend`, it restores the account only if this directive suspended it: an account suspended by a person for another reason stays suspended.
- **Record everything** as references/telemetry.md describes: audit records for each directive's life, span attributes on each request it touched, and the response actions in the inventory records.
- **Leave the other skills' rules alone.** A blocked caller is blocked on decoy routes too. Findings keep being recorded for a caller under a directive: the response is not a reason to stop looking.

### 5. Verify

1. **Project checks.** Lint, type checks and the app's existing tests pass.
2. **Nothing changes by default.** With the switch at `off`, and at `dry_run` with a directive for the test user, every response is identical to before the change, and under `dry_run` the server span reports the match.
3. **Each action, there and back.** In `enforce`: issue it, see its effect as the target, see no effect as another user of the same tenant and address, lift it, and see the target restored.
4. **Expiry.** A standing directive stops acting at its expiry with no one lifting it, and its expiry is recorded.
5. **The rails.** A protected account, a tenant's last owner, the intake's own credential, a `tenant` or `address` target while those are off, an expiry beyond the limit, an unknown action and a missing target are each refused, and each refusal is recorded.
6. **Fail open.** With the store unreachable at startup, and again once running: requests are served, the latency is unchanged, and the directives already held expire on time. Corrupt a stored directive: it is skipped and the rest hold.
7. **The backend's door.** A wrong signature, an old timestamp, a replayed request and an oversized body are refused alike; a valid request issued twice makes one directive.
8. **Cost.** Request latency is the same with no directives and with ten thousand.
9. **Records.** Each step of a directive's life is one audit record with the right actor, target and reason; each touched request's server span carries the action and directive ID; nothing holds the signing secret.
10. **Tests.** One per action for issue, enforce and lift; one per rail; one for fail-open; one for the signed door. A test that the seam runs on every surface: a request per surface under a `block` directive.

### 6. Report

- The actions offered, with file:line for each mechanism, and the ones left out.
- How to issue and lift a directive from each door, as commands the user can run.
- The switch, where it is set, and that it ships as `dry_run`: what to look at before moving to `enforce`.
- The delay between a directive and its effect.
- Protected targets, limits, and anything that can pass around the seam.
- **Advice on automation**, which is the backend's policy and not this skill's:
  - keep `test` findings and anonymous findings out of any automatic rule;
  - automate the actions a real user recovers from in a minute (`watch`, `step_up`, `revoke_session`), and leave `suspend` and `block` to a person;
  - a request another site made a signed-in victim's browser send can trip a tripwire in the victim's name. Before automating on a rule, check that its endpoint refuses cross-site requests, or the response becomes a way to sign other people out;
  - an attacker who learns that a tripwire signs them out has learned where the tripwires are. Responses that look like ordinary session expiry give away least.
- Assumptions and residual risks.

## Keep the team in on it

The seam is a line in the request path that someone will one day move. Mark it in code, test that it runs on every surface, and in a private repository add a short note to the repo's agent instructions (`AGENTS.md` or `CLAUDE.md`) naming the seam, the intake and the switch. Give the user the runbook from the report as a file beside the code: how to lift a directive at 3 a.m. is not something to look up in a pull request.

## Reference files

- **references/telemetry.md**: the OpenTelemetry prerequisite, the request context and records shared with add-auditing, add-deception and add-detection, and what a directive records.
