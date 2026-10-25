---
name: add-auditing
description: Add an audit trail to an application the user owns. Records what people, services and agents do in the product: everyday activity on its core objects (creating, editing, deleting, reading sensitive records) and the security-relevant actions (sign-ins, role and permission changes, sharing, exports, API keys, admin settings) as domain events in the product's own terms, with who did it, on whose behalf, to what, from where and with what outcome, emitted as self-contained OpenTelemetry audit records. Use this whenever the user wants audit logs, a user activity log or history, an audit trail, compliance logging (SOC 2, ISO 27001, HIPAA), a customer-facing audit log API, or a record of authorization decisions. Not for debugging logs, metrics, tracing setup or detecting attacks.
license: MIT
---

# Add auditing

You are giving the application a trustworthy record of what was done in it. An audit record answers on its own, without joining anything else: who did what, to which thing, on whose behalf, from where, with which credential, whether it was allowed, and what came of it. It describes a meaningful operation in the product's own terms ("shared a project with an outside collaborator"), never an HTTP call.

The judgment calls are yours:
- which actions matter enough to audit;
- naming them in the product's language;
- recording each one where the decision is actually made, with its full context;
- proving the trail is complete and never leaks what it shouldn't.

## What makes a good audit trail

| Property | In practice |
|---|---|
| Domain-native | Events are product actions with stable names, not routes. An analyst understands each one without reading code. |
| Complete | Every success, denial and failure of an audited action produces exactly one event. No action escapes through a second code path. |
| Truthful | An event says what really happened: no success recorded for an operation that rolled back. |
| Attributed | Actor, the person behind an impersonation or agent, credential, session, tenant and origin. |
| Self-contained | Enough context (resource, participants, changes, consequence) that a reader needs no other source. |
| Safe | No secrets, no content, minimal personal data. |
| Non-interfering | Recording never changes, slows or breaks the operation. |

## What to audit

Two kinds of activity, both as audit events in the same schema.

**What users do with the product.** Creating, editing, deleting, restoring, moving and archiving the product's core objects (the projects, documents, orders, records, tickets the product is about), changes of status and assignment, and reads of records that are sensitive in this product (a patient's chart, a payroll run, a customer's payment details). This is the trail that answers "who changed this, and when", for support, customers and investigations alike. Record what changed, not the content.

**Actions a security team or a customer's admin would ask about:**
- authentication: sign-in success and failure, sign-out, MFA and password changes, session revocation;
- access: role and permission grants and revocations, membership invitations and removals, ownership transfers;
- sharing and exposure: sharing outside the organization, public links, visibility changes;
- data movement: exports, bulk downloads, bulk reads;
- credentials and integrations: API keys, OAuth clients, webhooks, connected apps;
- administration: security and organization settings, billing and plan changes, deletions, restores;
- impersonation and support access, and actions taken by automated agents.

Every allow or deny on a sensitive operation is itself worth recording: the permission evaluated, the decision and the reason.

Leave out what isn't a user's action: page views, searches and ordinary reads of non-sensitive data, housekeeping no user would ask about (cache refreshes, cleanup of expired rows), and the app's own internal calls. Those belong in product analytics or traces; if the user wants them too, raise the volume and cost first. A job that carries out an audited operation (settling orders, running an approved deploy) is a path into it and emits.

## Workflow

### 0. Prerequisites and questions

- **OpenTelemetry traces and logs are a prerequisite.** Check them first, as references/telemetry.md describes, including how the app samples traces. If they aren't in place, stop and tell the user.
- **Ownership.** Confirm this is the user's own application.
- **Existing audit logging.** Find any audit tables, activity feeds or audit-style logs. Leave their records, names and storage exactly as they are: customers, reports and compliance evidence may depend on them. Emit the `audit.*` events alongside, from the same points in the code, and use the existing action names as the starting point for the registry. Replacing or migrating an existing trail is the user's decision, as a separate change.
- **Questions.** Ask in one batch, only what the code cannot tell you:
  1. Who reads the trail: the security team, compliance, customers through an audit log API? Any regulation that dictates content or retention?
  2. What sits in front of the app in production (load balancer, CDN, ingress), if the repo doesn't say?

### 1. Reconnaissance

- **Where decisions are made.** Find the domain code that grants roles, shares things, deletes, exports and changes settings, not the routes that call it. Note every path into each operation: UI, API, background jobs, framework admin sites (Django admin, Rails admin) and their bulk actions, management commands and scripts. Built-in and developer-only commands (creating a superuser, seeding data) go under Gaps.
- **Authorization.** How permissions are evaluated, and where allows and denies happen.
- **Who and from where.** Where the authenticated principal lives (user, tenant, credential, session, impersonation, agents), and how the client IP reaches the app through its proxies.
- **Vocabulary.** The product's own names for things, from the UI, docs and code.

### 2. Design

1. **The action registry.** For each audited action: its event name (references/telemetry.md), operation type, the resources and participants it records, the parameters and changes that matter, and which outcomes it can have. Keep it in one place in the codebase, versioned with it.
2. **Sensitive data.** Decide per action what must never be recorded (secrets, content) and what personal data is truly needed.
3. **Volume.** Bulk operations, including a job that changes many objects in one run, are one event with a count. Autosave and rapid edits to one object are one event per editing session or window where the app has such a boundary, otherwise one per save. Unauthenticated failures (failed sign-ins) arrive at the caller's chosen rate: record them, and tell the user. For an API that authenticates every request with a token, record failed authentication only; a success is the request's span. Where a regulation treats listing records as access (a patient roster), ask whether listings are audited, one entry per page with a count.

### 3. Present the plan

Unless the user already told you to go ahead, show the registry and wait:

| Action (event name) | Operation | Emitted at | Outcomes | Records | Never records |
|---|---|---|---|---|---|

### 4. Implement

- **Emit where the decision is made**, in the domain layer, through one small module that builds each complete audit entry from the registry and the request context. Middleware only knows the request, not what it meant.
- **Refusals raised before the domain code belong to the action too**: an authentication or membership dependency, a guard on a group of routes, method-level authorization, request validation, the CSRF check. Name the action beside the route or handler (a dependency parameter, an annotation, a class macro) so the guard, or the framework's central handler (Rails `rescue_from`, Spring's `AccessDeniedHandler` and `AuthenticationEntryPoint`), records the refusal, then returns or re-raises exactly what it did before. Where guards are mounted before any route matches (Express routers), keep a method-and-path table in the registry for them to look up. Refusals made before the action is known (an unparseable body) or before the app's code runs (a gateway's own check, a WAF, a 401 for a missing credential) go under Gaps, naming where their record lives.
- **Authorizers.** An authorizer function the team wrote is app code: it records its rejections under an `auth.*` action. Its cached results hide repeats and delay revocation: tell the user.
- **Set the request context on the server span** as references/telemetry.md describes, reusing it if add-deception or add-detection already added it. The audit entry still carries its own copy of who and from where.
- **Success is recorded only once the operation has committed** (an after-commit hook, or right after the transaction returns); a sensitive read, once the response is built. Denials and failures are recorded where they happen. Capture the request's span when the entry is built; an after-commit callback can run outside it. Model hooks fire for saves that changed nothing and from seeds and consoles, and miss nested records: record real changes with an origin (a request, a job, a script) only. ORM callbacks that run before commit are not emit points. Make the tests run after-commit hooks (Django: `captureOnCommitCallbacks(execute=True)`; Spring: tests without `@Transactional`).
- **Every path into an audited operation emits**, including background jobs and admin tools.
- **Recording never fails, blocks or changes an operation.** If the trail must be guaranteed for an action (some compliance regimes require it), raise that with the user instead of deciding on your own.
- **Nothing sensitive.** Secrets and content never enter an event.

### 5. Verify

1. **Project checks.** Lint, type checks and the app's existing tests pass.
2. **Each action, each outcome.** For every action in the registry, trigger success, denial and failure where they exist. Each produces exactly one audit record that matches references/telemetry.md, with every required key, the right actor, credential, tenant, resource and outcome, and the request's trace and span IDs.
3. **No false successes.** An operation that fails or rolls back after the decision records a failure or nothing, never a success.
4. **Every path.** The same action through each entry point (UI, API, job, admin tool) emits the same audit entry; bulk paths emit their own action.
5. **Nothing leaks.** Search the emitted records and the exported spans from your test runs for secrets, tokens and content.
6. **Robustness.** Make your own recording module fail in a test, through one fault point it exposes (not the OpenTelemetry API, which the instrumentation shares); the operation behaves exactly as before.
7. **Names.** Every record and span attribute uses the names in references/telemetry.md, and nothing else in the app uses them with another meaning.
8. **Tests.** One test per action and outcome, asserting the audit entry.

### 6. Report

- The action registry, with file:line for each emission point.
- What each event records, and what it deliberately leaves out.
- Gaps: operations you couldn't audit and why.
- Recommendations for the pipeline the user runs, which this skill doesn't change: audit records routed by their logger to their own pipeline without sampling, a durable queue, write-once storage as the system of record, a copy to the SIEM, and alerting on producers that go silent. A record lives only in memory until its batch is exported, so a crash right after commit loses it; a local collector narrows that window.
- Existing logs that already carry what the trail must not (a typed login on a failed sign-in, a token in a URL): report them; don't change them.
- Assumptions and residual risks.

## Ground rules

- **Never change behavior.** The audited operation works exactly as before.
- **Never record secrets or content.**
- **Truthful over complete.** An event must never claim something that didn't happen.
- **Stay in scope.** Ask before touching auth, infrastructure, the telemetry pipeline or CI.

## Reference files

- **references/telemetry.md**: the OpenTelemetry prerequisite, the request context and records shared with add-deception and add-detection, and the self-contained audit entry.
