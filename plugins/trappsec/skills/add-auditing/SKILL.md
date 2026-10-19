---
name: add-auditing
description: Add an audit trail to an application the user owns. Records what people, services and agents do in the product: everyday activity on its core objects (creating, editing, deleting, reading sensitive records) and the security-relevant actions (sign-ins, role and permission changes, sharing, exports, API keys, admin settings) as domain events in the product's own terms, with who did it, on whose behalf, to what, from where and with what outcome, emitted as OpenTelemetry events. Use this whenever the user wants audit logs, a user activity log or history, an audit trail, compliance logging (SOC 2, ISO 27001, HIPAA), a customer-facing audit log API, or a record of authorization decisions. Not for debugging logs, metrics, tracing setup or detecting attacks.
license: MIT
---

# Add auditing

You are giving the application a trustworthy record of what was done in it. An audit event answers, without joining anything else: who did what, to which thing, on whose behalf, from where, with which credential, whether it was allowed, and what came of it. It describes a meaningful operation in the product's own terms ("shared a project with an outside collaborator"), never an HTTP call.

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

Leave out what isn't a user's action: page views, searches and ordinary reads of non-sensitive data, background housekeeping, and the app's own internal calls. Those belong in product analytics or traces. If the user wants them too, raise the volume and cost with them first.

## Workflow

### 0. Prerequisites and questions

- **OpenTelemetry logs are a prerequisite.** Check them first, as references/telemetry.md describes. If they aren't in place, stop and tell the user.
- **Ownership.** Confirm this is the user's own application.
- **Existing audit logging.** Find any audit tables, activity feeds or audit-style logs. Extend or align with them rather than creating a parallel trail, and ask before replacing one.
- **Questions.** Ask in one batch, only what the code cannot tell you:
  1. Who reads the trail: the security team, compliance, customers through an audit log API? Any regulation that dictates content or retention?
  2. What sits in front of the app in production (load balancer, CDN, ingress), if the repo doesn't say?

### 1. Reconnaissance

- **Where decisions are made.** Find the domain code that grants roles, shares things, deletes, exports and changes settings, not the routes that call it. Note every path into each operation: UI, API, background jobs, admin tools, scripts.
- **Authorization.** How permissions are evaluated, and where allows and denies happen.
- **Who and from where.** Where the authenticated principal lives (user, tenant, credential, session, impersonation, agents), and how the client IP reaches the app through its proxies.
- **Vocabulary.** The product's own names for things, from the UI, docs and code.

### 2. Design

1. **The action registry.** For each audited action: its event name (references/telemetry.md), operation type, the resources and participants it records, the parameters and changes that matter, and which outcomes it can have. Keep it in one place in the codebase, versioned with it.
2. **Sensitive data.** Decide per action what must never be recorded (secrets, content) and what personal data is truly needed.
3. **Volume.** For bulk and high-volume operations, record one event per operation with a count, not one per item. Autosave and other rapid edits to the same object become one event per editing session or time window, with the fields that changed, if the app already has such a boundary; otherwise one per save.

### 3. Present the plan

Unless the user already told you to go ahead, show the registry and wait: actions, event names, where each is emitted, and what it records.

### 4. Implement

- **Emit where the decision is made**, in the domain layer, through one small module that builds events from the registry. Middleware only knows the request, not what it meant.
- **Success is recorded only once the operation has committed.** Denials and failures are recorded where they happen.
- **Every path into an audited operation emits**, including background jobs and admin tools.
- **Recording never fails, blocks or changes an operation.** If the trail must be guaranteed for an action (some compliance regimes require it), raise that with the user instead of deciding on your own.
- **Nothing sensitive.** Secrets and content never enter an event.

### 5. Verify

1. **Project checks.** Lint, type checks and the app's existing tests pass.
2. **Each action, each outcome.** For every action in the registry, trigger success, denial and failure where they exist. Each produces exactly one event that matches references/telemetry.md, with the right actor, credential, tenant, resource, outcome and trace context.
3. **No false successes.** An operation that fails or rolls back after the decision records a failure or nothing, never a success.
4. **Every path.** The same action through each entry point (UI, API, job, admin tool) emits the same event.
5. **Nothing leaks.** Search the emitted events from your test runs for secrets, tokens and content.
6. **Robustness.** Make recording fail in a test; the operation still behaves exactly as before.
7. **Tests.** One test per action and outcome, asserting the event.

### 6. Report

- The action registry, with file:line for each emission point.
- What each event records, and what it deliberately leaves out.
- Gaps: operations you couldn't audit and why.
- Recommendations for the pipeline the user runs, which this skill doesn't change: audit events on their own logs pipeline without sampling, a durable queue, write-once storage as the system of record, a projected copy to the SIEM, and alerting on producers that go silent.
- Assumptions and residual risks.

## Ground rules

- **Never change behavior.** The audited operation works exactly as before.
- **Never record secrets or content.**
- **Truthful over complete.** An event must never claim something that didn't happen.
- **Stay in scope.** Ask before touching auth, infrastructure, the telemetry pipeline or CI.

## Reference files

- **references/telemetry.md**: the OpenTelemetry prerequisite, the event schema shared with add-deception and add-detection, and the audit events.
