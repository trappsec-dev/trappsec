# Decoy routes, honey fields and responses

How to design them. How to build them in the app's own code is in native-implementation.md.

Contents
1. Cover stories for decoy routes
2. Honey fields
3. Responses
4. Breadcrumb chains
5. Intent labels
6. Directions by domain
7. Infrastructure gotchas

## 1. Cover stories for decoy routes

A decoy route is the endpoint behind a story. Pick stories that fit the app's history and model:

| Story | Fits when | Shape of the decoy |
|---|---|---|
| Retired version | The API is versioned (`/v2`) or was restructured | Previous-version mirrors of a few real resources, same naming |
| Support or operations tooling | Support staff act on customer accounts, and the app already gates something on a staff role | Account lookup, access or session tools, credit/adjustment actions, under the app's existing prefix and vocabulary |
| Dark-launched feature | The product has obvious next features | Bulk export, audit-log export, SSO/SCIM settings, API-key scopes, advanced reports |
| Partner or integration surface | The product integrates with others | Partner sync, webhook replay, import jobs |
| Data portability | User data can be exported | Export jobs for an account, workspace or user ID |
| Billing internals | There are plans, credits or invoices | Plan overrides, credit grants, invoice adjustments |
| Tenant administration | Multi-tenant model | Org transfer, member-role changes, workspace cloning |

Avoid features on the team's roadmap: when the real feature ships, it collides with the decoy.

**Inferred decoys need no lure.** Attackers enumerate around every resource they see:
- other methods on it (PATCH or DELETE on items the API lists);
- the collection behind a singular route, or the item behind a collection;
- the previous API version.

A decoy at such a path leaves nothing in the client to scrutinize. Someone reading the bundle or the pages finds nothing, and the only way to meet the decoy is to probe for it, which is exactly the behavior you want to catch.

Probing is also how it gets found out. A tester with real accounts makes every endpoint they can work, and whatever never works is left over. So give an inferred decoy neighbors: a method on a resource the API really writes, an item route whose collection exists, and a denial from a gate real routes share (SKILL.md, Design step 4).

Pick paths and methods that the real API plausibly lacks and that no real client calls. Expect method-fuzzing scanners to hit them anonymously; they get the sibling's real 401.

**Derive the path from real siblings.** Same prefix, version, pluralization, casing, trailing slash, ID placeholder style and action style. If real routes look like `/api/v2/workspaces/{workspaceId}/members`, a decoy looks like `/api/v2/workspaces/{workspaceId}/<sibling-resource>`, not `/admin/export`.

**Avoid paths generic scanners probe** (`/admin`, `/.env`, `/debug`, `/actuator`, `/phpinfo`, `/graphql`). They attract anonymous noise and look generic. An application-specific path is only found by someone who studied your app, which is exactly the person you want to catch.

## 2. Honey fields

A honey field is a parameter that real clients never send, or always send with one fixed value, on a real endpoint that would never honor it. The check records it and makes sure it can never change behavior (native-implementation.md §4).

In black-box testing, honey fields and value rules were never detected from behavior, while every decoy route was eventually singled out. Make them the core of the portfolio.

### Pick fields an attacker would try on that endpoint

Use the app's casing and authorization model:
- **Privilege:** whatever model the app uses, whether a role value, a permissions or scopes array, or an admin/staff flag. In an app built on roles, a boolean `is_admin` looks foreign. A role value or permission string fits.
- **Entitlement:** plan, tier, seats, quota, credits, trial end date, feature list.
- **Ownership and tenancy:** owner, organization or account IDs on resources whose owner the server derives from the session.
- **Price and state:** server-computed amounts or discounts on create endpoints; `status`, `verified` or `approved` on resources clients shouldn't promote.
- **Query parameters:** a distinct key that suggests wider access (deleted items, another user's view, all tenants), in the app's query style. A honey parameter needs its own key; don't repurpose a real parameter.

### Choose the expected value deliberately

| Real clients... | Record when |
|---|---|
| never send the field | it is present at all |
| always send one constant value (a hidden input, an echoed constant) | the value differs from that constant |
| echo back a per-user value they were given (their own org ID, their current permissions) | the value differs from what this caller could have been shown |

Compute per-user expected values from the authenticated caller, never from other fields in the same body.

**Stale but legitimate values.** A tab opened before a demotion still echoes the old role, and a tab from another account echoes that account's IDs. Accept values that are plausible for this caller, and record only impossible ones, such as a role nobody can hold through this endpoint, or a tenant the caller doesn't belong to. Write down any blind spot this creates.

Don't change the client to avoid staleness, for example by re-fetching before each save. Reviewers spot real code that bends around a tripwire.

### Values the real form never offers

A field the real handler reads can't be a honey field. A value the real UI never sends can still be a tripwire: a shipping option, payout schedule, role or status the form doesn't offer. Record it in the branch where the handler already rejects or falls back on unknown values, and keep the existing behavior. The lure is the real form, so nothing new ships to the client.

Only values that no version of the real form ever offered qualify. A tab opened before an option was retired still submits it.

### Bait it

A honey field nobody sees rarely gets tried. Return the field in a real GET response for the same resource, either constant for everyone or the caller's own value. Add it to the frontend type, and optionally display it read-only. Requirements:

- **Nothing real.** The field exposes nothing real or sensitive.
- **Unused today.** The real write handler doesn't read it.
- **Everywhere the resource appears.** If the resource appears in list, detail and embedded representations, the bait field appears in all of them, like the real fields.
- **Consumers survive it.** Adding the field doesn't break strict consumers: contract tests, response validation, strict mobile decoders.

## 3. Responses

A native decoy's responses come from its sibling's chain: authentication, loaders, permission checks and validation answer every probe exactly as they do for the sibling. You only choose the final denial (native-implementation.md §2).

**Capture real responses anyway.** Call real endpoints and record the status, body, headers and content type for each case: no credentials, expired credentials, valid credentials without permission, unknown resource, wrong method, invalid body. You'll compare the decoy with them during verification, and they tell you which error codes and messages the app already uses for the final denial.

**Every caller who passes the chain gets the same denial.** Choose one that makes sense for all of them, including the owner of their own workspace.

**Avoid success responses.** A created object implies follow-ups (fetching it, listing it, polling a job) that the rest of the API won't corroborate. If a read decoy must return data, the data must look like the app's real data:
- same ID format;
- realistic values;
- timestamps in the app's format;
- consistent across repeated calls. Derive values deterministically from the request (a hash of path parameters and user ID) rather than randomly per call.

Never include real data. Convincing fake data can trigger bug bounty reports, so agree on triage first.

## 4. Breadcrumb chains

A chain is two or more tripwires where one leads to the next. The first touch could be curiosity. Reaching the second is unambiguous, and both alerts carry the same identity.

Patterns:
- **Denial → escalation.** A decoy's 403 names the permission or role it requires, in the app's real error format. The current-user response shows where permissions or roles live. Sending that value to the profile or settings endpoint trips a honey field.
- **Rule → field.** A real form's 422 lists the values it accepts. A response field shows the caller's own value. Sending a value the form refuses, or tampering with that field elsewhere, trips the next tripwire.
- **Flag → feature → field.** A client-side flag reveals a gated entry point. Its decoy route answers with a validation error naming a field, and that field is a honey field on a real endpoint.

Each step must be plausible on its own and consistent with the others. The permission named in a 403 must be one the app's real routes use too.

## 5. Intent labels

Give every tripwire an intent, so alerts can be routed and prioritized. Use one consistent vocabulary, for example: `reconnaissance`, `privilege_escalation`, `account_takeover`, `cross_tenant_access`, `data_exfiltration`, `entitlement_abuse`, `payment_fraud`, `mass_assignment`, `defense_evasion`. If the team already has a security vocabulary, reuse it.

## 6. Directions by domain

These are directions, not names. Translate them into the app's vocabulary and conventions.

- **B2B SaaS:** workspace transfer, member-role changes, SSO/SCIM configuration, audit-log export, API-key scopes, seat counts. Honey fields: role or permissions, organization IDs.
- **E-commerce and marketplaces:** price or discount on cart and checkout creation, seller payout settings, order status, refunds. Honey fields: unit price, discount, payout account.
- **Fintech:** limits, verification status, fee overrides, statement exports. Honey fields: limits and verification state.
- **Healthcare and other regulated data:** record exports, delegate or caregiver access, consent state.
- **Developer platforms:** token scopes, usage quotas, organization billing, deployment environments.
- **Consumer apps:** premium entitlement, profile visibility, referral credits.

## 7. Infrastructure gotchas

- **Edge routing.** An API gateway, ingress or serverless config with an explicit route allowlist answers decoy paths itself (usually with a 404), and the decoy never records. Check the infrastructure config, and add routes there with the user's approval.
- **Caching.** A CDN that caches GET responses can serve a decoy without the request ever reaching the app. Make sure decoy responses aren't cacheable at the edge, just as real authenticated API responses shouldn't be.
- **Client IP.** Record the client IP the app already trusts (its proxy configuration), never a raw forwarding header.
- **Generated clients and contract tests.** A decoy that appears in a published spec gets picked up by SDK generators, contract tests and API fuzzers. Check which of the team's tools read the spec, and keep them away from decoys.
