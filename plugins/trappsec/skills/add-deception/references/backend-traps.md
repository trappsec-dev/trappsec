# Decoy routes, honey fields and responses

Contents
1. Cover stories for decoy routes
2. Honey fields
3. Responses that blend in
4. Breadcrumb chains
5. Intent labels
6. Directions by domain
7. Infrastructure and integration gotchas
8. Public repositories

## 1. Cover stories for decoy routes

A decoy route is the endpoint behind a story. Pick stories that fit the app's history and model:

| Story | Fits when | Shape of the decoy |
|---|---|---|
| Retired version | The API is versioned (`/v2`) or was restructured | Previous-version mirrors of a few real resources, same naming |
| Support or operations tooling | Support staff act on customer accounts | Account lookup, access or session tools, credit/adjustment actions, under the app's existing prefix and vocabulary |
| Dark-launched feature | The product has obvious next features | Bulk export, audit-log export, SSO/SCIM settings, API-key scopes, advanced reports |
| Partner or integration surface | The product integrates with others | Partner sync, webhook replay, import jobs |
| Data portability | User data can be exported | Export jobs for an account, workspace or user ID |
| Billing internals | There are plans, credits or invoices | Plan overrides, credit grants, invoice adjustments |
| Tenant administration | Multi-tenant model | Org transfer, member-role changes, workspace cloning |
| Protocol decoy | The app does NOT already use GraphQL (or similar) | A GraphQL endpoint that parses queries and answers like a real server (trappsec's GraphQL example) |

**Inferred decoys need no lure.** Attackers enumerate around every resource they see:
- other methods on it (PATCH or DELETE on items the API lists);
- the collection behind a singular route, or the item behind a collection;
- the previous API version.

A decoy at such a path leaves nothing in the client to scrutinize. Someone reading the bundle or the pages finds nothing, and the only way to meet the decoy is to probe for it, which is exactly the behavior you want to catch. Every client-side lure, by contrast, drew some suspicion in blind reviews.

Pick paths and methods that the real API plausibly lacks and that no real client calls. Answer them the way the real API answers a forbidden request on that resource. Expect method-fuzzing scanners to hit them anonymously (signals only).

**Derive the path from real siblings.** Same prefix, version, pluralization, casing, ID placeholder style and action style. If real routes look like `/api/v2/workspaces/{workspaceId}/members`, a decoy looks like `/api/v2/workspaces/{workspaceId}/<sibling-resource>`, not `/admin/export`.

**Avoid paths generic scanners probe** (`/admin`, `/.env`, `/debug`, `/actuator`, `/phpinfo`). They attract anonymous noise and look generic. An application-specific path is only found by someone who studied your app, which is exactly the person you want to catch.

**Set methods explicitly.** Traps default to GET and POST. Register exactly the methods the lure uses. Real routes don't usually accept both.

## 2. Honey fields

A honey field is a parameter that real clients never send, or always send with one fixed value, on a real endpoint that would never honor it. trappsec strips it before the handler runs, so it can never change behavior. It alerts when the field is present, or when its value differs from the default.

### Pick fields an attacker would try on that endpoint

Use the app's casing and authorization model:
- **Privilege:** whatever model the app uses, whether a role value, a permissions or scopes array, or an admin/staff flag. In an app built on roles, a boolean `is_admin` looks foreign. A role value or permission string fits.
- **Entitlement:** plan, tier, seats, quota, credits, trial end date, feature list.
- **Ownership and tenancy:** owner, organization or account IDs on resources whose owner the server derives from the session.
- **Price and state:** server-computed amounts or discounts on create endpoints; `status`, `verified` or `approved` on resources clients shouldn't promote.
- **Query parameters:** a distinct key that suggests wider access (deleted items, another user's view, all tenants), in the app's query style. A honey parameter needs its own key. You can't watch one value inside a real parameter like `include=` without stripping the real parameter.

### Choose the default deliberately

| Real clients... | Use |
|---|---|
| never send the field | no default: any presence alerts |
| always send one constant value (a hidden input, an echoed constant) | `default=<that value>` |
| echo back a per-user value they were given (their own org ID, their current permissions) | a callable default that computes that value from the request, so only tampering alerts |

Callable defaults receive the framework request and must be cheap and synchronous. They may run before route-level middleware, so derive the value from the request itself (trappsec-api.md §4). Arrays are compared element by element, in order. Value matching is canonical: the form string `"false"` equals `false`, but `"False"` does not.

**Stale but legitimate values.** A tab opened before a demotion still echoes the old role, and a tab from another account echoes that account's IDs. If the framework exposes the parsed body on the request (Express `req.body`), the callable default can act as a rule:
- return the submitted value when it is plausible for this caller, so nothing alerts;
- return the expected value otherwise.

Only impossible values then alert, such as a role nobody can hold through this endpoint, or a tenant the caller doesn't belong to. Write down any blind spot this creates.

Don't change the client to avoid staleness, for example by re-fetching before each save. Reviewers spot real code that bends around a tripwire.

### Values the real form never offers

A field the real handler reads can't be a honey field, because trappsec strips it. A value the real UI never sends can still be a tripwire: a shipping option, payout schedule, role or status the form doesn't offer. Where the handler already rejects or falls back on unknown values, call `ts.trigger(request, reason, intent, metadata)` in that branch (trappsec-api.md §6), and keep the existing behavior. The lure is the real form, so nothing new ships to the client.

Only values that no version of the real form ever offered qualify. A tab opened before an option was retired still submits it.

### Bait it

A honey field nobody sees rarely gets tried. Return the field in a real GET response for the same resource, either constant for everyone or the caller's own value. Add it to the frontend type, and optionally display it read-only. Requirements:

- **Nothing real.** The field exposes nothing real or sensitive.
- **Unused today.** The real write handler doesn't read it (stripping would break it). Validators that reject unknown fields are fine: trappsec strips the field before they run.
- **Consumers survive it.** Adding the field doesn't break strict consumers: contract tests, response validation, strict mobile decoders.

## 3. Responses that blend in

**Capture, don't guess.** Call real endpoints and record the status, body, content type and headers for each case: no credentials, valid credentials without permission, unknown resource, wrong method, invalid body. Copy those shapes, with bodies as strings so the bytes match.

**Anonymous.** Set `default_responses["unauthenticated"]` to the app's real anonymous response, byte for byte. Override it per trap only where a real sibling behaves differently.

**Signed in.** Choose what a real endpoint like this would do for a normal user:

| Response | When | Why it works |
|---|---|---|
| The app's real 403 shape | Privileged actions, support tooling, billing internals. **The default choice.** | Real apps check permissions before validating input or touching the database, so a constant, fast 403 fits any payload and any timing. It also invites an escalation attempt, which a honey field can catch. |
| The app's real validation error | Create or action endpoints where a real one would complain about input | Looks alive; invites a fuller attempt |
| A plausible success with synthetic data | Low-stakes reads where a denial would be odd | Keeps the attacker engaged. Use sparingly. |
| The app's real 404 shape | Resource-by-ID decoys, where the real API hides existence with 404 | Matches the app's own existence-hiding behavior |
| The app's retired-version response | Version decoys, if the app really announces retirement that way | Matches history, but ends exploration. Prefer a 403 or success if you want engagement. |

**Status per caller.** A static trap's status depends only on whether the caller is authenticated. Real siblings differ: 404 for an unknown or foreign parent ID, 201 for the owner of their own project (the most privileged role a self-signup attacker holds), 422 or 400 for a malformed body. With `respond_with` (releases after 0.2.0) a trap can mirror those checks from data already on the request (path parameters, session or token claims), so compare a trap with its sibling as each role you can sign up as. On 0.2.0, or where the check needs data the request doesn't carry, pick cover stories in which every role is plausibly denied: a flag that is off, a plan that doesn't include the feature, a function that moved to a hosted portal.

**Synthetic data must look like the app's real data:**
- same ID format;
- realistic values;
- timestamps in the app's format;
- consistent across repeated calls. Derive values deterministically from the request (a hash of path parameters and user ID) rather than randomly per call. An object that changes every time it is fetched is a tell.

Never include real data. Convincing fake data can trigger bug bounty reports, so agree on triage first.

**Content type and headers.**
- Set `mime_type` to what real endpoints send (e.g. `application/problem+json`).
- Headers added by global middleware (CORS, security headers, request IDs) apply to traps automatically.
- Headers a framework or handler adds per route don't, so set them with `headers` (releases after 0.2.0): FastAPI's `HTTPBearer` / `OAuth2PasswordBearer` send `WWW-Authenticate: Bearer` on every 401; Django REST framework sends `Allow`, `Vary: Accept` and `WWW-Authenticate` on every APIView response. Values that change per request (ETag, rate-limit counters) can come from `respond_with`. On 0.2.0, a middleware gated on `is_trap(request)` can add them.
- Run the parity script, and list the remaining differences as residual risks.
- For the same reason, a trap cannot mimic an endpoint that redirects anonymous requests. Put decoys among JSON endpoints that answer 401.

**Timing.** Keep dynamic bodies fast, and never sleep in them: sleeping blocks workers. Denials are fast in real apps too, which is another reason the 403 makes a good default.

## 4. Breadcrumb chains

A chain is two or more tripwires where one leads to the next. The first touch could be curiosity. Reaching the second is unambiguous, and both alerts carry the same identity.

Patterns:
- **Denial → escalation.** A decoy's 403 names the permission or role it requires, in the app's real error format. The current-user response shows where permissions or roles live. Sending that value to the profile or settings endpoint trips a honey field.
- **Flag → feature → field.** A client-side flag reveals a gated entry point. Its decoy call answers with a validation error naming a field, and that field is a honey field on a real endpoint.
- **Old version → new version.** A retired-version decoy's response points toward a newer path, which is itself a decoy.

Each step must be plausible on its own and consistent with the others. The permission named in a 403 must look like the app's real permission strings.

## 5. Intent labels

Give every trap and honey field an intent, so alerts can be routed and prioritized. Use one consistent vocabulary, for example: `reconnaissance`, `privilege_escalation`, `account_takeover`, `cross_tenant_access`, `data_exfiltration`, `entitlement_abuse`, `payment_fraud`, `mass_assignment`. If the team already has a security vocabulary, reuse it.

## 6. Directions by domain

These are directions, not names. Translate them into the app's vocabulary and conventions.

- **B2B SaaS:** workspace transfer, member-role changes, SSO/SCIM configuration, audit-log export, API-key scopes, seat counts. Honey fields: role or permissions, organization IDs.
- **E-commerce and marketplaces:** price or discount on cart and checkout creation, seller payout settings, order status, refunds. Honey fields: unit price, discount, payout account.
- **Fintech:** limits, verification status, fee overrides, statement exports. Honey fields: limits and verification state.
- **Healthcare and other regulated data:** record exports, delegate or caregiver access, consent state.
- **Developer platforms:** token scopes, usage quotas, organization billing, deployment environments.
- **Consumer apps:** premium entitlement, profile visibility, referral credits.

## 7. Infrastructure and integration gotchas

- **Paths.** Trap and watch paths are full public paths, including any mount prefix or sub-router base. Watches must use the exact route pattern the framework registered: FastAPI `{order_id}` with the same parameter name, Flask `<int:id>`, Express `:id`, Django `<str:pk>`.
- **Edge routing.** An API gateway, ingress or serverless config with an explicit route allowlist answers decoy paths itself (usually with a 404), and the trap never fires. Check the infrastructure config, and add routes there with the user's approval.
- **Caching.** A CDN that caches GET responses can serve a decoy without the request ever reaching the app. Make sure decoy responses aren't cacheable at the edge, just as real authenticated API responses shouldn't be.
- **Per-route authentication.** Guards, dependencies and route middleware don't run on trap routes. Identify users inside `identify_user` (see trappsec-api.md).
- **Global auth middleware that rejects anonymous requests before routing** answers for traps too. That matches real routes; it just means you get no `signal` events.
- **CSRF.** Some CSRF middleware needs an `is_trap` exemption (trappsec-api.md). Otherwise POST decoys answer with CSRF errors.
- **Workers.** Create the Sentry inside each worker (after fork), and call `close()` on shutdown.

## 8. Public repositories

If the server code is public, anyone can read the trap definitions and work out which frontend code is a lure. You can still catch opportunistic attackers who probe the deployed app without reading the repository.

To keep definitions out of the public tree:
- Load trap and watch definitions at startup from configuration the repo doesn't contain: an environment variable or secret-store entry holding JSON that the server turns into `ts.trap(...)` and `ts.watch(...)` calls.
- Keep frontend lures generic.
- Tell the user plainly what remains visible.
