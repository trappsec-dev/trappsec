# Implementation rules

What each piece must do. How to do it in a given stack is up to you: follow the app's own idioms.

Contents
1. Decoy routes
2. The final denial
3. Inferred decoys
4. Honey fields and value rules
5. Recording hits
6. Attribution
7. Keeping decoys recognizable to the team
8. Public repositories
9. Safety checklist

## 1. Decoy routes

A decoy route is its sibling's route with two changes: it records the hit right after authentication, and it ends in a denial where the real work would be.

```
sibling: authenticate → load resource → check permission → validate input → do the work
decoy:   authenticate → RECORD → load resource → check permission → validate input → FINAL DENIAL
```

- **Same chain, same order.** Reuse the sibling's own authentication, loaders, permission checks and validation, in the order the framework actually runs them for the sibling, including anything it does before authentication. Every probe the sibling rejects is then rejected by the same code, with the same status, body, headers and timing.
- **Record before anything that can reject an authenticated caller**, so attempts the permission check turns away are recorded too.
- **Declared beside the sibling**, in the same router, file and style, with the smallest diff. Don't reformat surrounding code.
- **Everything the framework publishes about a route** (route listings, generated specs, OPTIONS metadata, API browsers, handler names and docstrings) looks like the sibling's and fits the cover story.

## 2. The final denial

The caller who reaches the end has passed every real check, so the denial must make sense for them:

- **It fits everyone who can get there**, including the owner of their own workspace. "You need the owner role" sent to an owner is a contradiction.
- **It comes from the app's own error mechanism**, with a status and error code the app already returns elsewhere.
- **The story fits every role:** a feature not enabled for this account, a function handled elsewhere (an admin console, support), a capability limited to accounts the attacker can't create. A plan gate only works if no self-serve trial of that plan exists.
- **It is never a success.** A created object invites follow-ups (fetching it, listing it, polling it) the rest of the API won't corroborate.
- **Nothing runs after it.**

## 3. Inferred decoys

An inferred decoy is a method or sub-resource the API's conventions imply but the app doesn't have.

- **On an existing path, it is a new method of the existing route**, registered so the framework lists it in `Allow` and OPTIONS like any real method. Never register a second route for a path a real route serves: in routers that don't dispatch by method, it takes over the real route for every method.
- **Its sibling is the existing route on that path:** reuse that route's loaders, so an unknown item gets the same 404, then the permission check the action would have, then the final denial.
- **Pick capabilities no customer has.** A denied DELETE on something owners can delete elsewhere invites the question why.

## 4. Honey fields and value rules

A honey field is a parameter real clients never send, or always send with one known value, on a real endpoint that never honors it. A value rule records a value the real UI never offers, in a field the handler really reads.

- **Checked after authentication, before the input is validated or used.**
- **Expected values come from the authenticated caller**, never from other fields in the same request; otherwise an attacker adds a field and the check goes quiet.
  - Never sent by real clients: any presence records.
  - A constant the real UI always sends: record when it differs.
  - A per-user value the UI echoes back: record only values impossible for this caller. Values that are stale but legitimate (a tab opened before a demotion) don't record.
- **Compare canonically.** Form and query values are strings, JSON values are typed: `"true"` and `true` match, `"5"` and `5` match, arrays compare element by element, and a repeated parameter is tampering unless every value matches.
- **The endpoint behaves exactly as before for every request.** If it ignores unknown fields, the honey field is discarded after recording, so no later change can start honoring it. If it rejects unknown fields, the honey field is rejected exactly like any other. For value rules, the existing rejection or fallback is unchanged.
- **Constant work.** Look only at the named top-level field. Never walk arrays or nested objects, never run fuzzy matching over attacker input, and handle values of any type without failing: a crafted body costs the same as a normal one and never becomes a 500.
- **Only values no version of the real UI ever offered** qualify for value rules.

## 5. Recording hits

One small server-side module records every hit, in the app's style and named like its other observability code. It emits the event in references/alert-schema.md.

- **Never fails the request.** Any error while recording is swallowed, and the response is unchanged.
- **Never blocks.** No network call on the request path; delivery to other systems goes through the app's existing telemetry or background work.
- **Constant, small cost**, whatever the request contains.
- **Sanitized** as the schema requires: attacker-controlled values end up in dashboards and tickets.

## 6. Attribution

An alert must let a responder find the account, revoke the credential and find the same request in other logs.

- **Who comes from the app's authenticated state**, never from anything the caller sent: the user, their roles, their tenant, the session, token or key that authenticated them, and the real person behind the request when someone is acting as another user. Never record a secret.
- **The client IP is the one the app resolves through its trusted-proxy configuration.** Never parse forwarding headers yourself, and never trust a value the caller could have written. If the app isn't configured for the proxies in front of it, alerts will carry a proxy's address: report that, and the setting that would fix it, instead of changing proxy or infrastructure configuration yourself.
- **Correlation:** the event carries the request's trace context, and the app's own request ID if it has one.
- **Anonymous requests** are answered by the sibling's authentication before anything records. If the user wants them as low-severity signals, record them from the app's unauthenticated path for decoy routes only, without changing the response. Requests the framework rejects before authentication aren't recorded, the same as for the sibling.

## 7. Keeping decoys recognizable to the team

Decoys look exactly like real code, which is what gets them deleted or "finished" by a teammate or a coding agent.

- **A marker on every decoy and check** in server code, naming its cover story and its inventory ID.
- **One inventory** in server code or a server-side document: every decoy, check and lure with its ID, file, cover story and intent. The tripwire IDs in events come from it.
- **A test per tripwire** that fires it as a normal user and as an owner, and asserts the response, the recorded event and that no data changed, plus a test that every inventory entry has one.
- **Agent instructions and CODEOWNERS** in a private repository (SKILL.md, "Keep the team in on it").

## 8. Public repositories

Decoys in public source can be read by anyone, who can then work out which frontend code is a lure. To keep them out of the public tree, put the decoy routes and checks in a module that isn't in the public repository and register it at startup the way the app loads other optional modules. Keep frontend lures generic, and tell the user plainly what remains visible.

## 9. Safety checklist

Before calling a tripwire done:
- a decoy's last step is the final denial;
- it writes, sends, enqueues and calls out nothing, reads nothing beyond its sibling's loaders, and returns nothing the sibling wouldn't;
- every check leaves the endpoint's behavior exactly as it was for real clients;
- recording can fail without changing any response, and an oversized or deeply nested body changes neither responses nor response times;
- the app's existing tests pass, and every tripwire has a test.
