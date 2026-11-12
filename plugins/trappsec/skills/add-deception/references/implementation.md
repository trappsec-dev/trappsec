# Implementation rules

What each piece must do. How to do it in a given stack is up to you: follow the app's own idioms.

Contents
1. Decoy routes
2. The final denial
3. Inferred decoys
4. Honey fields
5. Recording and attribution
6. Keeping decoys recognizable to the team
7. Public repositories

## 1. Decoy routes

A decoy route is its sibling's route with two changes: it records the hit right after authentication, and it ends in a denial where the real work would be.

```
sibling: authenticate → load resource → check permission → validate input → do the work
decoy:   authenticate → RECORD → load resource → check permission → validate input → FINAL DENIAL
```

- **Same chain, same order.** Reuse the sibling's own authentication, loaders, permission checks and validation, in the order the framework actually runs them for the sibling, including anything it does before authentication. Every probe the sibling rejects is then rejected by the same code, with the same status, body, headers and timing.
- **Record before anything that can reject an authenticated caller**, so attempts the permission check turns away are recorded too. Where authentication is one bundle that also rejects authenticated callers (a token-permission check inside it), mark the request before the bundle and record once identity is known, in the response hook.
- **Declared beside the sibling**, in the same router, file and style, with the smallest diff. Don't reformat surrounding code.
- **Everything the framework publishes about a route** (route listings, generated specs, OPTIONS metadata, API browsers, handler names and docstrings) looks like the sibling's and fits the cover story.

## 2. The final denial

The caller who reaches the end has passed every real check, so the denial must make sense for them:

- **It fits everyone who can get there**, including the owner of their own workspace. "You need the owner role" sent to an owner is a contradiction.
- **It comes from the app's own error mechanism**, with a status and error code the app already returns elsewhere.
- **The story fits every role:** a feature not enabled for this account, a function handled elsewhere (an admin console, support), a capability limited to accounts the attacker can't create. A plan gate only works if no self-serve trial of that plan exists.
- **It is never a success.** A created object invites follow-ups (fetching it, listing it, polling it) the rest of the API won't corroborate.
- **Nothing runs after it.** The decoy writes, sends, enqueues and calls out nothing, reads nothing beyond its sibling's loaders, and returns nothing the sibling wouldn't.

## 3. Inferred decoys

An inferred decoy is a method or sub-resource the app doesn't have, at a strong inference from a route the attacker has already used (backend-traps.md §1). The API's naming conventions alone don't make one.

- **On an existing path, it is a new method of the existing route**, registered so the framework lists it in `Allow` and OPTIONS like any real method. Never register a second route for a path a real route serves: in routers that don't dispatch by method, it takes over the real route for every method.
- **Its sibling is the existing route on that path:** reuse that route's loaders, so an unknown item gets the same 404, then the permission check the action would have, then the final denial.
- **Pick capabilities no customer has.** A denied DELETE on something owners can delete elsewhere invites the question why.

## 4. Honey fields

A honey field is a parameter real clients never send, or always send with one known value, on a real endpoint that never honors it. Which values record is a design choice (backend-traps.md §2).

- **Checked after authentication, before the input is validated or used.**
- **Compare canonically.** Form and query values are strings, JSON values are typed: `"true"` and `true` match, `"5"` and `5` match, arrays compare element by element, and a repeated parameter is tampering unless every value matches.
- **The endpoint behaves exactly as before for every request.** Leave the request as it is: the handler already drops the field, and removing it yourself makes a honey field answer differently from other unknown fields (a deeply nested or huge value is the usual tell). The tripwire's test asserts the field is still dropped, so a change that starts honoring it fails. A field the handler reads is not a honey field, and an endpoint that rejects unknown fields has no honey fields: a field it refuses is add-detection's (attack-paths.md).
- **Bounded work.** Look only at the named top-level field. Never walk arrays or nested objects to decide, never run fuzzy matching over attacker input, and handle values of any type without failing. Recording a value clips it within a fixed budget of nodes and depth (references/telemetry.md, Values). Parsing the body is the app's own cost; the check adds a bounded amount to it and never becomes a 500.

## 5. Recording and attribution

Every hit is recorded through the request-context module and the findings in references/telemetry.md, which also hold the rules for emitting, recorded values and `client.address`. The result must let a responder find the account, revoke the credential and follow the request's trace.

**Anonymous requests** are answered by the sibling's authentication before anything records. If the user wants them as low-severity signals, record them from the app's unauthenticated path for decoy routes only, without changing the response. Requests the framework rejects before authentication aren't recorded, the same as for the sibling.

## 6. Keeping decoys recognizable to the team

Decoys look exactly like real code, which is what gets them deleted, wired into the real UI or "finished" by a teammate or a coding agent, and then the alert channel floods.

- **A marker on every decoy and check** in server code, naming its cover story and its inventory ID.
- **One inventory** in server code: every decoy, check and lure with its ID, file, cover story and intent. The tripwire IDs in findings come from it. It appears in the report and never in anything shipped to browsers.
- **A test per tripwire**, with recording on through the app's test setup or the recording module's own seam (with no endpoint set nothing records), that fires it as a normal user and as an owner, and asserts the response, the recorded finding and that no data changed, plus a test that every inventory entry has one. Follow the project's test conventions.
- **In a private repository**, a short note in the repo's agent instructions (AGENTS.md, CLAUDE.md) naming the decoys and lure symbols and asking agents not to remove, call or complete them, and suggested CODEOWNERS entries so the security team reviews changes to those files.
- **Commit messages and PR descriptions** describe the change accurately for reviewers.
- **In a public repository**, decoy code and notes are visible to attackers too: follow §7 and tell the user what remains visible.

## 7. Public repositories

Decoys in public source can be read by anyone, who can then work out which frontend code is a lure. To keep them out of the public tree, put the decoy routes and checks in a module that isn't in the public repository and register it at startup the way the app loads other optional modules; where the app has no such mechanism, keep them in the tree. Keep frontend lures generic, and tell the user plainly what remains visible.

For an app many people run from public source, an attacker compares against the upstream release, not only this codebase: a decoy route that answers where upstream answers 404 tells anyone who knows upstream. Weigh each decoy route against upstream behavior, and prefer honey fields upstream already ignores, which carry no such tell.
