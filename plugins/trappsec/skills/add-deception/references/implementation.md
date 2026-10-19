# Implementation

How to build decoys in the app's own code. Names below only illustrate patterns; never copy them into an app.

Contents
1. Anatomy of a decoy route
2. The final denial
3. Inferred decoys
4. Honey fields
5. Values the real form never offers
6. The tripwire helper
7. Identity and anonymous hits
8. Keeping decoys recognizable to the team
9. Public repositories
10. Framework notes
11. Safety checklist

## 1. Anatomy of a decoy route

A decoy route is its sibling's route with two changes: a tripwire step after authentication, and a final denial where the real work would be.

```
sibling: authenticate → load resource → check permission → validate body → do the work
decoy:   authenticate → TRIPWIRE → load resource → check permission → validate body → FINAL DENIAL
```

- **Copy the chain, in order.** Use the sibling's own middleware, dependencies, decorators, guards, permission classes and validators, in the order the sibling uses them. Every probe that the sibling rejects (no token, expired token, unknown or foreign ID, missing role, bad body) is then rejected by the same code, with the same status, body, headers and timing.
- **Record right after authentication**, before anything that can reject the caller, so every authenticated attempt is recorded, including the ones the permission check turns away.
- **Declare it where the sibling is declared**, in the same router, file and style, with the smallest edit. Don't reformat the surrounding routes: a large diff in real route files is harder to review and easier to undo by accident.
- **Treat the spec the same way as its siblings.** If the sibling appears in a generated spec or route listing, the decoy appears there too, unless that would invite legitimate API consumers to call it. In that case it belongs only where the app already keeps undocumented routes; a lone undocumented route beside documented siblings is the first thing a tester diffs.
- **Validate the body like the sibling does**, with a schema of the same kind, so malformed and incomplete bodies fail the same way and in the same order.

Express:

```js
// routes/projects.js (existing router; the decoy sits beside its sibling)
router.post('/:projectId/invitations', requireAuth, loadProject, requireRole('owner'), validate(invitationSchema), createInvitation);
// Security tripwire: <cover story>. See <inventory location>.
router.post('/:projectId/<decoy>', requireAuth, recordProbe('privilege_escalation'), loadProject, requireRole('owner'), validate(<decoySchema>),
  (req, res, next) => next(new HttpError(403, 'forbidden', '<final denial>')));
```

FastAPI (route-level `dependencies` run before the endpoint's own dependencies, after their own sub-dependencies such as authentication; make the probe `async def` so it doesn't add a threadpool hop):

```python
async def <decoy>_probe(request: Request, user: CurrentUser) -> None:
    security_events.record("trap_hit", request, user=<user id>, role=<role>, intent="privilege_escalation")

# Security tripwire: <cover story>. See <inventory location>.
@projects.post("/{project_id}/<decoy>", status_code=201, dependencies=[Depends(<decoy>_probe)])
def create_<decoy>(body: <DecoyCreate>, project: Annotated[dict, Depends(require_project_role("owner", "admin"))]):
    raise HTTPException(status_code=403, detail="<final denial>")
```

Django REST framework: DRF checks permissions in order before the action runs, so put a permission class that records and returns `True` first. Recording on the first line of the action also works, but only after global permissions and throttling have passed. DRF publishes an action's name and docstring through OPTIONS and the browsable API, so write the docstring as part of the cover story:

```python
class RecordProbe(BasePermission):  # name it in the app's style
    def has_permission(self, request, view):
        user = request.user if request.user.is_authenticated else None
        security_events.record("trap_hit", request, user=user and user.pk, role=<role>, intent=view.probe_intent)
        return True

# on the existing viewset, beside the sibling action
@action(detail=True, methods=["post"], permission_classes=[RecordProbe, *<the sibling's permission classes>])
def <decoy>(self, request, pk=None):
    project = self.get_object()          # the sibling's loader and object permissions
    serializer = <DecoySerializer>(data=request.data); serializer.is_valid(raise_exception=True)
    raise PermissionDenied("<final denial>")
```

Go (chi):

```go
r.With(requireAuth, recordProbe("privilege_escalation"), loadProject, requireRole("owner")).
	Post("/projects/{projectID}/<decoy>", deny<Decoy>)
```

## 2. The final denial

The caller who reaches the end of a decoy has passed every real check, so the denial must make sense for them:

- **For everyone who can get there**, including the owner of their own workspace. "You need the owner role" sent to an owner is a contradiction a tester will notice.
- **Through the app's own error mechanism**, with a status and an error code the app already returns elsewhere. Don't invent a new error code that appears nowhere else in the API.
- **A story that fits every role:** a feature not enabled for this account, a function handled by another surface (an admin console, support), a capability limited to accounts the attacker can't create. A plan gate only works if no self-serve trial of that plan exists.
- **Never a success.** A 201 with an ID invites `GET` on that ID, the list endpoint, a polling URL. The rest of the API won't corroborate them.
- **Nothing after it.** The denial is the last step; no code path continues past it.

## 3. Inferred decoys

An inferred decoy is a method or sub-resource the API's conventions imply but the app doesn't have (DELETE on items it lists, the previous version of a route). It is a real handler:

- **Same path, new method:** add the handler in the same router or view as the existing methods. The framework then lists it in `Allow` and answers OPTIONS for it like any real method. In method-agnostic routers (Django URL patterns), add a method to the existing view or viewset; never add a second pattern for the same URL.
- **Same chain:** the sibling of an inferred method is the existing route on that path. For a DELETE beside a GET, use the GET's loaders (so an unknown item gets the same 404), then the permission check a destructive action would have, then the final denial.
- **Pick capabilities no customer has.** An inferred DELETE on something owners can legitimately delete elsewhere invites the question why it's denied here. Prefer actions that are plausibly reserved for staff or for another surface.

## 4. Honey fields

A honey field is a parameter that real clients never send, or always send with one known value, on a real endpoint that would never honor it. It is a check at the top of the real endpoint.

- **Where:** after authentication, before validation or any use of the body. Use the endpoint's own access to the parsed body: `req.body`, `request.data`, a dependency that reads `await request.json()`, a pre-handler hook.
- **Detect:**
  - no expected value: any presence records;
  - a constant the real UI always sends: record when the value differs;
  - a per-user value the UI echoes back (their own role, their own org ID): compute the expected value from the authenticated caller and record only on a mismatch. For stale but legitimate values (a tab opened before a demotion), accept values that are plausible for this caller and record only impossible ones.
- **Compare canonically.** Form and query values are strings, JSON values are typed. Compare `"true"` with `true` and `"5"` with `5` as equal, compare arrays element by element, and treat a repeated query or form parameter as tampering unless every value matches. See `values_match` in §6.
- **Make sure it can never reach the logic, without changing what the endpoint does with it today.** If the endpoint currently ignores unknown fields (most do), remove the field after recording it, so a later change to the serializer can't start honoring it. If the endpoint rejects unknown fields, record it and let the validator reject it exactly as it rejects any other unknown field. A honey field that is silently accepted while every other unknown field is rejected is a tell.
- **Keep the work constant.** Look at the field on the top-level object only. Don't walk arrays or nested objects, don't run fuzzy matching (edit distance and the like) over attacker-supplied lists, and don't call `String()` or `str()` on values of unknown type without a guard: a crafted body must cost the same as a normal one and must never turn into a 500. In a safety review, a check that recursed into every array element let one anonymous 1.9 MB request write 8.7 MB of logs.
- **Nothing else in the body switches the check off.** Compute the expected value from the authenticated caller, never from other fields the caller sent (an `id` in the body, for example); otherwise an attacker adds a field and the tripwire goes quiet.
- **Bait it** with a field in a real response (backend-traps.md §2), and add it to the client types like the real optional fields.

Express:

```js
const watchField = (field, expected, intent) => (req, res, next) => {
  try {
    if (req.body && Object.hasOwn(req.body, field)) {
      const value = req.body[field];
      let want; try { want = expected(req); } catch { want = undefined; }
      if (want === undefined || !valuesMatch(value, want)) {
        securityEvents.record('watch_hit', req, { found_fields: [{ type: 'body', field, value, intent }] });
      }
      delete req.body[field];          // only if the endpoint ignores unknown fields today
    }
  } catch { /* never break the request */ }
  next();
};
```

## 5. Values the real form never offers

A field the real handler reads can't be a honey field. A value the real UI never sends can still be a tripwire: a shipping option, payout schedule, role or status the form doesn't offer. In the branch where the handler already rejects or falls back on unknown values, record the hit and keep the existing behavior. Only values that no version of the real form ever offered qualify.

## 6. The tripwire helper

One small module, written in the app's style and named like its other observability code. It records one structured event per hit. If the app already exports OpenTelemetry, emit the event through it (a log record, or an event on the current span, with the keys below as attributes) so it lands wherever the app's telemetry goes. Otherwise write it through the app's own logger.

Event schema (keep these keys so alert rules work across services):

| Key | Value |
|---|---|
| `timestamp` | seconds since the epoch |
| `event` | `trap_hit` (decoy route), `watch_hit` (honey field) or `rule_hit` (value the form never offers) |
| `type` | `alert` when a user is identified, else `signal` |
| `path`, `method`, `ip`, `user_agent` | from the request, truncated to 1024 characters |
| `user`, `role` | the authenticated caller, or null |
| `intent` | for `trap_hit` and `rule_hit` |
| `found_fields` | for `watch_hit`: `[{type: "body"|"query", field, value, intent}]` |
| `app` | `{service, environment, hostname}` |

Rules:
- **Never raise.** Wrap the whole body in try/except. A failure to record must not change the response.
- **Never block.** Write a log line. If alerts must go to a webhook, hand the event to the app's existing background worker or an in-process queue, never an HTTP call on the request path.
- **Sanitize.** Truncate strings, limit lists, serialize objects compactly. Attacker-controlled values end up in dashboards and tickets.
- **Use the client IP the app already trusts** (its proxy configuration), never a raw forwarding header.

Python:

```python
import json, logging, os, socket, time

_log = logging.getLogger("<app>.security")
_APP = {"service": "<service>", "environment": os.environ.get("<APP_ENV>", "production"), "hostname": socket.gethostname()}

def _clip(v, n=1024):
    if v is None or isinstance(v, (bool, int, float)):
        return v
    if isinstance(v, str):
        return v if len(v) <= n else v[:n] + "..."
    if isinstance(v, (list, tuple)):
        return [_clip(x) for x in list(v)[:20]]
    if isinstance(v, dict):
        return _clip(json.dumps(v, sort_keys=True, separators=(",", ":"), default=str))
    return "<%s>" % type(v).__name__

def _canon(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return str(int(v)) if v.is_integer() else repr(v)
    return v

def values_match(actual, expected):
    if isinstance(expected, list):
        return isinstance(actual, list) and len(actual) == len(expected) and all(map(values_match, actual, expected))
    if isinstance(actual, list):  # repeated query/form parameter
        return bool(actual) and all(values_match(a, expected) for a in actual)
    if isinstance(actual, dict) or isinstance(expected, dict):
        return actual == expected
    return _canon(actual) == _canon(expected)

def record(event, request, *, user=None, role=None, **fields):
    try:
        payload = {
            "timestamp": time.time(), "event": event, "type": "alert" if user else "signal",
            "path": _clip(<path from request>), "method": <method>, "ip": <client ip the app trusts>,
            "user_agent": _clip(<user agent>), "user": user, "role": role,
            **{k: _clip(v) if k != "found_fields" else [{**f, "value": _clip(f.get("value"))} for f in v] for k, v in fields.items()},
            "app": _APP,
        }
        _log.warning(json.dumps(payload, default=str))
    except Exception:
        pass
```

JavaScript:

```js
const os = require('node:os');
const APP = { service: '<service>', environment: process.env.<APP_ENV> || 'production', hostname: os.hostname() };

function clip(v, n = 1024) {
  if (v === null || v === undefined || ['boolean', 'number'].includes(typeof v)) return v ?? null;
  if (typeof v === 'string') return v.length <= n ? v : v.slice(0, n) + '...';
  if (Array.isArray(v)) return v.slice(0, 20).map((x) => clip(x, n));
  if (typeof v === 'object') return clip(JSON.stringify(v), n);
  return `<${typeof v}>`;
}
const canon = (v) => (typeof v === 'boolean' || typeof v === 'number' ? String(v) : v);
function valuesMatch(actual, expected) {
  if (Array.isArray(expected)) return Array.isArray(actual) && actual.length === expected.length && actual.every((a, i) => valuesMatch(a, expected[i]));
  if (Array.isArray(actual)) return actual.length > 0 && actual.every((a) => valuesMatch(a, expected));
  if ((actual && typeof actual === 'object') || (expected && typeof expected === 'object')) return JSON.stringify(actual) === JSON.stringify(expected);
  return canon(actual) === canon(expected);
}

function record(event, req, { user = null, role = null, ...fields } = {}) {
  try {
    const line = {
      timestamp: Date.now() / 1000, event, type: user ? 'alert' : 'signal',
      path: clip(<path from req>), method: req.method, ip: <client ip the app trusts>,
      user_agent: clip(<user agent>), user, role, ...fields, app: APP,
    };
    if (line.found_fields) line.found_fields = line.found_fields.map((f) => ({ ...f, value: clip(f.value) }));
    <app logger>.warn(JSON.stringify(line));
  } catch { /* never let recording break a request */ }
}
```

Go: the same shape as a function taking `*http.Request`, with `defer func() { _ = recover() }()` at the top and the app's `slog` or logger.

## 7. Identity and anonymous hits

The tripwire runs after the app's own authentication, so it has the real caller: pass the user ID and the role that matters for this route (an account role, or the caller's role in the workspace in the path when roles are per workspace).

Anonymous requests are rejected by the sibling's authentication before the tripwire runs, with the app's real 401. They are mostly scanners. If you want them as `signal`s, record from the app's 401 path for decoy routes only, without changing the response. Requests the framework rejects before authentication (FastAPI's 422 for malformed JSON, DRF's 406 for an unsupported `Accept`) are never recorded; that matches the sibling and is fine.

## 8. Keeping decoys recognizable to the team

Decoys look exactly like real code. That is what makes them convincing, and also what gets them deleted or "finished" by a teammate or a coding agent. Counter it with:

- **A marker on every decoy**, in server code: one comment line naming the cover story and pointing to the inventory, or a no-op decorator if the team uses decorators for such things.
- **One inventory**: a server-side document or module listing every decoy, honey-field check and lure with its file, its cover story and its intent.
- **A test per tripwire** that fires it as a normal user and as an owner, and asserts the response, the recorded event and that no data changed. If someone removes or completes a decoy, the test fails and says why. A further test that every inventory entry has a firing test keeps the two in step; when the inventory is code, the app can also refuse to start if a marker names an entry the inventory doesn't have.
- **Agent instructions and CODEOWNERS** in a private repository (SKILL.md, "Keep the team in on it").

## 9. Public repositories

Decoys in a public repository can be read by anyone, who can then work out which frontend code is a lure. You can still catch attackers who probe the deployed app without reading the source. To keep decoys out of the public tree:
- put the decoy routes and honey-field checks in a module that is not in the public repository (a private package, or a file supplied at deploy time) and register it at startup the way the app registers optional routers or plugins;
- keep frontend lures generic;
- tell the user plainly what remains visible.

## 10. Framework notes

- **FastAPI:** route-level `dependencies=[...]` run before the endpoint's own dependencies, after their own sub-dependencies; make the probe `async def`. A malformed JSON body is rejected with 422 before any dependency runs, for decoy and sibling alike. Body models ignore unknown fields unless the model forbids extras. In honey-field checks, read path parameters directly rather than depending on the sibling's loader a second time: a duplicated dependency reports a malformed ID twice in the 422 and changes real responses.
- **Flask:** decorators run outermost first, so put the tripwire decorator directly under the authentication decorator. Errors go through the app's `errorhandler`s like the sibling's.
- **Django / DRF:** permission classes run in order before the action; put the recording class first. Add inferred methods to the existing view or viewset; Django URL patterns don't dispatch by method, so a second pattern for the same URL takes over every method.
- **Express / Koa:** route middleware runs in the order given. Use the app's error middleware (`next(err)`) for the denial.
- **Fastify:** schema validation runs before `preHandler` hooks, even for anonymous callers; give the decoy a schema like the sibling's so validation happens at the same point, and put the tripwire first in the route's `preHandler` list. Register the decoy in the same plugin as the sibling so its hooks and error handler apply.
- **NestJS:** guards run before pipes and handlers; record in a guard ordered after the authentication guard, and keep the sibling's guards and pipes.
- **Go (chi, Gin, Echo, net/http):** reuse the sibling's middleware with the router's own `With`, group or handler-chain mechanism; finish with the app's error renderer, and `recover` inside the tripwire. When a group bundles authentication and the loader together (Gin `group.Use(requireAuth, loadProject)`), there's no slot between them: declare the decoy in a second group on the same prefix with only authentication, and name the loader on the route.
- **Rails, Laravel, Spring, ASP.NET:** use `before_action`, middleware or interceptors in the sibling's order; record after authentication and before authorization. In Spring, method security (`@PreAuthorize`) runs before the method body, so record in an interceptor or filter scoped to the decoy's path.
- **Next.js route handlers, serverless functions:** call the same helpers the sibling calls, in the same order.

## 11. Safety checklist

Before calling a decoy done:
- its last step is the final denial; nothing runs after it;
- it writes nothing, sends nothing, enqueues nothing and calls out to nothing;
- it reads nothing beyond what its sibling's loaders read, and returns nothing the sibling wouldn't;
- every honey-field check leaves the endpoint's behavior exactly as it was for real clients;
- the tripwire and every honey-field check catch their own errors and do constant work, and tests prove a failing logger and an oversized or deeply nested body don't change the response;
- the app's existing tests pass, and a test per tripwire fires it and asserts no state change.
