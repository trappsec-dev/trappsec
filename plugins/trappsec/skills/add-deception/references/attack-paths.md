# Attack paths

How add-deception maps the routes an attacker takes through the app, and which chokepoints it covers. The core below is shared word for word with add-detection, so the two skills plan from one map and divide it without gaps or overlap.

<!-- BEGIN ATTACK PATHS CORE: identical in add-deception and add-detection -->
## One map, two skills

add-detection and add-deception catch the same attacker at the same places by different means. Detection makes a refusal the app already makes report on itself. Deception plants something the app ignores: a field no handler reads, a route nothing serves. Both plan from one map of the attacker's routes, and one test decides which skill covers each point on it.

## Map the attack paths

Start from who would attack this app and what they want: privilege, money, other users' or other tenants' data, workflow integrity. For each intent, walk the route from the account an attacker can get (a self-serve signup, one employee's login, a stolen session or token) to the outcome they want, through the stages most attacks share:

- **Orient:** read the client and the API's conventions, enumerate resources, try the routes they imply, list what the account can see.
- **Escalate:** gain a role, permission, plan or entitlement the account doesn't have.
- **Reach:** read or export what isn't theirs: other users' records, other tenants, sensitive fields, bulk exports.
- **Act or persist:** move money, change who gets paid, approve their own work, create accounts or keys that outlast the session.

At each stage, list the **chokepoints**: every endpoint, parameter and response field the attacker must touch or would try there, taken from this codebase, on every surface a client uses (web pages and forms, the API, mobile and partner clients).

## Which skill covers an input

A chokepoint usually holds several inputs an attacker could try: a field, a value, an ID, a method, a path. For each one, ask what the app does with it **today**, reading the form, serializer and handler rather than going by the field's name:

| What the app does today | What it is | Covered by |
|---|---|---|
| Refuses it, and no real client can produce it | A detection | add-detection: a rule in the branch that refuses |
| Ignores it: no handler reads the field, or no route serves the path | A tripwire | add-deception: a honey field or a decoy route |
| Accepts it and acts on it, though no real client sends it | A vulnerability | Neither: report it, and don't instrument it |
| Refuses it, but a real client can reach that refusal | Nothing certain | Neither: an uncovered input, with the reason |

Mass assignment shows the split. A field the endpoint refuses is a detection, a field it silently drops is a honey field, and a field it saves is a vulnerability.

## Hand off what belongs to the other skill

Each skill reports every chokepoint on the map with one outcome per input:

- **covered**, with the rule or tripwire ID;
- **handed off** to the other skill, naming the input and what the app does with it today;
- **uncovered**, with a reason about effectiveness (a real client could produce it, or every candidate would give itself or another away);
- **vulnerability**, reported for the user to fix.

Before mapping, read the other skill's server-side inventory if one exists: an input it already covers needs nothing from you, and an input it handed off is yours to cover or to report as uncovered. A handed-off input stays in each report until a report shows it covered. When both skills are applied to one app, run add-detection first: it changes no behavior, and its map and hand-offs become add-deception's starting point.
<!-- END ATTACK PATHS CORE -->
