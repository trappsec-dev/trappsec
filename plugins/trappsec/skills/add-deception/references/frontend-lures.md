# Frontend lures

A lure is the breadcrumb that leads an attacker to a decoy route or honey field. In most apps the frontend is where attackers build their map, so it is where most lures belong.

Contents
1. How attackers read a frontend
2. Pick surfaces the app already has
3. Lure patterns (A–H)
4. Surviving the build
5. False-positive hazards
6. Tells
7. Framework notes
8. Apps without a frontend, or a frontend you can't change

## 1. How attackers read a frontend

Signed-in attackers (curious customers, bug bounty hunters, someone using a stolen account, automated tools) usually map an app from its client before touching the API:

- **Bundles and chunks.** They download every JavaScript chunk, found through the HTML, the bundler manifest, or Next.js's `_buildManifest.js`. Then they grep for:
  - path-like strings (`/api/`, `fetch(`, `axios`);
  - role and permission names;
  - words such as admin, internal, export, impersonate, billing, beta, legacy, v1.

  Tools like LinkFinder, JSluice and GAP automate this. Chunk file names (`AccountTools-3f9a.js`) get read too.
- **Source maps.** If `.map` files are deployed, the original source tree comes back: file paths, comments, everything. Check whether the production build emits maps and whether the deploy serves them.
- **Runtime state.** Inline bootstrap JSON (`__NEXT_DATA__`, `window.__INITIAL_STATE__`), feature-flag payloads, local storage, the current-user object.
- **Responses.** Every JSON response in devtools or an intercepting proxy. Extra fields such as role, plan, staff flags or organization IDs are mass-assignment candidates. Attackers echo them back in PUT/PATCH with changed values.
- **Specs and docs.** `/openapi.json`, `/swagger.json`, `/api-docs`, GraphQL endpoints, generated SDKs.
- **Locale files.** Translation keys reveal features the UI never shows.
- **Client-side gates.** `if (user.role === 'admin')` around a component suggests the server might trust the client. Flipping a flag in local storage or devtools to reveal hidden UI is routine.

Automated tools are exhaustive: they try every endpoint string they find. Put your lures on these paths, and make each decoy answer in a way that makes the next step look worthwhile.

## 2. Pick surfaces the app already has

The strongest lure reuses a pattern the codebase already has. A role-gated lure fits perfectly in an app that gates admin UI by role. A flag-gated lure in an app without feature flags introduces a new pattern, and new patterns stand out.

| If the app has... | Natural lure |
|---|---|
| An API client module or service classes | A method on it for the decoy (A) |
| Role or permission checks in the UI | A gated menu item, route or button (B) |
| A feature-flag system | A flag-gated entry point (C) |
| A versioned API with migration history | A legacy path or fallback (D) |
| An OpenAPI spec with a generated client | The decoy operation in the spec (E) |
| Responses rendered into forms or profile screens | A bait field in the type and the UI (F) |
| Server-rendered forms | A hidden input (G) |
| i18n, lazy routes, inline config | Supporting details (H) |

Use one or two patterns per decoy. A decoy referenced from five places looks staged.

## 3. Lure patterns

### A. A method on an existing API client

Add the decoy call beside its real siblings. Use the same helper, naming, typing and error handling. Put it in the module the cover story implies: a bulk export belongs in the exports or workspace client, not in a new file.

Survival: class methods and object properties survive bundling even when unused. A standalone `export function` that nothing imports is removed by tree-shaking. Either give it a gated caller (B, C) or attach it to the client object.

Camouflage: an uncalled method blends in where the codebase already has uncalled siblings. Several orphans read as unfinished UI. A lone orphan on a sensitive resource (billing, ownership, tokens, tenancy) stands out. If yours would be the only one, give it a gated caller instead.

The more powerful the capability, the more it needs a gated entry point: an uncalled method that impersonates users, switches tenants or redeems vouchers looks planted far more readily than one behind a flag.

### B. Role- or permission-gated UI the backend never grants

Single-page apps routinely ship admin and support screens to every user and hide them behind a client-side check. Attackers know this and look for it, which makes this the most believable lure in a SPA.

The pattern: add a menu item, route or button gated on a role or permission that fits the app's model but that no real account holds. The gated code calls the decoy.

- **Prove the gate never passes.** Read the backend: which roles exist in the database or enum, how they are assigned, whether staff use a separate admin app.
- **Name the chunk.** A lazy-loaded gated route gets its own chunk, and the chunk name is part of the lure. Name the component the way the team would.
- **Keep it small, but finish it.** Don't build a whole fake screen. Give the entry point what the real feature would have at this stage: a response typed like its siblings', the states it moves through, its confirmation and success copy. A thin entry point with an untyped response looks planted; a fully wired one (a typed response with its states, a confirmation, translated copy) looks like work in progress.

### C. A dark-launched feature behind a flag

If the app has feature flags, gate an entry point to the decoy behind a flag that is off for everyone. Attackers who override client-side flags reveal the UI and send the request themselves.

- **Make the flag impossible to enable for real users:**
  - not part of any percentage rollout;
  - not targetable;
  - off by default wherever the flag service has no definition for it.

  Record the flag name in the report so nobody later reuses it for a real feature.
- **Name it like the team's other flags.**
- **Vary it.** Two flag-gated features with one shape (a per-user flag plus an owner check in front of a high-value endpoint) read as written together. For a second decoy, use a different pattern or an inferred decoy.

### D. A legacy path or version fallback

In a versioned API whose client has been migrated, a leftover method or fallback that still points at the old version is natural ("kept for older mobile builds"). Only do this when no real client still calls the old version. Check with the user, and check the server logs.

### E. The decoy in an API spec and generated client

If the frontend uses a client generated from an OpenAPI spec, add the decoy operation to the spec and regenerate. Mark it `deprecated`, or tag it the way the app tags internal operations. The lure then appears in generated code in exactly the generator's style.

If the spec is published, the decoy is discoverable there too. That is fine as long as it stays consistent with its siblings. With an auto-generated spec, a decoy that is a real route appears in it like any other route; if that would invite legitimate API consumers to call it, choose another pattern. Testers diff the spec against the client: a client method whose endpoint is missing from a generated spec that lists every other endpoint is a tell.

### F. Bait fields in types and UI (for honey fields)

When the backend starts returning a bait field (references/backend-traps.md §2), add it to the frontend type for that resource, declared like the real optional fields. Showing it read-only somewhere natural, such as a badge or a disabled input, makes it more convincing: the UI uses the field, so surely the server cares about it.

The real UI must either never send the field or send back exactly what the server returned. Check how the app builds write payloads. If forms spread the whole fetched object back (`{...user, name}`), the field gets echoed, and the check must expect exactly what the server returned.

### G. Hidden inputs in server-rendered forms

In a form the app really submits, add `<input type="hidden" name="..." value="...">` in the app's field-naming style. Every legitimate submission carries that value, and the check expects it.

- **Carry what the app's forms already carry.** Ask whether another real form in this app already sends this kind of value. A hidden input of a kind no other form uses stands out. It stands out more when the server obviously knows the value already, or when nearby text states it. Examples: the seller's own shop ID when the product form gets the shop from the session; the currency of a single-currency site; a platform fee printed next to the form.
- **Follow the app's idiom for read-only values.** A disabled control fits only if the app already shows read-only settings that way. If it states them as text, a form control for the same value is unnatural ("a display-only value needs no `<input>`"). Browsers never submit disabled controls, so any submitted value is tampering, but the control must look like it belongs.
- **Give every field a feature.** A hidden field that is always empty and that no UI ever fills (for example a voucher code in an app with no voucher input) reads as planted. Prefer fields the real UI already sends.
- Avoid names browsers autofill: email, name, address, phone, password fields.
- Check form libraries that whitelist fields or reject unknown ones.

### H. Supporting details

- **Locale strings.** If the app ships translation files to the client, add keys for the gated entry point in every locale the app maintains, in the existing key style.
- **Lazy routes and chunk names.** See B.
- **Inline config.** A key in bootstrap config that the decoy feature would plausibly need.
- **Comments.** Production builds strip comments, but source maps keep them. If you write one, write what a teammate would have written ("used by the v1 mobile client until 4.x is retired"). Never write one that points at the lure ("internal debug, remove before prod"). Usually no comment is best.

## 4. Surviving the build

A lure the bundler removes does not exist. Know what survives:

- **Removed:**
  - unused ES module exports (tree-shaking);
  - code under conditions known at build time (`if (false)`, `process.env.NODE_ENV === 'development'`, `import.meta.env.DEV`);
  - code used only by tests or stories;
  - comments.
- **Kept:**
  - class methods and object properties, even when unused;
  - code behind runtime conditions (user role, flag value);
  - string literals. Minifiers rename variables, not URLs.
- **Server components.** In Next.js and similar frameworks, server components and server actions never reach the browser. Lures must live in client components or client modules.
- **Verify.** Build for production, then run `scripts/scan_bundle.mjs` with each lure string. Report any lure that is missing. For a decoy method on an existing path, the path matches real calls too: scan for a string only the lure has, such as its client method's name.

## 5. False-positive hazards

A legitimate request to a decoy is a false alert, and it erodes trust in every future alert. Never put a decoy URL anywhere something fetches without a person choosing to:

- `<a href>`, `<form action>`, `<img src>`, `<link rel="prefetch|preload">`;
- router link prefetching (Next.js `<Link>`), service-worker precache lists, sitemaps, `robots.txt`;
- effects, data loaders and query prefetchers that run on render (`useEffect`, react-query/SWR prefetch, route loaders);
- retry or polling logic, analytics beacons;
- navigation arrays rendered with `.map`, where one filter bug would show the item to everyone;
- anything link-preview bots, crawlers, uptime monitors, synthetic checks, Lighthouse or e2e crawl tests visit.

Also consider: older app versions still in users' hands, partner integrations, internal scripts, the team's own scanners, and browser autofill on hidden fields.

## 6. Tells

Before finishing, look at each lure the way an attacker would, and remove:

- **Revealing words** anywhere that ships: trap, decoy, honey, honeypot, lure, bait, canary, tripwire, fake, dummy, sensor, deception. Check identifiers, strings, comments, file and chunk names, CSS classes, `data-testid`, storage keys, flag names, locale keys.
- **Style that differs from the neighbors:**
  - a different HTTP helper, quote style or casing;
  - missing types where everything else is typed;
  - untranslated strings where everything else is translated;
  - a different error-handling pattern;
  - different micro-conventions: how flags are aliased to variables, how handlers are named, which calls type their responses. Code written in one sitting shares quirks the rest of the codebase doesn't.
- **Orphans:** a method in an unrelated module, a feature with no natural footprint, or the only uncalled method in a codebase that otherwise has none.
- **Care that doesn't match the stakes:** one feature under three names across method, flag and UI string; a button squeezed into an unrelated form; an owner-only gate on low-value data; a high-stakes feature built more thinly than the app's comparable features; code cloned line for line from a neighboring feature.
- **Repetition:** two lures built from one template read as written together.
- **Real code bent to serve a tripwire:** for example a re-fetch before every save so an echoed field is never stale, with a comment explaining why. Handle staleness on the server instead (backend-traps.md §2).
- **Template seams:** template comments and directives don't ship, but the blank lines they leave do. A hidden input after a blank line that its neighbors lack shows it was added separately.
- **Dangling references:** something nothing consumes, such as a `data-` attribute no script reads or a config key no code uses. It exists only to be found, and reads that way.
- **Vocabulary only lures use:** a role, permission, scope or flag that appears in a lure and nowhere else in the app.
- **Clichés:** "internal", "debug", "do not use", "remove before prod", `/admin/secret`, `superuser`.
- **Mismatches with the backend:** a different method, a path that answers 404, a response that doesn't fit the type the frontend declares.
- **Anything copied from this skill's examples.**

## 7. Framework notes

- **React (Vite, CRA, React Router/Remix).** API modules and hooks are natural homes. Gated routes in the router config with `lazy()` produce named chunks. Vite emits source maps only when `build.sourcemap` is set.
- **Next.js.**
  - Lures belong in `"use client"` components and client-side modules.
  - Page routes appear in build manifests; API calls made from client components appear in chunks.
  - `productionBrowserSourceMaps` controls public source maps.
  - If the API itself is Next.js route handlers, decoys are route handlers too: call the same helpers as the sibling handler, in the same order.
- **Vue / Nuxt.** Composables and API service modules; route meta for role gates. Nuxt server routes are backend code.
- **Angular.** Injectable services are classes, so unused methods survive. Route guards (`canActivate`) are the natural role gate.
- **Svelte / SvelteKit.** Use client modules. Loaders (`+page.ts`) run on navigation, so never put a decoy call in a loader that real users trigger. `+page.server.ts` never ships.
- **Server-rendered templates (Django, Jinja, ERB-style, Go templates, EJS).** Content inside a server-side role check (`{% if user.is_staff %}`) never reaches other users, so it is not a lure. What everyone receives is hidden inputs, data attributes, the app's static JavaScript, and response fields of JSON endpoints.

  Client-side lures are weak here. A script hook for markup no page ever renders (a submit handler for a form that never appears) is a dangling reference. Hidden inputs that duplicate state the server already holds (the user's own shop ID, a single-currency site's currency) look planted too.

  Prefer, in order:
  1. honey fields the real JSON already exposes (backend-traps.md §2);
  2. inferred decoys (backend-traps.md §1).

  Values the real forms never offer, in fields they already submit, are covered by the add-detection skill.

  A design built only from these adds nothing to the pages. The trade-off is that such tripwires are found only by probing. They catch active testers, not people reading the page source. Give at least one a breadcrumb that probing turns up, such as the `405` and `Allow` header some frameworks send for other methods on the decoy's path, or an error that names a permission.
- **Mobile apps.** Decompilers read endpoint strings out of the binary. The same patterns apply, but slow release cycles make lures harder to maintain.

## 8. Apps without a frontend, or a frontend you can't change

For public APIs consumed by developers, the API itself is the lure surface:
- fields in responses (a link to a legacy resource, a permissions array);
- the published spec and SDKs;
- error messages that name a permission or a newer endpoint;
- older versions.

If the frontend lives in a repository you can't access, write the lure changes as a patch or instructions for that team, and leave out any lure you can't verify.
