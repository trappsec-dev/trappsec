# Sinks

A sink is an operation where a value stops being data: it becomes part of a query, a command, a template, an object graph, a file path or a network address. An attacker who probes one leaves a different trace from one who probes business logic. The app usually doesn't refuse the input with a validation error; the operation fails, or runs somewhere it never should.

The rule is the same as for the rest of add-detection: add no check that changes what the app does, and record only what the app's own code can never cause.

## Which sinks

Only the ones request input can reach. Start from the handlers and follow each value the caller controls (body, query, path, headers, uploaded file names and content, stored values another request wrote) to where it is used:

| Sink | Where to look |
|---|---|
| `sql` | Statements built as text: string formatting or concatenation into a query, raw fragments passed to an ORM (an order-by, a filter expression, a column name) |
| `command` | Processes the app starts with an argument from input, above all through a shell |
| `template` | Templates compiled from a string at run time, where any part of the string comes from input or from stored content users edit |
| `deserialization` | Formats that build objects or run code while they load (native object serialization, a YAML loader that constructs types) |
| `xml` | Parsers given a document from input: entities, DTDs, external references |
| `file` | A path built from input: downloads, uploads, attachments, exports, includes |
| `outbound` | A request the server makes to an address from input: webhooks, link previews, imports by URL, avatars, callbacks |

A sink that input can't reach gets nothing. A sink where input goes in as a bound parameter, an argument vector with no shell, or a fixed template with data passed as context is doing the right thing: list it as checked and move on.

## Three sources of a sink finding

**1. An error only injected input can cause.** The app's own statements, templates and documents parse: if one didn't, it would have failed the first time anyone ran it. So in production, on a statement the app builds, these come from input that changed its structure:

- a database **syntax** error. Only the syntax class (the driver's code for it): an unknown column or table also happens during a deploy, a constraint violation is ordinary, and a timeout or deadlock is load;
- a template syntax or compile error, on a template built at run time;
- a deserializer or parser refusing a type, a tag, an entity or a DTD that the app never writes;
- a shell reporting a syntax error.

Record where the error is caught: at the app's own helper around the operation where every caller uses one, otherwise in the central error handler by the error's class. The response is whatever the app already answers. `outcome` is `refused`.

Leave out any feature where users write the query or template themselves (a report builder, an admin console, a theme editor): their mistakes are typos.

**2. A guard the app already has at the sink**: a check that the resolved path stays in its directory, an allow-list of hosts or a block on private addresses, an allow-list of classes. Its refusal follows the main skill's bar. Where no real client can produce the input (`..` in a field the client fills from names the server listed), it is a sink finding with `outcome` = `refused`. Where a real user can (someone typing `http://localhost` into a webhook form), it is a refusal on the server span and nothing more.

**3. An invariant the code implies and doesn't check.** The feature serves files from one directory, or fetches public URLs, and nothing enforces it. Here the operation went ahead, so this is first a vulnerability: report it with the others for the user to fix. Until it is fixed, observe it, without stopping it:

- a file path that, once the code has resolved it, lies outside the directory the feature serves;
- an outbound request that connected to a loopback, private, link-local or metadata address, from a feature meant for public ones.

`outcome` is `allowed`, and the severity `critical`. Decide from values the code already holds: the resolved path it is about to open, the address the HTTP client reports it connected to. Never touch the file system or resolve a name a second time to find out, since a second lookup can answer differently from the first and waits on the network. Where the client doesn't expose the connected address, the invariant can't be observed: say so, and leave the vulnerability report to stand on its own.

When the user fixes the vulnerability by adding the guard, the rule moves to source 2 and its outcome becomes `refused`.

## Rules for every sink rule

- **Record at the app's own call site or helper**, with its idioms. Never patch or wrap a library globally: that is instrumentation, and add-telemetry's to decide.
- **Add no parsing, no pattern matching on the input, and no check that can change the outcome.** A rule that looks for quotes or `../` in a value is a WAF rule, and real data contains both.
- **Cost stays constant**: one comparison on an error class, a prefix test on a path already resolved, a range test on an address already known.
- **What goes in the finding** is in references/telemetry.md, Sink findings: the kind of sink, the error's class, the field when known, otherwise the input's length and hash. Never the statement, command, template or content.
- **Each rule gets an inventory entry** like any other, with the source (1, 2 or 3) and, for source 3, a link to the vulnerability it stands in for.

## What can go wrong

A release that ships a broken statement trips a source-1 rule for every caller at once. That is a bug, not an attack, and the finding can't tell them apart; the backend can, because it arrives from many unrelated accounts right after a new `service.version`. Say so in the inventory entry and the report, and keep the app's own tests covering every statement the rule watches.

Verification for a sink rule is the same as for any other, with two additions: trigger each rule with input that breaks the structure and show the response is unchanged from before the rule existed; and run the app's whole test suite with recording on and show no sink finding, which proves the app's own statements don't trip it.
