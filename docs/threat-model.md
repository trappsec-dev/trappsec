---
layout: default
title: Threat Model
permalink: /threat-model/
tagline: "What trappsec detects, what it does not, and how attackers may notice it."
---

trappsec is a **detection** tool for attackers who probe your API's business logic. It is not a firewall, a WAF or an authentication system, and it never blocks a request.

## Attacker model

trappsec assumes an attacker who:

*   can send arbitrary HTTP requests to your API, usually with a low-privilege (or stolen) account;
*   reads client-side code, API docs, OpenAPI specs and responses to discover endpoints and parameters;
*   tries endpoints and fields that "should not" be used by them: admin routes, hidden flags such as `is_admin`, read-only attributes returned by GET and echoed back in PUT/POST (mass assignment), debug parameters.

A legitimate user of your own UI never touches a decoy route or sends a honey field, so any hit is high-signal.

## What it detects

| Technique | Detected by |
|---|---|
| Endpoint enumeration and forced browsing | Trap routes (`trap_hit`) |
| Use of leaked or forgotten client-side references | Trap routes baited through [lures](/baiting-and-lures/) |
| Mass assignment / privilege escalation via extra body or query fields | Watches (`watch_hit`) |
| Parameter tampering on read-only or fixed values | Watches with a default value |
| Business-logic abuse you can recognize in code | `trigger()` (`rule_hit`) |
| Evasion by duplicating parameters (`?role=user&role=admin`), by type games (`"true"`, `1.0`) or, in Go, by key case | Canonical [value matching](/events/#value-matching) |

Hits with an identified user are `alert`s; hits without one are `signal`s (see [Tuning](/tuning/)).

## What it does not detect

*   Attacks against routes that have no trap or watch. Coverage is only as good as your decoys.
*   Anything that never reaches your application: attacks blocked or handled by a CDN, WAF or gateway, or traffic to other services.
*   Injection, XSS, SSRF, authentication bypass and other vulnerability classes. A trap only tells you someone went somewhere they should not.
*   Attackers who only use documented, legitimate behavior (for example, scraping an endpoint they are allowed to call).
*   Request bodies beyond what the integration parses: unsupported content types, bodies larger than the Go adapters' size limit (1 MiB by default) or the Litestar integration's (10 MiB, just above Litestar's own default `request_max_body_size` of 10 MB, so by default Litestar rejects such bodies first), or multipart parts that are not text fields are not inspected.
*   A compromised host. An attacker with code execution can read configuration and silence the sensor. Use heartbeats to notice silence.
*   Attribution accuracy beyond what your `identify_user` and IP extraction provide.

## Fingerprinting considerations

A determined attacker may try to tell traps from real routes. trappsec reduces the signals, but you control the rest:

*   **Traps are real framework routes**, not middleware shortcuts, registered next to your real routes, so routing behavior (405 vs 404, trailing slashes, HEAD/OPTIONS handling) follows the same rules as your real endpoints. The exceptions are listed, each with the app-side fix, under [where a trap can still differ from a real route](/supported-frameworks/#where-a-trap-can-still-differ-from-a-real-route): middleware or hooks scoped to a router, group or plugin (Fastify, Gin, chi and gorilla/mux), validation that runs before auth (Fastify), wrong-method answers (chi, gorilla/mux, Django REST framework) and schema listings (FastAPI). Shadowing and CSRF protection never change the decoy response.
*   **Unauthenticated requests get the decoy's `if_unauthenticated` response** (default `401`). This looks like any protected route and nudges the attacker to authenticate, which turns a `signal` into an `alert`.
*   **Make responses plausible.** Use realistic status codes, bodies and headers. Empty `{}` on every trap is a tell; use [templates](/api/#template) and dynamic bodies.
*   **Keep latency comparable.** Delivery is asynchronous so webhooks never add latency; avoid slow dynamic bodies.
*   **Do not give traps away by naming.** Names like `/admin/honeypot` defeat the purpose. See [Best Practices](/best-practices/).
*   **Honey fields must be stripped.** trappsec removes every occurrence of a watched field before your handler runs, so it can never change real behavior and cannot be used to probe your logic.
*   **Source is public.** trappsec is open source; assume attackers know the technique. Detection value comes from realistic, application-specific decoys, not secrecy of the library.
*   **Error behavior.** Callback failures never change the response; the request proceeds as if trappsec were not there.

## Security of the alert channel

Sign webhooks with a `secret` and verify timestamp and signature ([details](/events/#webhook-signing)); events contain attacker-controlled strings (paths, user agents, field values). trappsec truncates and sanitizes them, and Slack output is escaped, but treat them as untrusted data in your SIEM and ticketing tools.
