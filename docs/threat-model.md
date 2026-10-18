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

*   **Traps are real framework routes**, not middleware shortcuts, so routing behavior (405 vs 404, trailing slashes, HEAD/OPTIONS handling) matches your real endpoints. Shadowing and CSRF protection never change the decoy response.
*   **Unauthenticated requests get the decoy's `if_unauthenticated` response** (default `401`). This looks like any protected route and nudges the attacker to authenticate, which turns a `signal` into an `alert`.
*   **Make responses plausible.** Compare each trap byte for byte with a real sibling route and copy what differs. Empty `{}` on every trap is a tell.
    *   **Headers.** Frameworks add headers a trap must copy: FastAPI's `HTTPBearer` and `OAuth2PasswordBearer` send `WWW-Authenticate: Bearer` on every 401; Django REST framework sends `Allow`, `Vary: Accept` and `WWW-Authenticate` on every APIView response. Set them with `headers` on `respond`, `if_unauthenticated`, the [default responses](/api/#default-responses) or a [template](/api/#template).
    *   **Bytes.** trappsec JSON-encodes object bodies itself, which can differ from your framework's encoder (key order, ASCII escaping, a trailing newline). Use a string body captured from the real route to match exactly; see [Matching the real response bytes](/api/#matching-the-real-response-bytes).
    *   **Status per request.** A real route answers 404 for an unknown or foreign parent ID, 201 to the owner of a project (the most privileged role a self-signup attacker holds) and 422 or 400 for a malformed body. A static decoy cannot; mirror those checks from data already on the request with [`respond_with`](/api/#respond_with).
    *   **Validation order** is not reproduced: FastAPI parses a JSON body, and Fastify runs its body schema, before authentication, so a real route can answer 422 or 400 to an unauthenticated malformed request where a trap answers 401. Mirror it in `respond_with` if your attackers can reach it.
*   **Keep latency comparable.** Delivery is asynchronous so webhooks never add latency; avoid slow dynamic bodies and `respond_with` hooks.
*   **Do not give traps away by naming.** Names like `/admin/honeypot` defeat the purpose. See [Best Practices](/best-practices/).
*   **Honey fields must be stripped.** trappsec removes every occurrence of a watched field before your handler runs, so it can never change real behavior and cannot be used to probe your logic.
*   **Source is public.** trappsec is open source; assume attackers know the technique. Detection value comes from realistic, application-specific decoys, not secrecy of the library.
*   **Error behavior.** On watched routes, callback failures never change the response; the request proceeds as if trappsec were not there. On traps, a failing `respond_with` hook sends the trap's static response, and a failing body callback (or a body that cannot be encoded) sends the default response for the auth state, never `{}`. Set the defaults to your real 401 and 403 so a failure is indistinguishable from a regular hit.

## Security of the alert channel

Sign webhooks with a `secret` and verify timestamp and signature ([details](/events/#webhook-signing)); events contain attacker-controlled strings (paths, user agents, field values). trappsec truncates and sanitizes them, and Slack output is escaped, but treat them as untrusted data in your SIEM and ticketing tools.
