---
layout: default
title: Wiring Effective Traps
nav_order: 3
---

# Wiring Effective Traps

Effective deception is not about creating the most complex trap; it's about creating the most convincing one. This guide outlines strategies to design traps that attract attackers and generate high-fidelity alerts without disrupting legitimate users.

## 1. The Art of Blending In (Realism)
The primary goal of a decoy route or honey field is to look boringly normal. If a trap looks too good to be true, sophisticated attackers will avoid it.

### Match Your Neighbors
Your decoy routes should indistinguishably resemble your real API endpoints.
*   **Naming Conventions**: If your API uses `snake_case`, your traps must use `snake_case`. If you use `/api/v1/resource`, don't put a trap at `/admin/config` unless you actually have other root-level admin routes.
*   **Error Handling**: If your real API returns `{ "error": { "code": 401, "message": "..." } }` for unauthenticated requests, your traps must return the exact same structure. A default Nginx 404 page in a JSON-only API is a dead giveaway.

### The "Boring" Response
Don't try to be clever with responses.
*   **Avoid**: "You have been caught!" or infinite redirection loops. This signals to the attacker that they are being watched, prompting them to change tactics or IP addresses.
*   **Prefer**: Standard HTTP errors like `401 Unauthorized`, `403 Forbidden`, or `405 Method Not Allowed`. These are frustratingly common for attackers and encourage them to try "just one more" payload, keeping them engaged with the trap.

## 2. Strategic Placement
Where you place your traps determines who you catch.

### The "Obvious" Targets (Low Hanging Fruit)
Place traps in locations that automated scanners and script kiddies always check. This helps identify broad scanning campaigns.
*   `/admin`
*   `/config`
*   `/metrics`
*   `/health`
*   `/.git`
*   `/.env`

### The "Shadow" Targets (Sophisticated)
Shadowing involves placing traps near or "under" real resources to catch privilege escalation or lateral movement attempts.
*   **Shadow Decoys**: If you have `/api/v1/users`, create `/api/v1/users/admin` or `/api/v1/users/export`.
*   **Legacy Shadows**: Revive old endpoints that have been deprecated. If you moved from `/v1/` to `/v2/`, trap the old `/v1/` routes. Legitimate clients should have migrated; attackers often rely on outdated docs or old exploits.

## 3. Lure Strategies (Bait)
A trap is useless if no one finds it. You need lures—breadcrumbs that lead attackers to your traps.

### Passive Lures
*   **robots.txt**: explicitely "disallow" a decoy path. Attackers treat `robots.txt` as a target list.
    ```text
    User-agent: *
    Disallow: /api/internal/config  # <--- Decoy Route
    ```
*   **HTML Comments**: Leave comments in your frontend code hinting at admin endpoints or debug modes.
    ```html
    <!-- TODO: Remove debug endpoint /api/debug/users before prod -->
    ```

### Active Lures (Honey Fields)
Embed honey fields (fake parameters) in the responses of legitimate API calls.
*   Return a user object with an extra key: `{ "id": 123, "role": "user", "is_admin_mode": false }`.
*   If an attacker sends `POST /update` with `"is_admin_mode": true`, you have a confirmed privilege escalation attempt.

## 4. Operational Security
How you handle the detection is just as important as the detection itself.

### Silent Interception
When an attacker interacts with a Honey Field (e.g., sends a malicious parameter), **do not block the request**.
1.  **Strip** the malicious field from the request.
2.  **Forward** the sanitized request to your actual application logic.
3.  **Return** a standard `200 OK` (or whatever the app would normally return).

**Why?** If the request fails, the attacker knows the parameter was invalid. If it succeeds, they think they might have bypassed a filter or that the parameter is accepted but silent. This keeps them in the dark about the alert they just triggered.
