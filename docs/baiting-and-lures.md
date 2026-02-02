---
layout: default
title: Baiting & Lures
nav_order: 3
permalink: /baiting-and-lures/
---

# Baiting & Lures

Traps are only effective if attackers find them. You need to plant "lures" — hints and crumbs that lead attackers to your decoy routes and honey fields.

### Decoy Routes
*   **Frontend Code**: Leave references to decoy routes in your Javascript or mobile app source code (e.g., `const ADMIN_API = "/api/admin/v1";`), but ensure they are never invoked by legitimate user flows.
*   **Documentation Artifacts**: Include references to decoy routes in fake API documentation, unused Swagger/OpenAPI files, or comments.
*   **Legacy Versions**: If your app uses `/api/v2/...`, deploy traps at `/api/v1/...` mirroring the structure. Attackers often check for older, potentially vulnerable versions.

### Honey Fields
*   **Hidden Parameters**: Include the honey field in your API payloads or hidden form fields with a default value (e.g., passing `"is_admin": false` in a profile update). Legitimate users won't change it, but attackers might.
*   **Mass Assignment**: Expose a sensitive-looking parameter (like `"role": "user"`) in a `GET` response. Attackers may try to include it in a subsequent `POST` or `PATCH` request to escalate privileges.

---

{: .note }
> **Get Creative:**
> These are just a starting point. This list is by no means exhaustive. The most effective lures are often specific to your business logic and technology stack. The only limit is your own creativity (and how devious you want to be).
