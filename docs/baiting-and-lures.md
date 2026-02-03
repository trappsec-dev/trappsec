---
layout: default
title: Baiting & Lures
nav_order: 3
permalink: /baiting-and-lures/
---

# Baiting & Lures

Traps are only effective if attackers find them. You need to plant "lures" — hints and crumbs that lead attackers to your decoy routes and honey fields.

### Decoy Routes
*   **Frontend Code**: Attackers often reverse-engineer your client-side code (JavaScript bundles, mobile apps) to map your API surface. By including "ghost methods" in your service layer that are never called by the UI but reference trap endpoints, you can trigger alerts when attackers try to invoke them.

```typescript
// services/UserService.ts

class UserService {
    // ... legitimate methods ...
    async getProfile() { /* ... */ }
    async updateAvatar() { /* ... */ }

    // 🪤 LURE: This method is never called by the UI. 
    // It exists solely to trap attackers inspecting the code.
    async updateUserPermissions() { 
        return this.http.post('/api/v1/admin/user', {..}); // Trap Endpoint
    }
}
```

*   **Documentation Artifacts**: Include references to decoy routes in fake API documentation, unused Swagger/OpenAPI files, or comments.
*   **Legacy Versions**: If your app uses `/api/v2/...`, deploy traps at `/api/v1/...` mirroring the structure. Attackers often check for older, potentially vulnerable versions.

### Honey Fields
*   **Hidden Parameters**: Include the honey field in your API payloads or hidden form fields with a default value (e.g., passing `"is_admin": false` in a profile update). Legitimate users won't change it, but attackers might.
*   **Mass Assignment**: Expose a sensitive-looking parameter (like `"role": "user"`) in a `GET` response. Attackers may try to include it in a subsequent `POST` or `PATCH` request to escalate privileges.

---

{: .note }
> **Get Creative:**
> These are just a starting point. This list is by no means exhaustive. The most effective lures are often specific to your business logic and technology stack. The only limit is your own creativity (and how devious you want to be).
