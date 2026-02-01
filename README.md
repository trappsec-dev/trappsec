## **trappsec** 

**trappsec** is an open-source framework for instrumenting application-layer deception. It enables developers to embed high-fidelity detection triggers directly into the API surface, turning attacker reconnaissance into actionable security telemetry.

---

### Core Concepts

* **Decoy Routes:** Defined endpoints that exist outside of your business logic. They are designed to mimic standard API patterns (e.g., `/api/v1/admin/config`) and return configurable, realistic responses. Since these routes are omitted from client documentation, any interaction constitutes a high-probability indicator of unauthorized probing.


* **Honey Fields:** Non-functional parameters injected into legitimate request schemas. While invisible to the UI and standard users, they serve as "tripwires" for automated scanners or manual testers attempting to manipulate sensitive fields (e.g., `is_admin` or `debug_mode`).


* **Identity Attribution:** Middleware hooks allow you to bind traps to specific session contexts, IP addresses, or authenticated identities. By mapping traps to a specific **intent** (e.g., *Privilege Escalation* or *Database Discovery*), you generate alerts with immediate architectural context.

---

### Alerting & Integration

trappsec can integrate directly into your existing workflows. Events are written to your standard logging handlers by default, but can be configured to integrate into **OpenTelemetry** for observability or **Webhooks** to trigger automated responses or notify security teams.

---

### Shift detection "left" into the application itself.