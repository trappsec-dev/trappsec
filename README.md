![Version 0.1](https://img.shields.io/badge/version-0.1-blue)
## **trappsec** 

trappsec is an open-source framework that helps developers detect attackers who probe API business logic. By embedding realistic decoy routes and honey fields that are difficult to distinguish from real API constructs, attackers are nudged to authenticate — converting reconnaissance activity into actionable security telemetry.

> Built for the 1% of people who actually look at their security alerts, **and** the 99% who just like the idea of having them — based on the radical idea that if you can’t reduce your attack surface, expand it.


[Read the Docs](https://trappsec.dev/getting-started/) • [Ultra Quickstart](https://trappsec.dev/ultra-quickstart/)

---

### Core Concepts

* **Decoy Routes:** These are "ghost" endpoints that sit outside your real logic but look authentic. By planting dummy references in your client-side code, you can bait attackers into hitting these traps, allowing you to monitor their behavior via custom static or dynamic responses.

* **Honey Fields:** Non-functional parameters embedded within legitimate API endpoints that act as invisible tripwires. You can bait attackers by including them as hidden form fields with static values or leveraging existing "read-only" attributes that appear in GET responses as honey fields that trigger alerts if an attacker attempts to modify them via POST or PUT requests.

* **Identity Attribution:** Framework hooks allow you to link a request to an authenticated user identity. You can also map traps to a specific **intent** (Privilege Escalation, Reconnaissance etc). Put together, you get high-fidelity alerts that security teams can respond to quickly and more effectively.

---

### Best Practices

*  **Require Authentication:** In an internet that is mostly harmless but increasingly full of people and scanners (mostly scanners) poking things they shouldn't, you don’t want to get buried with noise. Use unauthenticated template responses like (401, Unauthorized) to guide them to probe with authentication.

*  **Blend In:** A trap should look exactly like a normal part of your API. A good trap should look like a mundane, standard - perhaps even tedious part of your API. If it looks "too good to be true", attackers will ignore it. Design traps to catch people trying to understand or manipulate your business logic.

---

### Alerting

trappsec can integrate directly into your existing workflows. Events are written to your standard logging handlers by default, but can be configured to also integrate into **OpenTelemetry** for observability or **Webhooks** to trigger automated responses or notify security teams.

---

### Supported Frameworks

<table>
  <thead>
    <tr>
      <th>Language</th>
      <th>Framework</th>
      <th>Status</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td rowspan="2"><b>Python</b></td>
      <td>Flask</td>
      <td>✅ Stable</td>
    </tr>
    <tr>
      <td>FastAPI</td>
      <td>✅ Stable</td>
    </tr>
    <tr>
      <td><b>Node.js</b></td>
      <td>Express</td>
      <td>✅ Stable</td>
    </tr>
    <tr>
      <td rowspan="2"><b>Go</b></td>
      <td>net/http</td>
      <td>🚧 Planned</td>
    </tr>
    <tr>
      <td>Gin</td>
      <td>🚧 Planned</td>
    </tr>
  </tbody>
</table>

> Missing your favorite framework? [Raise a request here](https://github.com/trappsec-dev/trappsec/discussions/new?category=feature-requests).

---

### Support
Community support is available via GitHub issues and discussions.  
For commercial support or services, email **nikhil@ftfy.co**.