---
layout: default
title: Overview
permalink: /overview/
tagline: "An open-source framework that turns your application into a security sensor — detecting attackers who probe your API business logic before they exploit anything."
---

{: .note }
> trappsec is MIT-licensed and available on [GitHub](https://github.com/trappsec-dev/trappsec). Current version: `0.2.0`.

<div class="video-wrap">
  <iframe
    src="https://www.youtube.com/embed/Tke40NKbYxk?si=9V2J4oIpGRugybeP"
    title="trappsec explainer"
    frameborder="0"
    allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share"
    allowfullscreen>
  </iframe>
</div>

## What it does

By embedding realistic **decoy routes** and **honey fields** that are indistinguishable from real API constructs, trappsec nudges attackers to authenticate — converting anonymous reconnaissance into identity-attributed security telemetry.

Detection happens *before* the perimeter is crossed, at the reconnaissance phase, when an attacker is still mapping your API surface. Traditional honeypots tell you a breach happened. trappsec tells you it's coming.

<div class="intro-cards">
  <a class="intro-card" href="/getting-started/">
    <span class="intro-card-icon">→ Getting Started</span>
    <h3>Installation &amp; setup</h3>
    <p>Install the SDK, initialise the Sentry, and define your first trap in under 5 minutes.</p>
  </a>
  <a class="intro-card" href="/ultra-quickstart/">
    <span class="intro-card-icon">⚡ Ultra Quickstart</span>
    <h3>See it working now</h3>
    <p>Copy-paste a full working example and trigger a trap from the command line.</p>
  </a>
  <a class="intro-card" href="/baiting-and-lures/">
    <span class="intro-card-icon">🪤 Baiting &amp; Lures</span>
    <h3>Make traps discoverable</h3>
    <p>A trap no one finds doesn't fire. Learn how to plant effective lures.</p>
  </a>
  <a class="intro-card" href="/api/">
    <span class="intro-card-icon">{} API Reference</span>
    <h3>Full API docs</h3>
    <p>Every method on <code>Sentry</code>, <code>TrapBuilder</code>, and <code>WatchBuilder</code>.</p>
  </a>
</div>

## Core concepts

### Decoy Routes

Ghost endpoints that sit outside your real logic but mirror your authentic API structure. When a request hits one, trappsec intercepts it, sends a convincing dummy response, and fires a high-fidelity alert. Attackers doing path discovery can't distinguish them from live routes.

### Honey Fields

Non-functional parameters embedded within legitimate API payloads. You bait attackers by including them as read-only attributes in GET responses — for example, `"is_admin": false`. If an attacker tries to flip that field in a POST, trappsec silently fires an alert while the application logic continues normally.

### Identity Attribution

Framework hooks let you link every event to an authenticated user identity. Unauthenticated probes return a `401` and generate only a low-priority `signal` — keeping noise out. When an attacker authenticates and returns, the `alert` carries their user ID, role, IP, and the intent label you declared on the trap.

## Supported frameworks

| Language | Frameworks | Install |
|----------|------------|---------|
| **Python** | Flask, FastAPI, Django, Starlette, Litestar, Sanic, Tornado | `pip install trappsec` |
| **Node.js** | Express, NestJS, Fastify, Hapi, Koa | `npm install trappsec` |
| **Go** | Gin, net/http, Echo | `go get github.com/trappsec-dev/trappsec/packages/go/gin` |

Missing your framework? [Raise a request →](https://github.com/trappsec-dev/trappsec/discussions/new?category=feature-requests){:target="_blank"}
