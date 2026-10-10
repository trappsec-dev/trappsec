# trappsec (Node.js)

Deception as a developer tool: decoy routes (traps) and honey fields (watches) for Express, Fastify, Koa, Hapi and NestJS.

```js
const express = require('express');
const { Sentry } = require('trappsec');

const app = express();
app.use(express.json());

const ts = new Sentry(app, 'my-service', 'production');
ts.identify_user(req => req.user ? { user: req.user.id, role: req.user.role } : null);

ts.trap('/admin/backup').intent('Recon').respond({ status: 200, body: { ok: true } });
ts.watch('/profile').body('is_admin', { defaultValue: false, intent: 'Privilege escalation' });

ts.add_webhook('https://example.com/hook', { secret: process.env.HOOK_SECRET });

app.listen(3000);
```

## API

- `new Sentry(app, service, environment)`
- `trap(path)` / `watch(path)` / `template(name, status, body, mime?)`
- `identify_user(cb)` / `override_source_ip(cb)`
- `add_webhook(url, opts)` / `add_slack(url, opts)` / `add_otel()`
- `trigger(req, reason, intent?, metadata?)` emits a `trappsec.rule_hit` event
- `bootstrap()` installs traps and watches (idempotent; called by `listen`)
- `close(timeout?)` stops heartbeats and flushes pending deliveries

## Webhook signing

When a `secret` is set, requests carry `x-trappsec-timestamp` (unix seconds) and
`x-trappsec-signature: sha256=<hex HMAC-SHA256(secret, "<timestamp>.<raw body>")>`.

Delivery is asynchronous (global `fetch`, 5s timeout, max 100 in flight, 2 retries). Requires Node 20+.
`@opentelemetry/api` is an optional peer dependency used by `add_otel()`.

License: MIT
