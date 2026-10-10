# trappsec

trappsec is an open-source framework that helps developers detect attackers who probe API business logic. By embedding realistic decoy routes and honey fields that are difficult to distinguish from real API constructs, attackers are nudged to authenticate, converting reconnaissance into actionable security telemetry.

[Docs](https://trappsec.dev/overview/) | [Ultra Quickstart](https://trappsec.dev/ultra-quickstart/) | [GitHub](https://github.com/trappsec-dev/trappsec)

## Core concepts

* **Decoy routes**: ghost endpoints that look authentic. Hits are reported with the caller's identity and your chosen intent, and the response can differ for authenticated and unauthenticated callers.
* **Honey fields**: query or body parameters on real endpoints that legitimate clients never change. Modifying one raises an alert. Watched fields are always stripped from the request before your handler sees it.
* **Identity attribution**: link requests to users with `identify_user` to turn signals into high-fidelity alerts.

## Install

```sh
pip install trappsec
pip install "trappsec[webhooks]"   # webhook and Slack delivery (requests)
pip install "trappsec[otel]"       # OpenTelemetry span events
```

Supported frameworks: Flask, FastAPI, Starlette, Litestar, Django, Sanic, Tornado. Python 3.9+.

## Usage

```python
from fastapi import FastAPI
from trappsec import Sentry, NO_DEFAULT

app = FastAPI()
ts = Sentry(app, service="orders", environment="prod")

ts.identify_user(lambda request: {"user": request.headers.get("x-user"), "role": None})
ts.add_webhook("https://example.com/hooks/trappsec", secret="s3cret")

ts.template("unauthorized", 401, {"error": "unauthorized"})

ts.trap("/admin/export").intent("Reconnaissance").if_unauthenticated(template="unauthorized")
ts.watch("/profile").body("is_admin", default=False, intent="Privilege Escalation") \
                    .query("debug", default=NO_DEFAULT, intent="Reconnaissance")
```

Traps and watches are installed at application startup. Call `ts.bootstrap()` yourself (it is idempotent) if you serve the app through a custom test client or server; the first request also bootstraps lazily where the framework allows it.

## Alerting

Events are written to the `trappsec` logger as JSON. trappsec never configures logging; attach your own handlers.

* `add_webhook(url, secret=None, headers=None, heartbeat_interval=None, template=None, alerts_only=True)`: delivery is asynchronous (bounded queue of 1000, background worker, up to 2 retries) and never blocks a request. When `secret` is set, requests carry `x-trappsec-timestamp` and `x-trappsec-signature: sha256=<hex HMAC-SHA256(secret, "<timestamp>.<raw body>")>`.
* `add_slack(url, alerts_only=True)`: Slack incoming webhook.
* `add_otel()`: adds attributes and events to the current OpenTelemetry span.

Call `ts.close()` on shutdown to stop heartbeats and flush pending deliveries.

## License

MIT
