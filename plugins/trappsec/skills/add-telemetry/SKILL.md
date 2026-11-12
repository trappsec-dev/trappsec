---
name: add-telemetry
description: Set up OpenTelemetry traces, logs and metrics in an application the user owns, so every request has a server span, the app's own log records carry its trace, and everything is exported over OTLP. Use this whenever the user wants to add OpenTelemetry, tracing, distributed traces, OTLP export or log correlation to their app, or when add-auditing, add-deception or add-detection stopped because traces and logs were missing. Not for custom business metrics, dashboards, alerting, deploying a Collector, or instrumenting LLM calls.
license: MIT
---

# Add telemetry

You are giving the application standard OpenTelemetry: one server span per request with the right attributes, child spans for its database and outbound calls, its own log records joined to the request that wrote them, and the framework's HTTP metrics, all exported over OTLP. When you finish, the app meets the prerequisite the other trappsec skills check for, and nothing about how it behaves, responds or logs to its console has changed.

The judgment calls are yours:
- where the SDK must start in each entry point, so nothing loads before the instrumentation that patches it;
- which instrumentations the app needs, from what it actually uses;
- what must never reach a span or a log record;
- proving the telemetry arrives, and that the app is unaffected when the backend is down or absent.

## What makes a good setup

| Property | In practice |
|---|---|
| Standard | The SDK, the official instrumentations and OTLP, configured by the standard `OTEL_*` environment variables. No vendor SDK, no custom wire format. |
| Off until configured | With no OTLP endpoint set, the app starts no exporter and sends nothing anywhere. Setting the endpoint is the one switch. |
| Everywhere the app runs | Every entry point initializes it: web server and each of its worker processes, background workers, schedulers, CLIs, scripts, management commands. |
| Correlated | Every log record the app writes inside a request carries that request's trace and span IDs. |
| Harmless | Exporting never fails, blocks or slows a request; the backend being down changes nothing the user sees; the console output stays as it was. |
| Quiet | Health checks and static files make no traces, and the exporter's own errors never loop back into the export. |
| Clean | No request or response bodies, no auth headers or cookies, no secrets from URLs or SQL parameters. |

## Workflow

### 0. Prerequisites and questions

- **Ownership and scope.** Confirm this is the user's own application. Ask before touching the Collector, infrastructure, CI or deployment configuration; tell the user which variables to set there instead.
- **What is already there.** Look for an existing OpenTelemetry setup, a vendor agent or APM SDK (Datadog, New Relic, Sentry tracing, Elastic APM), and trace-ID injection in the log format. An existing OpenTelemetry setup is extended, never replaced: fill only the gaps the prerequisite list below names. A vendor agent or SDK that traces the HTTP server or the database driver in production can double every span: stop and ask which one stays before adding anything. One that is installed but doesn't trace (Sentry with no traces sample rate) is no conflict; say so in the plan.
- **Questions.** Ask in one batch, only what the code cannot tell you:
  1. Where should telemetry go: an OTLP endpoint (a Collector, a vendor, a log store), and does it need an auth header? If there is none yet, you verify against a local Collector and leave the endpoint unset.
  2. Which processes run in production: the web server and its launcher (gunicorn, uWSGI, Puma, PM2, a container entrypoint), workers, schedulers, cron jobs, one-off scripts?
  3. Do other services call this one with trace context, or is every caller outside the organization? This decides whether the server span trusts an inbound `traceparent` (references/setup.md).

### 1. Reconnaissance

- **Entry points.** Every way the app's code starts: the web entry (`wsgi.py`, `asgi.py`, `server.js`, `main.go`, `config.ru`), the launcher's fork and preload settings, worker and scheduler entry points, CLIs, scripts and management commands, test runners.
- **What to instrument.** The web framework and server, the database drivers and ORM, caches and queues, and the HTTP clients the app uses for outbound calls.
- **Logging.** How the app configures logging (a `LOGGING` dict, a logger factory, a framework default), where it writes, and which of its records are written inside a request.
- **Secrets on the wire.** Routes whose path or query carries a token (password reset, magic links, signed downloads, webhook secrets), headers that carry credentials, and queries whose literal values are sensitive.
- **The stack.** The language runtime and framework versions; then answer the questions in references/setup.md (Learning the stack) before you design. An example in parentheses here only illustrates a rule.

### 2. Design

1. **One telemetry module**, named like the app's other infrastructure code, that builds the resource, the three providers and their OTLP exporters, starts the instrumentations, and registers shutdown. Entry points start it; nothing else does. Spans for jobs and commands (item 4) are started where those run, through a helper the module exports.
2. **The start point in each entry point**, following references/setup.md, Rules on every stack: before the instrumented object is built, after any fork, after the environment file.
3. **The resource:** `service.name` and `service.version` from the app itself, `deployment.environment.name` from its existing environment setting, all overridable through `OTEL_SERVICE_NAME` and `OTEL_RESOURCE_ATTRIBUTES`. Check the override really wins: some SDKs let attributes set in code beat the environment's, so merge the environment's last.
4. **Instrumentations:** the framework's HTTP server instrumentation, the database drivers in use, and outbound HTTP clients. Work outside a request gets a span of its own, so its queries and log records share one trace instead of arriving as orphan spans: each job inside the span its instrumentation starts or, where the job library has none, one the module starts named for the job, by wrapping the function that runs each job; and each CLI or management command in one span named for the command. A scheduler's own polling and queries made at startup stay orphan spans; leave them. Add an instrumentation only for a library the app uses, and leave out the ones that only add noise (file system, DNS, every middleware as its own span) unless the user asks.
5. **Logs:** a handler or bridge that forwards the app's existing log records to the logger provider at the app's current level, beside the handlers it already has, never instead of them.
   - **Where it attaches.** Where the app applies a logging configuration, which replaces the handlers already there, add the bridge to that configuration as a handler: on the root, and on every logger that doesn't propagate to it.
   - **What it leaves out.** Access loggers, whose lines repeat the server span and carry the raw URL, tokens included; where access lines share a logger with other lines, a filter on the bridge drops them by their shape. Development stand-ins that log a message's text (a mail transport that prints each email). The exporter's own loggers.
   - **Values it can't encode** (a request object a framework puts in a record's extras) would print an error per record: hand the bridge a copy without them, only for a record that holds one, never changing the record the console handler prints.
6. **A seam for the request context:** where the HTTP instrumentation takes a request hook and a response hook, pass one function each that runs a list other modules can add to, each call guarded. The other trappsec skills write the caller's identity on the server span through it.
7. **Defaults:** batching processors, parent-based always-on sampling (the SDK default; add no sampler), the stable HTTP semantic conventions, health checks and static files excluded, the exporter's own requests left out of the outbound HTTP instrumentation (or they show up as client spans and metrics), no body or header capture.

### 3. Present the plan

Unless the user already told you to go ahead, show the plan and wait:

| Entry point | Where the SDK starts | Instrumentations | Log bridge | Notes |
|---|---|---|---|---|

Below it: your answers to the research questions, each with where you found it; the packages and versions you will add, the environment variables the user will set in production, and anything you will leave out with its reason.

### 4. Implement

- **Add the packages to the app's own dependency file and lockfile**, pinned the way the app pins its others (a workspace catalog, a minimum release age), with every OpenTelemetry package at versions released together (references/setup.md). This is the one trappsec skill that adds dependencies; say so in the plan.
- **Off until configured.** The module returns at once, before importing the SDK, unless an OTLP endpoint is set (`OTEL_EXPORTER_OTLP_ENDPOINT` or a per-signal one) and `OTEL_SDK_DISABLED` isn't `true`. Build a signal's exporter only when its own or the general endpoint is set; otherwise it falls back to the SDK's default address and fails every batch. An open-source or self-hosted app then sends nothing by default, and its tests run without telemetry unless a test turns it on.
- **Configuration through the standard variables.** Endpoint, headers, protocol, sampler, resource and export intervals come from `OTEL_*` variables. Never write an endpoint, an API key or an auth header into the repo: an `OTEL_EXPORTER_OTLP_HEADERS` value is a secret and lives where the app's other secrets live.
- **Initialize once per process.** Guard against a second call.
- **Shut down on every exit path, once, within a bounded time.** Register one shutdown that flushes all three providers with a timeout of a few seconds in total (where the SDK's providers register their own, keep only one of the two), so a short-lived command or a recycled worker neither loses its last batch nor hangs on an unresponsive backend. Code that ends the process itself (an exit call deep in a library) can skip registered shutdown: flush before it where the app owns the call, and report it where it doesn't.
- **Never let telemetry break the app.** The module catches its own errors and the app carries on. When an endpoint is set and something failed to start (an instrumentation, an exporter), it logs one warning at startup, so the operator knows telemetry is partly off; when none is set, it logs nothing.
- **Keep secrets off the wire.** Leave body and header capture off. For routes with a token in the path or query (a reset link, an invitation, an OAuth callback's `code`), a hook overwrites each URL attribute the instrumentation filled on the server span: the path with the route template, which is known only after routing (write it in the response hook, or resolve the path yourself), and the value of every query key that names a secret (`code`, `state`, `token`, `key`, `signature`, `password`) with a fixed marker. Do the same for outbound client spans (`url.full` with an `api_key`), and for the framework's own log lines that quote the path (`Not Found: /reset/<token>/`). Report a database instrumentation that records statement parameters, and turn that off.
- **Client address.** Behind a proxy, the instrumentation's `client.address` is the proxy's address or the first `X-Forwarded-For` entry, which the caller controls. Leave it, and report it: the other skills' request-context module writes the address the app resolves.
- **Inbound trace context.** Keep the default, and act on the answer to question 3 as references/setup.md describes, as a separate decision.
- **Document it beside the code.** List the environment variables, what each signal contains, and how to switch it off, in the module's own docstring or comment and in the app's existing setup documentation.

### 5. Verify

These checks are the authority on whether the setup works, on any stack. When one disagrees with an example in this skill, the documentation or what you expected, the check wins: find out why in the installed code, fix the setup, and say in the report what was different.

1. **Project checks.** Lint, type checks and the app's existing tests pass, with no endpoint set; the checks below cover the endpoint set. Type checks matter here: an API remembered from an older release can build a component that silently does nothing.
2. **Off by default.** With no endpoint set, the app starts, imports no exporter, opens no connection and prints nothing new.
3. **End to end.** Point the app at a local Collector with a debug exporter, a small OTLP receiver outside the repo where no Collector can run, or the user's backend, and send one probe request that writes a log record from the app's own code. Find, where the telemetry lands:
   - the server span with `http.request.method`, `http.route` (the template, not the raw path), `url.path`, `http.response.status_code`, `client.address` and `user_agent.original`;
   - its database and outbound child spans;
   - the log record, with the same trace and span IDs;
   - one log record emitted with an event name through the Logs API, from a throwaway probe;
   - the HTTP server duration metric, after one export interval.
   Run the probe through the server production uses where it can run locally, since a development server can pass the instrumentation fewer request facts and leave attributes out. Turn the SDK's own error reporting up while you do, the way your research found it reports; most SDKs say nothing about a dropped record by default.
4. **Exclusions.** A health check and a static file make no span. Exclusion patterns are often matched against the full URL, not the path, so test them rather than read them.
5. **Every entry point.** Run each distinct start point once with the endpoint set (one management command proves the command runner; add each custom command that runs in production), and find its spans and log records; a command that exits at once still delivers its last batch.
6. **Backend down.** Point the endpoint at a closed port, then at an address that accepts connections and never answers: requests return the same responses at the same latency, a command still exits within a few seconds, and nothing goes back through the exporter. The exporter may print one failure line per batch interval for each signal; that is the operator's signal that export is failing, so leave it, but there must be none per request. Say so in the report.
7. **Nothing leaks.** Search the spans, log records and metrics from your runs for tokens, cookies, auth headers, passwords, request bodies and personal data (emails, names), including what the app logs under its development settings.
8. **The prerequisite holds.** Walk the list in references/setup.md: each item is met, with the evidence you found.

### 6. Report

- Each entry point, where the SDK starts in it, and what it emits.
- The packages added and their versions, and the environment variables to set in production, marking which are secrets.
- What each signal contains and what it deliberately leaves out.
- Gaps: processes or libraries left uninstrumented, and why.
- Recommendations for the pipeline the user runs, which this skill doesn't change: a Collector near the app for batching, retries and routing; tail sampling there rather than in the app, keeping every trace marked `security.flagged`; metric exemplars off if traces may carry client addresses (`OTEL_METRICS_EXEMPLAR_FILTER=always_off`).
- Next steps: add-auditing, add-detection and add-deception can now run on this app.

## Reference files

- **references/setup.md**: the prerequisite the other trappsec skills check for, shared with them word for word; the research questions that teach you the app's stack; the rules that hold on every stack; inbound trace context; and a local Collector or receiver for verification.
