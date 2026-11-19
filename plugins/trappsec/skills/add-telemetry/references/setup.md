# Setup

What add-telemetry must leave in place, how to learn the app's stack, and the rules that hold on every stack.

## The prerequisite it meets

add-auditing, add-deception and add-detection each stop unless the app already has the list below. It is shared with them word for word, so this skill finishes exactly where they start:

<!-- BEGIN PREREQUISITE CORE: identical in add-auditing, add-deception, add-detection and add-telemetry -->
- an OpenTelemetry SDK with a tracer provider and a logger provider, both exported (usually OTLP to a Collector), initialized in every entry point that will emit: the web server, workers, each CLI, script or management command;
- a server span for every request, from HTTP server instrumentation or, on a function platform, the invocation span;
- log records emitted in a request carrying its trace and span IDs (test with a record your own code emits; framework access lines are often written after the span ends);
- a way to emit a log record with an event name through the Logs API.
<!-- END PREREQUISITE CORE -->

Beyond the list, the other skills want the server span to carry `http.request.method`, `http.route`, `url.path`, `http.response.status_code`, `client.address` and `user_agent.original`, which the stable HTTP semantic conventions give, and a request and a response hook they can add to (Design step 6).

## Learning the stack

This skill names no stack's packages or APIs, because they change between releases and an app on a stack nobody listed deserves the same result. Learn them for this app from the OpenTelemetry project's current documentation and each instrumentation's README, then confirm each version-specific answer (hook timing, constructor shapes, option names, dependency pins) in the installed code at the versions you install; read the app's own code for how it starts, forks, loads its environment and configures logging. The installed code, the type checker and the checks overrule the documentation.

Where no official instrumentation exists for the framework, the server span comes from wrapping the app's request handling at its outermost layer with the SDK's tracer, as the instrumentations for other frameworks do; say so in the plan.

Answer each question below; in the plan, give the answers that shaped a design choice, with their source:

- **Packages and versions.** Which SDK, OTLP exporter and instrumentation packages, and which versions were released together. A package's own dependency pins say which releases match (an instrumentation that requires one exact semantic-conventions release matches the SDK that requires the same one).
- **Starter or hand-built.** Whether to use the SDK's all-in-one starter, where there is one, or providers you build yourself, and which `OTEL_*` variables each reads: hand-built providers often ignore the sampler, batch and interval variables the starter reads, so wire the ones you need from the environment yourself.
- **Attaching the HTTP instrumentation.** Does it patch on import, wrap an object as it is built, or need a preload flag or agent on the command line? What must not be imported or built before it?
- **Attribute names.** Whether the instrumentation writes the stable HTTP semantic conventions by default, or needs an opt-in for them.
- **Hooks.** Which hooks run inside the server span at the start of a request and once the response is known, and which of the request's facts (the matched route, the query) each one can see. A hook's name doesn't say when it runs (a "response" hook can run as the request starts): read where the instrumentation calls it.
- **Logs.** How the app's log records reach the logger provider, whether applying the app's logging configuration removes that handler, and which loggers don't propagate to the root.
- **Event names.** How code emits a log record with an event name through the Logs API, and whether the logging bridge can set one too.
- **The SDK's own errors.** How it reports them (an environment variable some SDKs read and others ignore, or its own logger), so you can turn them up while verifying.
- **Shutdown.** Whether the providers register their own shutdown at exit.
- **Resource.** Whether attributes set in code or from the environment win when both name the same key.
- **Exclusions.** What the instrumentation's excluded-URL setting is matched against: the path, or the full URL with its scheme, host and trailing characters.
- **Development and production servers.** Which request attributes each one passes the instrumentation; a development server often passes fewer.

## Rules on every stack

- **Start before the instrumented object is built.** Instrumentations patch libraries as they are imported or wrap objects as they are built. Start the SDK at the top of each entry point, or through the runtime's preload flag, never from the app's own startup code once the framework is up. Where the framework can't be kept out of the import chain, what matters is starting before the object the instrumentation wraps (the middleware stack, the router, the server) is built.
- **After the fork.** A pre-forking server forks after the parent has imported the app, and the exporter's background threads don't survive the fork. Initialize in each worker: in the server's post-fork hook, or by letting each worker import the entry point itself. A development server's file-watching parent may initialize too; skip it there if its export is noise.
- **After the environment file.** Where the app loads `OTEL_*` values from a file, the SDK reads them after that file is loaded.
- **Framework error lines may fall outside the span.** A framework that logs a request's failure after the server span ends writes a record with no trace. Report it; don't move the framework's logging.
- **On a function platform**, start at module load, once per cold start, and flush the tracer and logger providers at the end of every invocation, error paths included: the process freezes after the response, and unflushed batches are lost.

## Inbound trace context

HTTP server instrumentations take their parent from the caller's `traceparent` by default. For a service the organization's own traced services call, that is what joins their traces. For a public entry point it lets any caller choose the trace ID and, under the parent-based default sampler, whether the server span is sampled at all. The fix, when the user chooses it, is to ignore inbound context on public routes: a propagator setting for the server instrumentation only (an empty propagator, or a filter that drops the header before the instrumentation reads it), while keeping propagation on outbound calls. Never silently change it.

## A local Collector for verification

When the user has no backend yet, run a Collector with an OTLP receiver and the `debug` exporter at `detailed` verbosity, point `OTEL_EXPORTER_OTLP_ENDPOINT` at it (`http://localhost:4318` for OTLP over HTTP), and read the spans, log records and metrics from its output. Where no Collector can run (no container runtime, no binary), a small OTLP/HTTP receiver serves instead: a few dozen lines listening on port 4318 that decode `/v1/traces`, `/v1/logs` and `/v1/metrics` with an OTLP protobuf package and print them as JSON. Either one runs outside the app: nothing about it goes into the repo, and the committed configuration leaves the endpoint unset.
