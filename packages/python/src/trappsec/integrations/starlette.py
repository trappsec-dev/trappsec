import json
import threading
import uuid
from contextlib import asynccontextmanager
from urllib.parse import parse_qsl, urlencode

from . import _jsonbody


class TrapConflictError(RuntimeError):
    """A trap path+method exactly duplicates an existing application route."""


_ERRORS = "surrogateescape"
_TAG = "__trappsec_watch__"
MAX_SNIFF_BYTES = 10 * 1024 * 1024


def _mime(headers):
    for k, v in headers:
        if k == b"content-type":
            return v.decode("latin-1").split(";")[0].strip().lower()
    return ""


def _set_header(headers, name, value):
    out = [(k, v) for k, v in headers if k != name]
    out.append((name, value))
    return out


class _Bootstrapper:
    """Pure ASGI middleware: lazily bootstraps trappsec on the first request."""

    def __init__(self, app, integration=None):
        self.app = app
        self.integration = integration

    async def __call__(self, scope, receive, send):
        integ = self.integration
        if integ is not None and not integ._bootstrapped:
            integ._ensure_bootstrapped()
        await self.app(scope, receive, send)


class StarletteIntegration:
    def __init__(self, ts, app):
        self.ts = ts
        self.app = app
        self.watch_map = {}
        self._bootstrapped = False
        self._lock = threading.RLock()

        if not self.ts.identity.ip:
            self.ts.identity.ip = lambda r: r.client.host if r.client else "0.0.0.0"

        self.ts.request.path = lambda r: str(r.url.path)
        self.ts.request.user_agent = lambda r: r.headers.get("user-agent", "unknown")
        self.ts.request.method = lambda r: r.method

        self._patch_startup()

    # ------------------------------------------------------------------ public

    def bootstrap(self):
        """Install traps and watches. Idempotent and thread-safe."""
        if self._bootstrapped:
            return
        with self._lock:
            if self._bootstrapped:
                return
            self.inject_traps()
            self.setup_watches()
            self._bootstrapped = True

    def _ensure_bootstrapped(self):
        try:
            self.bootstrap()
        except TrapConflictError:
            raise
        except Exception as e:
            self.ts.logger.error("trappsec bootstrap failed: %s", e)
            self._bootstrapped = True  # do not retry on every request

    # ------------------------------------------------------------------- traps

    def _iter_routes(self, routes, prefix=""):
        """Yield (full_path, route) for every plain route, descending into mounts."""
        for route in routes:
            sub = getattr(route, "routes", None)
            if sub is not None and not hasattr(route, "endpoint"):
                mount_prefix = prefix + (getattr(route, "path", "") or "")
                for item in self._iter_routes(list(sub), mount_prefix):
                    yield item
            elif hasattr(route, "path") and hasattr(route, "app") and hasattr(route, "methods"):
                yield prefix + route.path, route

    def _check_conflicts(self, traps):
        existing = {}
        for full_path, route in self._iter_routes(self.app.router.routes):
            existing.setdefault(full_path, []).append(route)

        for trap in traps:
            wanted = set(m.upper() for m in trap["methods"])
            for route in existing.get(trap["path"], []):
                methods = route.methods
                if methods is None or set(methods) & wanted:
                    raise TrapConflictError(
                        "trappsec error: trap %s %s duplicates an existing route."
                        % (sorted(wanted), trap["path"])
                    )

    def _fallback(self, trap):
        cfg = trap["response.unauthenticated"]
        body = cfg.get("response_body")
        if callable(body):
            body = {}
        if not isinstance(body, (str, bytes)):
            body = json.dumps(body, default=str)
        return body, cfg

    def _make_trap_endpoint(self, trap):
        from starlette.responses import Response

        async def endpoint(req):
            try:
                response_body, response_config = self.ts._trigger_trap_event(req, trap)
            except Exception as e:
                self.ts.logger.error("trappsec trap handling failed: %s", e)
                response_body, response_config = self._fallback(trap)
            return Response(
                response_body,
                status_code=response_config["status_code"],
                media_type=response_config["mime_type"],
            )

        return endpoint

    def _build_trap_routes(self, traps):
        from starlette.routing import Route

        return [
            Route(
                trap["path"],
                endpoint=self._make_trap_endpoint(trap),
                methods=trap.get("methods", ["GET", "POST"]),
                name="trappsec_%d" % idx,
            )
            for idx, trap in enumerate(traps)
        ]

    def inject_traps(self):
        traps = self.ts.traps
        self._check_conflicts(traps)
        # Prepend: Starlette routing is order based, traps must not be shadowed.
        self.app.router.routes = self._build_trap_routes(traps) + list(self.app.router.routes)

    # ----------------------------------------------------------------- watches

    def setup_watches(self):
        self.watch_map = {w["path"]: w for w in self.ts.watches}
        if not self.watch_map:
            return
        self._wrap_routes(self.app.router.routes)

    def _wrap_routes(self, routes):
        # Wrapping route.app at the ASGI level works for every route flavour
        # (sync/async functions, HTTPEndpoint classes, FastAPI APIRoute) and
        # needs no knowledge of how the endpoint consumes the request.
        # Mounts of opaque ASGI apps (e.g. StaticFiles) cannot be descended into.
        for full_path, route in self._iter_routes(routes):
            watch = self.watch_map.get(full_path)
            if watch is None or getattr(route.app, _TAG, False):
                continue
            route.app = self._make_watch_app(route.app, watch)

    def _make_watch_app(self, inner, watch):
        integration = self

        async def watch_app(scope, receive, send):
            try:
                scope, receive = await integration._inspect(scope, receive, watch)
            except Exception as e:
                integration.ts.logger.error("trappsec watch failed: %s", e)
            await inner(scope, receive, send)

        setattr(watch_app, _TAG, True)
        return watch_app

    async def _inspect(self, scope, receive, watch):
        """Detect and strip watched fields. Returns the (scope, receive) to dispatch with.

        If anything fails after the request body has been consumed, the original
        messages are replayed so the application still sees an intact request.
        """
        from starlette.requests import Request

        if scope.get("type") != "http":
            return scope, receive

        ts = self.ts
        found_fields = []
        query_fields = watch["query_fields"]
        body_fields = watch["body_fields"]
        new_scope = scope
        new_receive = receive

        if query_fields:
            qs = scope.get("query_string", b"")
            if qs:
                pairs = parse_qsl(qs.decode("latin-1"), keep_blank_values=True, errors=_ERRORS)
                q = {}
                for k, v in pairs:
                    q.setdefault(k, []).append(v)
                q, mod, touched = ts._detect_honey_fields(
                    q, query_fields, Request(scope), source="query")
                found_fields.extend(mod)
                if touched:
                    new_scope = dict(new_scope)
                    new_scope["query_string"] = urlencode(
                        q, doseq=True, errors=_ERRORS).encode("latin-1")

        if body_fields:
            headers = scope.get("headers", [])
            mime = _mime(headers)
            kind = None
            if mime == "application/json" or mime.endswith("+json"):
                kind = "json"
            elif mime == "application/x-www-form-urlencoded":
                kind = "urlencoded"
            elif mime == "multipart/form-data":
                kind = "multipart"
            else:
                # request.json() ignores Content-Type: sniff any other body.
                kind = "sniff"

            if kind:
                messages = []
                chunks = []
                total = 0
                oversized = False
                while True:
                    message = await receive()
                    messages.append(message)
                    if message["type"] != "http.request":
                        break
                    chunk = message.get("body", b"")
                    chunks.append(chunk)
                    total += len(chunk)
                    if not message.get("more_body", False):
                        break
                    if kind == "sniff" and total > MAX_SNIFF_BYTES:
                        oversized = True  # too big to be worth sniffing: replay and stream
                        break
                raw = b"".join(chunks)

                def replay(msgs, original):
                    pending = list(msgs)

                    async def _receive():
                        if pending:
                            return pending.pop(0)
                        return await original()
                    return _receive

                new_receive = replay(messages, receive)
                req = Request(new_scope)
                new_body = None
                try:
                    if oversized:
                        pass
                    elif kind in ("json", "sniff"):
                        if kind == "json":
                            data = _jsonbody.parse_json_bytes(raw)
                        else:
                            data = _jsonbody.sniff_json(raw)
                        if data is not None:
                            data, mod, touched = ts._detect_honey_fields(
                                data, body_fields, req, source="body")
                            found_fields.extend(mod)
                            if touched:
                                new_body = _jsonbody.serialize(data)
                                ct = _jsonbody.fix_charset(
                                    next((v.decode("latin-1") for k, v in headers
                                          if k == b"content-type"), ""))
                                if ct is not None:
                                    headers = _set_header(headers, b"content-type", ct.encode("latin-1"))
                    elif kind == "urlencoded":
                        form = {}
                        for k, v in parse_qsl(raw.decode("utf-8", _ERRORS),
                                              keep_blank_values=True, errors=_ERRORS):
                            form.setdefault(k, []).append(v)
                        form, mod, touched = ts._detect_honey_fields(
                            form, body_fields, req, source="body")
                        found_fields.extend(mod)
                        if touched:
                            new_body = urlencode(form, doseq=True, errors=_ERRORS).encode("utf-8", _ERRORS)
                    else:
                        new_body, new_headers, mod = await self._inspect_multipart(
                            new_scope, new_receive, raw, headers, body_fields, req)
                        found_fields.extend(mod)
                        if new_body is not None:
                            headers = new_headers
                except Exception as e:
                    ts.logger.error("error inspecting %s body: %s", kind, e)
                    new_body = None

                if new_body is not None:
                    headers = _set_header(headers, b"content-length", str(len(new_body)).encode("ascii"))
                    new_scope = dict(new_scope)
                    new_scope["headers"] = headers
                    sent = []

                    async def stripped_receive(_orig=receive):
                        if not sent:
                            sent.append(True)
                            return {"type": "http.request", "body": new_body, "more_body": False}
                        return await _orig()
                    new_receive = stripped_receive

        if found_fields:
            try:
                ts._trigger_watch_event(Request(new_scope), found_fields)
            except Exception as e:
                ts.logger.error("error triggering watch event: %s", e)

        return new_scope, new_receive

    async def _inspect_multipart(self, scope, receive, raw, headers, body_fields, req):
        """Parse multipart, detect/strip watched fields, re-serialise only if touched.

        Returns (new_body_or_None, new_headers, found_fields).
        """
        from starlette.datastructures import UploadFile
        from starlette.requests import Request

        pending = [{"type": "http.request", "body": raw, "more_body": False}]

        async def parse_receive():
            if pending:
                return pending.pop(0)
            return {"type": "http.disconnect"}

        form = await Request(scope, parse_receive).form()
        try:
            items = list(form.multi_items())
            data = {}
            for k, v in items:
                data.setdefault(k, []).append(v)
            data, mod, touched = self.ts._detect_honey_fields(
                data, body_fields, req, source="body")
            if not touched:
                return None, headers, mod

            boundary = uuid.uuid4().hex
            parts = []

            def esc(s):
                return (str(s).replace("\r", "%0D").replace("\n", "%0A").replace('"', "%22"))

            for k, v in items:
                if k not in data:
                    continue
                head = '--%s\r\nContent-Disposition: form-data; name="%s"' % (boundary, esc(k))
                if isinstance(v, UploadFile):
                    await v.seek(0)
                    content = await v.read()
                    head += '; filename="%s"\r\nContent-Type: %s\r\n\r\n' % (
                        esc(v.filename or ""), v.content_type or "application/octet-stream")
                else:
                    content = str(v).encode("utf-8")
                    head += "\r\n\r\n"
                parts.append(head.encode("utf-8") + content + b"\r\n")
            parts.append(("--%s--\r\n" % boundary).encode("ascii"))

            new_headers = _set_header(
                headers, b"content-type",
                ("multipart/form-data; boundary=%s" % boundary).encode("ascii"))
            return b"".join(parts), new_headers, mod
        finally:
            await form.close()

    # ----------------------------------------------------------------- startup

    def _patch_startup(self):
        # Lazy bootstrap on the first request/lifespan scope of any ASGI server or
        # test client. A middleware is used because it is the only hook that sees
        # the very first scope; the lifespan wrapper below covers Router-only use.
        from starlette.middleware import Middleware

        user_middleware = getattr(self.app, "user_middleware", None)
        if user_middleware is not None:
            user_middleware.insert(0, Middleware(_Bootstrapper, integration=self))
            # Force the middleware stack to be rebuilt if the app was already called.
            if getattr(self.app, "middleware_stack", None) is not None:
                self.app.middleware_stack = None
        else:
            self.ts.logger.warning(
                "trappsec: app has no user_middleware; traps are installed on lifespan "
                "startup only. Call sentry.bootstrap() manually if lifespan is not run.")

        router = self.app.router
        original_lifespan = getattr(router, "lifespan_context", None)
        if original_lifespan is None:
            return

        @asynccontextmanager
        async def wrapped_lifespan(app_instance):
            self._ensure_bootstrapped()
            async with original_lifespan(app_instance) as state:
                yield state

        router.lifespan_context = wrapped_lifespan
