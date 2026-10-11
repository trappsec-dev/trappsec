"""Litestar integration.

Design notes
------------
* Traps are registered as real Litestar routes (specificity-based router, R2).
  A trap that exactly duplicates an application route (same path template and a
  shared method) makes ``bootstrap()`` raise instead of shadowing/replacing it.
* Watches are matched on the *resolved* route: the app's own routing table is
  asked which route handler / ``path_template`` a request resolves to (the same
  cached lookup Litestar performs for the request), so a watch on
  ``/users/{id}`` fires for ``/users/5`` but not for a static ``/users/me`` route.
  This uses ``app.asgi_router.handle_routing`` (internal but stable across the
  2.x series); if it is unavailable an error is logged once and watches are
  inactive rather than falling back to raw-URL guessing.
* Only requests that resolve to a watched route are touched. The body is only
  buffered when the watch has body fields and the declared ``Content-Length`` is
  below ``MAX_INSPECT_BYTES`` (any content type: a JSON body is sniffed even
  when it is not labelled as JSON); otherwise the request streams untouched.
  When a body is rewritten the ``Content-Length`` header is updated to match.
* ``identify_user`` and callable defaults receive a real ``litestar.Request``
  built on an isolated copy of the ASGI scope (so cookies/headers work and no
  parsed state leaks into the application's own ``Request``). Litestar
  authentication middleware runs *inside* the route stack, after this hook, so
  ``request.user`` / ``request.auth`` are not populated; identify from headers
  or cookies.
* ``bootstrap()`` is public, idempotent and thread-safe; it runs from
  ``on_startup`` and lazily on the first request (e.g. ``TestClient`` used
  without a lifespan).
"""
import json
import re
import threading
from functools import lru_cache

from . import _formbody, _jsonbody
from ._version import warn_if_older

MAX_INSPECT_BYTES = 10 * 1024 * 1024

_TYPED_PARAM_RE = re.compile(r"\{([^}:]+):[^}]+\}")


@lru_cache(maxsize=1024)
def _normalize_template(path):
    path = _TYPED_PARAM_RE.sub(r"{\1}", str(path))
    if not path.startswith("/"):
        path = "/" + path
    if len(path) > 1:
        path = path.rstrip("/")
    return path


def _replay(messages, fallback=None):
    """A fresh ASGI ``receive`` that yields ``messages`` and then ``fallback()`` / an empty body."""
    it = iter(list(messages))

    async def receive():
        try:
            return next(it)
        except StopIteration:
            if fallback is not None:
                return await fallback()
            return {"type": "http.request", "body": b"", "more_body": False}

    return receive


class LitestarIntegration:
    def __init__(self, ts, app):
        self.ts = ts
        self.app = app
        self.watch_map = {}  # normalized route template -> watch, built once (R13)
        self._lock = threading.RLock()
        self._bootstrapped = False
        warn_if_older(ts.logger, "litestar", (2, 13), "honey fields may not be detected or stripped")
        self._bootstrap_error = None
        self._routing_warned = False

        if not self.ts.identity.ip:
            self.ts.identity.ip = lambda r: r.client.host if r.client else "0.0.0.0"

        self.ts.request.path = lambda r: r.url.path
        self.ts.request.user_agent = lambda r: r.headers.get("user-agent", "unknown")
        self.ts.request.method = lambda r: r.method

        self.app.on_startup.append(self._startup)
        self._patch_asgi_handler()

    # ------------------------------------------------------------------ setup
    def _startup(self):
        self.bootstrap()

    def bootstrap(self):
        """Install traps and watches. Public, idempotent and thread-safe."""
        with self._lock:
            if not self._bootstrapped:
                self._bootstrapped = True  # never half-install twice
                try:
                    self._inject_traps()    # R10: traps before watches
                    self._setup_watches()
                except Exception as e:
                    self._bootstrap_error = e
            if self._bootstrap_error is not None:
                raise self._bootstrap_error

    def _inject_traps(self):
        from litestar import Request, Response
        from litestar.handlers import HTTPRouteHandler

        csrf_config = getattr(self.app, "csrf_config", None)
        csrf_exclude_key = getattr(csrf_config, "exclude_from_csrf_key", None) or "exclude_from_csrf"
        from litestar.routes import HTTPRoute

        ts = self.ts
        traps = ts.traps
        if not traps:
            return

        existing = {}
        for route in self.app.routes:
            if isinstance(route, HTTPRoute):
                existing.setdefault(_normalize_template(route.path_format), set()).update(
                    m.upper() for m in route.methods)

        def make_handler(_trap):
            async def trap_handler(request: Request) -> Response:
                try:  # C1: a failing callback must still yield the decoy response
                    body, cfg = ts._trigger_trap_event(request, _trap)
                except Exception as e:
                    ts.logger.error("trappsec trap error: %s", e)
                    body, cfg = ts._trap_fallback(_trap)
                if not isinstance(body, (str, bytes)):
                    body = json.dumps(body, default=str, separators=(",", ":"))
                if isinstance(body, str):
                    body = body.encode("utf-8")  # bytes are sent verbatim for any media type
                return Response(content=body, status_code=cfg["status_code"], media_type=cfg["mime_type"])

            return trap_handler

        for idx, trap in enumerate(traps):
            methods = {m.upper() for m in trap["methods"]}
            clash = methods & existing.get(_normalize_template(trap["path"]), set())
            if clash:
                raise RuntimeError(
                    f"trappsec: trap {sorted(clash)} {trap['path']} duplicates an existing "
                    f"application route; refusing to shadow or replace it")
            route_handler = HTTPRouteHandler(
                path=trap["path"],
                http_method=trap["methods"],
                include_in_schema=False,
                name=f"trappsec_trap_{idx}",
                # R22: CSRF protection must not turn a trap into a silent 403.
                opt={csrf_exclude_key: True},
            )(make_handler(trap))
            self.app.register(route_handler)

        self._clear_routing_cache()

    def _clear_routing_cache(self):
        try:
            self.app.asgi_router.handle_routing.cache_clear()
        except Exception:
            pass

    def _setup_watches(self):
        self.watch_map = {_normalize_template(w["path"]): w for w in self.ts.watches}

    # ------------------------------------------------------------ request path
    def _resolve_watch(self, scope):
        """R1: resolve the request to its route and look the route template up."""
        from litestar.utils import normalize_path

        path = scope.get("path", "/")
        root_path = scope.get("root_path", "")
        if root_path:
            path = path.split(root_path, maxsplit=1)[-1]
        try:
            _, _, _, _, template = self.app.asgi_router.handle_routing(
                path=normalize_path(path), method=scope.get("method"))
        except (AttributeError, TypeError, ValueError) as e:
            if not self._routing_warned:
                self._routing_warned = True
                self.ts.logger.error(
                    "trappsec: cannot resolve Litestar routes (unsupported litestar version?); "
                    "watches are inactive: %s", e)
            return None
        except Exception:
            return None  # unmatched path / method not allowed: nothing to watch
        return self.watch_map.get(_normalize_template(template))

    def _patch_asgi_handler(self):
        original_handler = self.app.asgi_handler

        async def wrapped(scope, receive, send):
            if scope.get("type") != "http":
                return await original_handler(scope, receive, send)

            if not self._bootstrapped:
                try:
                    self.bootstrap()
                except Exception as e:  # C1: keep serving the application
                    self.ts.logger.error("trappsec: bootstrap failed: %s", e)

            watch = None
            if self.watch_map:
                try:
                    watch = self._resolve_watch(scope)
                except Exception as e:
                    self.ts.logger.error("trappsec watch resolution error: %s", e)
            if watch is None:
                return await original_handler(scope, receive, send)

            try:
                receive = await self._handle_watch(scope, receive, watch)
            except Exception as e:  # C1: request continues unmodified
                self.ts.logger.error("trappsec watch error: %s", e)
            return await original_handler(scope, receive, send)

        self.app.asgi_handler = wrapped

    async def _read_body(self, receive, headers):
        """Buffer the body only if it is worth inspecting; returns (messages, body) or None."""
        try:
            length = int(headers.get("content-length", "0") or 0)
        except ValueError:
            length = 0
        if length > MAX_INSPECT_BYTES:
            return None
        messages, chunks, total = [], [], 0
        while True:
            message = await receive()
            messages.append(message)
            if message.get("type") != "http.request":
                break  # http.disconnect: hand everything back as-is
            chunk = message.get("body", b"")
            total += len(chunk)
            chunks.append(chunk)
            if not message.get("more_body", False):
                break
            if total > MAX_INSPECT_BYTES:
                # too large to inspect: replay what was read, then stream the rest
                return messages, None
        return messages, b"".join(chunks)

    async def _handle_watch(self, scope, receive, watch):
        """Inspect (and strip) the watched fields. Returns the ``receive`` to hand to the app."""
        from litestar import Request

        headers = {k.decode("latin1").lower(): v.decode("latin1") for k, v in scope.get("headers", [])}
        query_fields = watch.get("query_fields") or {}
        body_fields = watch.get("body_fields") or {}

        messages, body = [], None
        app_receive = receive
        if body_fields:
            read = await self._read_body(receive, headers)
            if read is not None:
                messages, body = read
                app_receive = _replay(messages, fallback=receive)

        # Real Request on an isolated scope copy: cookies/headers work and nothing it
        # caches (body, json, ...) can leak into the application's own Request.
        iso = dict(scope)
        iso["state"] = {k: v for k, v in dict(scope.get("state") or {}).items() if k != "_ls_connection_state"}
        request = Request(scope=iso, receive=_replay(messages))

        found = []
        new_qs = None
        new_body = None

        try:
            if query_fields:
                qs = scope.get("query_string", b"")
                if qs:
                    mod, new_qs = _formbody.inspect_urlencoded(
                        self.ts, qs, query_fields, request, source="query")
                    found.extend(mod)

            if body:
                new_body = self._inspect_body(body, headers, body_fields, request, found)
        except Exception as e:
            self.ts.logger.error("trappsec watch inspection error: %s", e)
            new_qs = new_body = None
            if not found:
                return app_receive

        # Strip first, notify second: a failing callback can never leave the field in place.
        if new_qs is not None:
            scope["query_string"] = new_qs
        if new_body is not None:
            new_ct = _jsonbody.fix_charset(headers.get("content-type", ""))

            def _rewrite(k, v):
                name = k.decode("latin1").lower()
                if name == "content-length":
                    return k, str(len(new_body)).encode("latin1")
                if name == "content-type" and new_ct is not None and \
                        _jsonbody.media_type(headers.get("content-type", "")) not in _jsonbody.FORM_MEDIA:
                    return k, new_ct.encode("latin1")
                return k, v
            scope["headers"] = [_rewrite(k, v) for k, v in scope.get("headers", [])]
            app_receive = _replay([{"type": "http.request", "body": new_body, "more_body": False}])

        if found:
            try:
                self.ts._trigger_watch_event(request, found)
            except Exception as e:
                self.ts.logger.error("trappsec watch event error: %s", e)
        return app_receive

    def _inspect_body(self, body, headers, rules, request, found):
        """Returns the rewritten body bytes if something was stripped, else None."""
        ctype = headers.get("content-type", "")
        media = _jsonbody.media_type(ctype)

        if media not in _jsonbody.FORM_MEDIA:
            # request.json() ignores Content-Type, so sniff any non-form body.
            if _jsonbody.is_json_media(media):
                try:
                    obj = _jsonbody.parse_json_bytes(body)
                except Exception:
                    return None
            else:
                obj = _jsonbody.sniff_json(body)
                if obj is None:
                    return None
            obj, mod, touched = self.ts._detect_honey_fields(obj, rules, request)
            found.extend(mod)
            return _jsonbody.serialize(obj) if touched else None

        if media == "application/x-www-form-urlencoded":
            mod, new_body = _formbody.inspect_urlencoded(self.ts, body, rules, request)
        else:
            mod, new_body = _formbody.inspect_multipart(self.ts, body, ctype, rules, request)
        found.extend(mod)
        return new_body
