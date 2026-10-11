"""Sanic integration.

Design notes
------------
* Traps are registered as real Sanic routes (Sanic is a specificity-based
  router, so static trap paths cannot be shadowed). An exact path+method
  duplicate of an application route makes ``bootstrap()`` raise (Sanic's own
  ``RouteExists``, re-raised with a trappsec message) instead of silently
  replacing either route.
* Watches run in a single ``on_request`` middleware that is registered when
  the integration is constructed. The middleware only looks at requests whose
  *resolved* route (``request.route``) has a watch. No global ``Request`` class
  patching is performed: when a watched field is stripped, only the affected
  request instance is modified (its parsed caches ``parsed_args`` /
  ``parsed_json`` / ``parsed_form`` / ``body`` and, for query strings, the
  private ``_parsed_url`` slot, which is the only way to keep
  ``request.query_string`` / ``query_args`` consistent; this is a Sanic
  internal, so it is guarded and covered by tests).
* ``request.args`` / ``request.form`` stay ``RequestParameters`` (``get`` returns
  the first value, ``getlist`` returns all values) because the cached objects
  are rebuilt from the original multi-value pairs.
* Setup is idempotent and thread-safe (``bootstrap()``). It runs from
  ``before_server_start`` and lazily on the first request as a safety net.
  Routes cannot be added once Sanic's router is finalised, so a lazy
  bootstrap that has to add traps after startup logs a loud warning if that
  fails; always let Sanic run ``before_server_start`` (it does for the real
  server, ``app.test_client`` and ``app.asgi_client``).
"""
import json
import re
import threading
from functools import lru_cache

from . import _formbody, _jsonbody
from ._version import warn_if_older

_PARAM_RE = re.compile(r"<([^:>]+):[^>]+>")


class SanicIntegration:
    def __init__(self, ts, app):
        self.ts = ts
        self.app = app
        self.watch_map = {}
        self._lock = threading.RLock()
        self._bootstrapped = False
        warn_if_older(ts.logger, "sanic", (24, 6), "query honey fields may not be detected or stripped")

        if not self.ts.identity.ip:
            # remote_addr is set only when Sanic trusts forwarded headers (PROXIES_COUNT /
            # FORWARDED_SECRET); otherwise use the socket peer address.
            self.ts.identity.ip = lambda r: r.remote_addr or r.ip or "0.0.0.0"

        self.ts.request.path = lambda r: r.path
        self.ts.request.user_agent = lambda r: r.headers.get("user-agent", "unknown")
        self.ts.request.method = lambda r: r.method

        self._install_hooks()

    # ------------------------------------------------------------------ setup
    def _install_hooks(self):
        # Registered once, at construction time, so routes registered before
        # Sentry was installed are covered and restarts do not stack middleware.
        @self.app.before_server_start
        async def trappsec_init(_app, _loop=None):
            self.bootstrap()

        @self.app.on_request
        async def trappsec_watcher(request):
            await self._on_request(request)

    def bootstrap(self):
        """Install traps and watches. Public, idempotent and thread-safe."""
        with self._lock:
            if self._bootstrapped:
                return
            self._bootstrapped = True  # never half-install twice
            self.inject_traps()
            self.setup_watches()

    def inject_traps(self):
        from sanic.response import HTTPResponse

        ts = self.ts

        def make_endpoint(trap):
            async def endpoint(request, **_params):
                try:
                    body, cfg = ts._trigger_trap_event(request, trap)
                except Exception as e:  # C1: serve the plain decoy
                    ts.logger.error("trappsec trap error: %s", e)
                    body, cfg = ts._trap_fallback(trap)
                if not isinstance(body, (str, bytes)):
                    body = json.dumps(body, default=str)
                return HTTPResponse(body=body, status=cfg["status_code"], content_type=cfg["mime_type"])

            return endpoint

        for idx, trap in enumerate(ts.traps):
            try:
                self.app.add_route(
                    make_endpoint(trap),
                    trap["path"],
                    methods=trap["methods"],
                    name=f"trappsec_trap_{idx}",
                )
            except Exception as e:
                if type(e).__name__ == "RouteExists":
                    raise RuntimeError(
                        f"trappsec: trap {trap['methods']} {trap['path']} duplicates an existing "
                        f"application route; refusing to shadow or replace it ({e})"
                    ) from e
                raise

    def setup_watches(self):
        self.watch_map = {self._normalize_route_pattern(w["path"]): w for w in self.ts.watches}

    @staticmethod
    @lru_cache(maxsize=1024)
    def _normalize_route_pattern(path):
        normalized = _PARAM_RE.sub(r"<\1>", str(path))
        if not normalized.startswith("/"):
            normalized = f"/{normalized}"
        if len(normalized) > 1:
            normalized = normalized.rstrip("/")
        return normalized

    # ------------------------------------------------------------ request path
    def _resolve_watch(self, request):
        route = getattr(request, "route", None)
        if route is None:
            return None  # 404: no route, nothing to watch (R1)
        for attr in ("uri", "path"):
            value = getattr(route, attr, None)
            if value:
                watch = self.watch_map.get(self._normalize_route_pattern(value))
                if watch:
                    return watch
        return None

    async def _on_request(self, request):
        try:
            if not self._bootstrapped:
                try:
                    self.bootstrap()
                except Exception as e:
                    self.ts.logger.error(
                        "trappsec: lazy bootstrap failed (traps may be missing; make sure "
                        "before_server_start runs): %s", e)
            if not self.watch_map:
                return
            watch = self._resolve_watch(request)
            if watch is None:
                return
            found = self._inspect(request, watch)
        except Exception as e:  # C1: never break the host request
            self.ts.logger.error("trappsec watch error: %s", e)
            return

        if found:
            try:
                self.ts._trigger_watch_event(request, found)
            except Exception as e:
                self.ts.logger.error("trappsec watch event error: %s", e)

    def _inspect(self, request, watch):
        found = []
        query_fields = watch.get("query_fields") or {}
        body_fields = watch.get("body_fields") or {}

        if query_fields:
            try:
                found.extend(self._inspect_query(request, query_fields))
            except Exception as e:
                self.ts.logger.error("trappsec query inspection error: %s", e)

        if body_fields:
            try:
                found.extend(self._inspect_body(request, body_fields))
            except Exception as e:
                self.ts.logger.error("trappsec body inspection error: %s", e)
        return found

    def _inspect_query(self, request, rules):
        qs = request.query_string
        if not qs:
            return []
        found, new_qs = _formbody.inspect_urlencoded(
            self.ts, qs.encode("utf-8"), rules, request, source="query")
        if new_qs is not None:
            self._set_query(request, new_qs)
        return found

    def _set_query(self, request, new_qs):
        from httptools import parse_url

        raw = request.raw_url
        path = raw.split(b"?", 1)[0]
        new_raw = path + (b"?" + new_qs if new_qs else b"")
        request._parsed_url = parse_url(new_raw)  # private slot, see module docstring
        request.raw_url = new_raw
        # Drop derived caches so args / query_args / query_string are all rebuilt
        # from the stripped query (RequestParameters keeps its multi-value API).
        request.parsed_args.clear()
        request.parsed_not_grouped_args.clear()

    def _inspect_body(self, request, rules):
        body = request.body
        if not body:
            return []
        ctype = request.headers.get("content-type", "")
        media = _jsonbody.media_type(ctype)
        found = []

        if media not in _jsonbody.FORM_MEDIA:
            # request.json ignores Content-Type, so sniff any non-form body.
            if _jsonbody.is_json_media(media):
                try:
                    obj = _jsonbody.parse_json_bytes(body)
                except Exception:
                    return []  # let the handler produce its own 400
            else:
                obj = _jsonbody.sniff_json(body)
                if obj is None:
                    return []
            obj, found, touched = self.ts._detect_honey_fields(obj, rules, request)
            if touched:
                self._set_body(request, _jsonbody.serialize(obj))
                ct = _jsonbody.fix_charset(ctype)
                if ct is not None:
                    try:
                        request.headers["content-type"] = ct
                    except Exception:
                        pass
                request.parsed_json = None  # re-parsed lazily from the stripped body
        else:
            if media == "application/x-www-form-urlencoded":
                found, new_body = _formbody.inspect_urlencoded(self.ts, body, rules, request)
            else:
                found, new_body = _formbody.inspect_multipart(self.ts, body, ctype, rules, request)
            if new_body is not None:
                self._set_body(request, new_body)
                request.parsed_form = None
                request.parsed_files = None
        return found or []

    @staticmethod
    def _set_body(request, new_body):
        request.body = new_body
        try:
            request.headers["content-length"] = str(len(new_body))
        except Exception:
            pass
