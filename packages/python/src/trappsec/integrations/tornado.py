"""Tornado integration.

Design notes
------------
* ``bootstrap()`` (public, idempotent, thread-safe) installs traps and builds
  the watch index. It is called from the patched ``Application.listen`` and,
  lazily, from a wrapped ``Application.find_handler`` so that
  ``HTTPServer(app).listen()``, ``AsyncHTTPTestCase`` and any other custom
  server are protected as well. ``find_handler`` is what every Tornado server
  entry point (``Router.start_request`` / ``Application.__call__``) goes through.
* Traps are installed with ``Application.add_handlers(".*$", ...)``. Tornado
  consults host rules *before* the wildcard router that holds the ordinary
  application handlers, and trappsec moves its own host rule to the very front
  of ``default_router.rules``, so traps always win over app routes
  (no reordering of ``wildcard_router`` is needed or performed).
  If a trap path is also an application route, bootstrap raises when the
  methods overlap (never silently shadows/replaces) and otherwise restricts the
  trap to its own methods so the application route keeps serving the others.
* A trap answers only its declared methods; every other method gets Tornado's
  own 405 (no ``Allow`` header, like a real handler without that method), so the
  response cannot tell a trap from an application route (R14). Traps skip XSRF
  checks.
* Watches wrap the per-request ``_HandlerDelegate.execute`` of requests whose
  matched handler class/route has a watch; user handler classes are never
  patched. The raw ``request.body`` is the source of truth: it is rewritten
  (JSON, urlencoded and multipart) and Tornado's parsed ``arguments`` are kept
  consistent. Streaming-body handlers (``@stream_request_body``) are not
  inspected because their body is not available at this point.
* Handlers added with ``add_handlers`` *after* the first request / ``listen``
  are not watched (the watch index is built once, R13).
"""
import json
import re
import threading

from . import _formbody, _jsonbody

class TrapConflictError(RuntimeError):
    """A trap path+method exactly duplicates an existing application route."""


_SEGMENT_PARAM_RES = (
    re.compile(r"^:\w+$"),          # :id
    re.compile(r"^\{[^}]*\}$"),     # {id}, {id:int}
    re.compile(r"^<[^>]*>$"),        # <id>, <int:id>
)
_CATCH_ALL_RES = (
    re.compile(r"^\*\w*$"),                  # *rest
    re.compile(r"^\{[^}:]*(\.\.\.|:path)\}$"),  # {rest...}, {rest:path}
    re.compile(r"^<path:[^>]*>$"),           # <path:rest>
)


def _trap_pattern(path):
    """Translate a trap path template into the regex Tornado's ``PathMatches`` expects:
    parameter segments become a ``[^/]+`` group, a catch-all last segment ``.+``."""
    segments = path.split("/")
    for i, seg in enumerate(segments):
        if i == len(segments) - 1 and any(r.match(seg) for r in _CATCH_ALL_RES):
            segments[i] = "(.+)"
        elif any(r.match(seg) for r in _SEGMENT_PARAM_RES):
            segments[i] = "([^/]+)"
    return "/".join(segments)


def _make_trap_handler(trap, methods, ts):
    """Factory that captures trap/methods/ts by value, avoiding the loop-variable closure bug."""
    import tornado.web

    class TrapHandler(tornado.web.RequestHandler):
        _trappsec_trap = True
        SUPPORTED_METHODS = tuple(sorted(methods))

        def check_xsrf_cookie(self):  # traps must never be blocked by XSRF protection
            return

        async def _serve(self, *args, **kwargs):
            try:
                body, cfg = ts._trigger_trap_event(self.request, trap)
            except Exception as e:  # C1: serve the plain decoy
                ts.logger.error("trappsec trap error: %s", e)
                body, cfg = ts._trap_fallback(trap)
            self.set_status(cfg["status_code"])
            self.set_header("Content-Type", cfg["mime_type"])
            if not isinstance(body, (str, bytes)):
                body = json.dumps(body, default=str, separators=(",", ":"))
            self.write(body)

    for m in methods:
        setattr(TrapHandler, m.lower(), TrapHandler._serve)

    return TrapHandler


class TornadoIntegration:
    def __init__(self, ts, app):
        self.ts = ts
        self.app = app
        self.watch_map = {}
        self._class_rules = {}  # handler class -> [(matcher, watch), ...]
        self._lock = threading.RLock()
        self._bootstrapped = False

        if not self.ts.identity.ip:
            self.ts.identity.ip = lambda r: getattr(r, "remote_ip", None) or "0.0.0.0"

        self.ts.request.path = lambda r: r.path
        self.ts.request.user_agent = lambda r: r.headers.get("User-Agent", "unknown")
        self.ts.request.method = lambda r: getattr(r, "method", None)

        self._patch_startup()
        self._patch_find_handler()

    # ------------------------------------------------------------------ setup
    def bootstrap(self):
        """Install traps and watches. Public, idempotent and thread-safe.

        A trap conflict raises ``TrapConflictError`` on every call (nothing is installed
        and the app is never left half-set-up); any other trap failure is logged and
        watches are still set up."""
        with self._lock:
            if self._bootstrapped:
                return
            try:
                self.inject_traps()  # R10: traps before watches
            except TrapConflictError:
                raise
            except Exception as e:
                self.ts.logger.error("trappsec: trap installation failed: %s", e)
            self.setup_watches()
            self._bootstrapped = True

    def _leaf_rules(self, router=None, _seen=None):
        """Yield (handler_class, matcher) for every class-targeted rule, recursing into sub-routers."""
        router = router if router is not None else self.app.default_router
        _seen = _seen if _seen is not None else set()
        if id(router) in _seen:
            return
        _seen.add(id(router))
        for rule in list(getattr(router, "rules", [])):
            target = getattr(rule, "target", None)
            if hasattr(target, "rules"):
                yield from self._leaf_rules(target, _seen)
            elif isinstance(target, type):
                yield target, getattr(rule, "matcher", None)

    @staticmethod
    def _handled_methods(cls):
        import tornado.web

        base = tornado.web.RequestHandler
        out = set()
        for m in getattr(cls, "SUPPORTED_METHODS", ()):
            attr = getattr(cls, m.lower(), None)
            if attr is not None and attr is not getattr(base, m.lower(), None):
                out.add(m.upper())
        return out

    def inject_traps(self):
        from tornado.routing import PathMatches, Rule

        class MethodPathMatches(PathMatches):
            def __init__(self, pattern, methods):
                super().__init__(pattern)
                self._methods = methods

            def match(self, request):
                if request.method not in self._methods:
                    return None
                return super().match(request)

        traps = self.ts.traps
        if not traps:
            return

        existing = [(c, m) for c, m in self._leaf_rules() if not getattr(c, "_trappsec_trap", False)]
        rules = []
        for idx, trap in enumerate(traps):
            methods = frozenset(m.upper() for m in trap["methods"])
            pattern = _trap_pattern(trap["path"])
            probe = PathMatches(pattern)
            restricted = False
            for cls, matcher in existing:
                regex = getattr(matcher, "regex", None)
                if regex is None or regex.pattern != probe.regex.pattern:
                    continue
                overlap = methods & self._handled_methods(cls)
                if overlap:
                    raise TrapConflictError(
                        f"trappsec: trap {sorted(overlap)} {trap['path']} duplicates an existing "
                        f"application route ({cls.__name__}); refusing to shadow or replace it"
                    )
                restricted = True
            handler_cls = _make_trap_handler(trap, methods, self.ts)
            handler_cls.__name__ = f"TrappsecTrapHandler{idx}"
            matcher = MethodPathMatches(pattern, methods) if restricted else PathMatches(pattern)
            rules.append(Rule(matcher, handler_cls))

        # R2: Tornado checks host rules before the wildcard router that holds the
        # application's handlers. Register one host rule and move it to the front so
        # that it also precedes any host rule added by the application earlier.
        before = list(self.app.default_router.rules)
        self.app.add_handlers(r".*$", rules)
        new = [r for r in self.app.default_router.rules if r not in before]
        for r in new:
            self.app.default_router.rules.remove(r)
        self.app.default_router.rules[0:0] = new

    def setup_watches(self):
        self.watch_map = {w["path"]: w for w in self.ts.watches}
        self._class_rules = {}
        if not self.watch_map:
            return
        for cls, matcher in self._leaf_rules():
            if getattr(cls, "_trappsec_trap", False) or matcher is None:
                continue
            regex = getattr(matcher, "regex", None)
            if regex is None:
                continue
            path = getattr(matcher, "_path", None)
            watch = self.watch_map.get(path) if path else None
            if watch is None:
                watch = self.watch_map.get(regex.pattern.rstrip("$"))
            if watch is not None:
                self._class_rules.setdefault(cls, []).append((matcher, watch))

    def _patch_startup(self):
        original_listen = self.app.listen

        def wrapped_listen(*args, **kwargs):
            self.bootstrap()
            return original_listen(*args, **kwargs)

        self.app.listen = wrapped_listen

    def _patch_find_handler(self):
        original = self.app.find_handler

        def find_handler(request, **kwargs):
            if not self._bootstrapped:
                self.bootstrap()  # a trap conflict fails loud on every request
            delegate = original(request, **kwargs)
            if self._class_rules:
                try:
                    self._wrap_delegate(delegate)
                except Exception as e:
                    self.ts.logger.error("trappsec watch setup error: %s", e)
            return delegate

        self.app.find_handler = find_handler

    # ---------------------------------------------------------------- watching
    def _wrap_delegate(self, delegate):
        cls = getattr(delegate, "handler_class", None)
        rules = self._class_rules.get(cls)
        request = getattr(delegate, "request", None)
        if not rules or request is None or not hasattr(delegate, "execute"):
            return
        watch = None
        for matcher, w in rules:  # R1: the route that actually matched this request
            if matcher.regex.match(request.path):
                watch = w
                break
        if watch is None:
            return

        original_execute = delegate.execute

        def execute():
            try:
                found = self._inspect(request, watch, getattr(delegate, "stream_request_body", False))
            except Exception as e:  # C1
                self.ts.logger.error("trappsec watch error: %s", e)
                found = []
            if found:
                try:
                    self.ts._trigger_watch_event(request, found)
                except Exception as e:
                    self.ts.logger.error("trappsec watch event error: %s", e)
            return original_execute()

        delegate.execute = execute

    def _inspect(self, request, watch, streaming):
        found = []
        query_fields = watch.get("query_fields") or {}
        body_fields = watch.get("body_fields") or {}

        if query_fields and request.query:
            try:
                found.extend(self._inspect_query(request, query_fields))
            except Exception as e:
                self.ts.logger.error("trappsec query inspection error: %s", e)

        if body_fields and request.body and not streaming:
            try:
                found.extend(self._inspect_body(request, body_fields))
            except Exception as e:
                self.ts.logger.error("trappsec body inspection error: %s", e)
        return found

    def _inspect_query(self, request, rules):
        from tornado.escape import parse_qs_bytes

        # Tornado decodes the query as latin-1, so this round-trips the original bytes.
        found, new_qs = _formbody.inspect_urlencoded(
            self.ts, request.query.encode("latin-1", "replace"), rules, request, source="query")
        if new_qs is not None:
            request.query = new_qs.decode("latin-1")
            request.uri = request.path + ("?" + request.query if new_qs else "")
            request.query_arguments.clear()
            request.query_arguments.update(parse_qs_bytes(request.query, keep_blank_values=True))
            self._rebuild_arguments(request)
        return found

    @staticmethod
    def _rebuild_arguments(request):
        import copy

        merged = copy.deepcopy(request.query_arguments)
        for k, v in request.body_arguments.items():
            merged.setdefault(k, []).extend(v)
        request.arguments.clear()
        request.arguments.update(merged)

    def _inspect_body(self, request, rules):
        body = request.body
        ctype = request.headers.get("Content-Type", "")
        media = _jsonbody.media_type(ctype)
        found = []

        if media not in _jsonbody.FORM_MEDIA:
            # handlers json-decode request.body regardless of Content-Type: sniff.
            if _jsonbody.is_json_media(media):
                try:
                    obj = _jsonbody.parse_json_bytes(body)
                except Exception:
                    return []
            else:
                obj = _jsonbody.sniff_json(body)
                if obj is None:
                    return []
            obj, found, touched = self.ts._detect_honey_fields(obj, rules, request)
            if touched:
                self._set_body(request, _jsonbody.serialize(obj))
                ct = _jsonbody.fix_charset(ctype)
                if ct is not None:
                    request.headers["Content-Type"] = ct
        else:
            if media == "application/x-www-form-urlencoded":
                found, new_body = _formbody.inspect_urlencoded(self.ts, body, rules, request)
            else:
                found, new_body = _formbody.inspect_multipart(self.ts, body, ctype, rules, request)
            if new_body is not None:
                self._set_body(request, new_body)
        return found or []

    def _set_body(self, request, new_body):
        request.body = new_body
        if "Content-Length" in request.headers:
            request.headers["Content-Length"] = str(len(new_body))
        # Tornado >= 6.5 parses the body later (inside RequestHandler._execute) and will
        # simply see the stripped body. Older versions already parsed it: redo it.
        if request.body_arguments or request.files:
            request.body_arguments.clear()
            request.files.clear()
            self._rebuild_arguments(request)
            request._parse_body()
