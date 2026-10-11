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
from urllib.parse import parse_qsl, urlencode

from . import _jsonbody

_NAME_RE = re.compile(r';\s*name=(?:"([^"]*)"|([^;\s]*))', re.I)
_FILENAME_RE = re.compile(r";\s*filename\*?=", re.I)


def _media_type(content_type):
    return (content_type or "").split(";")[0].strip().lower()


def _group_pairs(pairs):
    """[(k, v), ...] -> {k: scalar | [v, v, ...]} (lists only for repeated keys)."""
    out = {}
    for k, v in pairs:
        if k in out:
            if isinstance(out[k], list):
                out[k].append(v)
            else:
                out[k] = [out[k], v]
        else:
            out[k] = v
    return out


def _multipart_boundary(content_type):
    for param in (content_type or "").split(";")[1:]:
        param = param.strip()
        if param.lower().startswith("boundary="):
            return param.split("=", 1)[1].strip().strip('"')
    return None


def _multipart_parts(body, boundary):
    """Split a multipart body into (preamble, parts, tail); raw bytes are kept so
    unrelated parts can be re-emitted byte-for-byte."""
    delim = b"--" + boundary.encode("utf-8")
    chunks = body.split(delim)
    preamble, tail, parts = chunks[0], b"", []
    for seg in chunks[1:]:
        if seg.startswith(b"--"):
            tail = seg
            break
        head, sep, rest = seg.partition(b"\r\n\r\n")
        name, is_file = None, False
        for line in head.split(b"\r\n"):
            text = line.decode("latin1")
            if text.lower().startswith("content-disposition"):
                m = _NAME_RE.search(text)
                if m:
                    name = m.group(1) if m.group(1) is not None else m.group(2)
                is_file = bool(_FILENAME_RE.search(text))
        value = rest[:-2] if rest.endswith(b"\r\n") else rest
        parts.append({"name": name, "is_file": is_file, "raw": seg, "value": value.decode("utf-8", "replace")})
    return preamble, parts, tail or b"--\r\n"


def _rebuild_multipart(preamble, parts, tail, boundary, drop):
    delim = b"--" + boundary.encode("utf-8")
    kept = [p["raw"] for p in parts if p["is_file"] or p["name"] not in drop]
    return preamble + b"".join(delim + raw for raw in kept) + delim + tail


def _detect_json(ts, obj, rules, req):
    """Top-level object -> inspect; array -> inspect every object element; else skip."""
    found, touched = [], False
    if isinstance(obj, dict):
        obj, mod, touched = ts._detect_honey_fields(obj, rules, req)
        found.extend(mod or [])
    elif isinstance(obj, list):
        for i, el in enumerate(obj):
            if isinstance(el, dict):
                el, mod, t = ts._detect_honey_fields(el, rules, req)
                obj[i] = el
                found.extend(mod or [])
                touched = touched or t
    return obj, found, touched


def _make_trap_handler(trap, methods, ts, fallback):
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
                body, cfg = fallback()
            self.set_status(cfg["status_code"])
            self.set_header("Content-Type", cfg["mime_type"])
            if not isinstance(body, (str, bytes)):
                body = json.dumps(body, default=str)
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
        self._bootstrap_error = None

        if not self.ts.identity.ip:
            self.ts.identity.ip = lambda r: getattr(r, "remote_ip", None) or "0.0.0.0"

        self.ts.request.path = lambda r: getattr(r, "path", getattr(r, "uri", "").split("?")[0])
        self.ts.request.user_agent = lambda r: r.headers.get("User-Agent", "unknown")
        self.ts.request.method = lambda r: getattr(r, "method", None)

        self._patch_startup()
        self._patch_find_handler()

    # ------------------------------------------------------------------ setup
    def bootstrap(self):
        """Install traps and watches. Public, idempotent and thread-safe."""
        with self._lock:
            if not self._bootstrapped:
                self._bootstrapped = True  # never half-install twice
                try:
                    self.inject_traps()
                    self.setup_watches()
                except Exception as e:
                    self._bootstrap_error = e
            if self._bootstrap_error is not None:
                raise self._bootstrap_error

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
            probe = PathMatches(trap["path"])
            restricted = False
            for cls, matcher in existing:
                regex = getattr(matcher, "regex", None)
                if regex is None or regex.pattern != probe.regex.pattern:
                    continue
                overlap = methods & self._handled_methods(cls)
                if overlap:
                    raise RuntimeError(
                        f"trappsec: trap {sorted(overlap)} {trap['path']} duplicates an existing "
                        f"application route ({cls.__name__}); refusing to shadow or replace it"
                    )
                restricted = True
            handler_cls = _make_trap_handler(trap, methods, self.ts, self._fallback_response)
            handler_cls.__name__ = f"TrappsecTrapHandler{idx}"
            matcher = MethodPathMatches(trap["path"], methods) if restricted else PathMatches(trap["path"])
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

    def _fallback_response(self):
        cfg = dict(self.ts.default_responses.get("unauthenticated") or {})
        cfg.setdefault("status_code", 401)
        cfg.setdefault("mime_type", "application/json")
        body = cfg.get("response_body", {})
        if callable(body):
            body = {}
        return body, cfg

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
                try:
                    self.bootstrap()
                except Exception as e:  # C1: the host app keeps serving
                    self.ts.logger.error("trappsec: bootstrap failed: %s", e)
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

        pairs = parse_qsl(request.query, keep_blank_values=True)
        data, found, touched = self.ts._detect_honey_fields(_group_pairs(pairs), rules, request, source="query")
        if touched:
            new_qs = urlencode([(k, v) for k, v in pairs if k in data])
            request.query = new_qs
            request.uri = request.path + ("?" + new_qs if new_qs else "")
            request.query_arguments.clear()
            request.query_arguments.update(parse_qs_bytes(new_qs, keep_blank_values=True))
            self._rebuild_arguments(request)
        return found or []

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
        media = _media_type(ctype)
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
            obj, found, touched = _detect_json(self.ts, obj, rules, request)
            if touched:
                self._set_body(request, _jsonbody.serialize(obj))
                ct = _jsonbody.fix_charset(ctype)
                if ct is not None:
                    request.headers["Content-Type"] = ct
        elif media == "application/x-www-form-urlencoded":
            pairs = parse_qsl(body.decode("utf-8", "replace"), keep_blank_values=True)
            data, found, touched = self.ts._detect_honey_fields(_group_pairs(pairs), rules, request)
            if touched:
                self._set_body(request, urlencode([(k, v) for k, v in pairs if k in data]).encode("utf-8"))
        elif media == "multipart/form-data":
            boundary = _multipart_boundary(ctype)
            if not boundary:
                return []
            preamble, parts, tail = _multipart_parts(body, boundary)
            pairs = [(p["name"], p["value"]) for p in parts if p["name"] and not p["is_file"]]
            data, found, touched = self.ts._detect_honey_fields(_group_pairs(pairs), rules, request)
            if touched:
                drop = {k for k, _ in pairs if k not in data}
                self._set_body(request, _rebuild_multipart(preamble, parts, tail, boundary, drop))
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
