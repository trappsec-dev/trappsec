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
  buffered when the watch has body fields, the content type is JSON /
  urlencoded / multipart and the declared ``Content-Length`` is below
  ``MAX_INSPECT_BYTES``; otherwise the request streams untouched. When a body is
  rewritten the ``Content-Length`` header is updated to match.
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
from urllib.parse import parse_qsl, urlencode

from . import _jsonbody

MAX_INSPECT_BYTES = 10 * 1024 * 1024

_TYPED_PARAM_RE = re.compile(r"\{([^}:]+):[^}]+\}")
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

    def _fallback_response(self):
        cfg = dict(self.ts.default_responses.get("unauthenticated") or {})
        cfg.setdefault("status_code", 401)
        cfg.setdefault("mime_type", "application/json")
        body = cfg.get("response_body", {})
        if callable(body):
            body = {}
        return body, cfg

    def _inject_traps(self):
        from litestar import Request, Response
        from litestar.handlers import HTTPRouteHandler
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
                    body, cfg = self._fallback_response()
                if not isinstance(body, (str, bytes)):
                    body = json.dumps(body, default=str)
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

    async def _read_body(self, scope, receive, headers):
        """Buffer the body only if it is worth inspecting; returns (messages, body) or None."""
        media = _media_type(headers.get("content-type", ""))
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
            read = await self._read_body(scope, receive, headers)
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
                qs = scope.get("query_string", b"").decode("utf-8", "replace")
                if qs:
                    pairs = parse_qsl(qs, keep_blank_values=True)
                    data, mod, touched = self.ts._detect_honey_fields(
                        _group_pairs(pairs), query_fields, request, source="query")
                    found.extend(mod or [])
                    if touched:
                        new_qs = urlencode([(k, v) for k, v in pairs if k in data]).encode("utf-8")

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
        media = _media_type(ctype)

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
            obj, mod, touched = _detect_json(self.ts, obj, rules, request)
            found.extend(mod)
            return _jsonbody.serialize(obj) if touched else None

        if media == "application/x-www-form-urlencoded":
            pairs = parse_qsl(body.decode("utf-8", "replace"), keep_blank_values=True)
            data, mod, touched = self.ts._detect_honey_fields(_group_pairs(pairs), rules, request)
            found.extend(mod or [])
            return urlencode([(k, v) for k, v in pairs if k in data]).encode("utf-8") if touched else None

        if media == "multipart/form-data":
            boundary = _multipart_boundary(ctype)
            if not boundary:
                return None
            preamble, parts, tail = _multipart_parts(body, boundary)
            pairs = [(p["name"], p["value"]) for p in parts if p["name"] and not p["is_file"]]
            data, mod, touched = self.ts._detect_honey_fields(_group_pairs(pairs), rules, request)
            found.extend(mod or [])
            if touched:
                drop = {k for k, _ in pairs if k not in data}
                return _rebuild_multipart(preamble, parts, tail, boundary, drop)
        return None
