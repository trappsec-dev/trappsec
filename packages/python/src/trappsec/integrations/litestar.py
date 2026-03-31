import json
import re
from urllib.parse import parse_qs, urlencode


class _ASGIRequestURL:
    __slots__ = ("path",)

    def __init__(self, path):
        self.path = path


class _ASGIRequest:
    def __init__(self, scope, headers, body_data=None):
        self.scope = scope
        self.headers = headers
        self.path = scope.get("path", "/")
        self.url = _ASGIRequestURL(self.path)
        self.method = scope.get("method", "GET")
        client = scope.get("client") or ("0.0.0.0", 0)
        self.client = type("Client", (), {"host": client[0]})()
        self.body_data = body_data or {}


class LitestarIntegration:
    def __init__(self, ts, app):
        self.ts = ts
        self.app = app
        self.watch_map = {}      # route pattern -> watch dict, built once at init (R13)
        self.watch_patterns = [] # [(pattern, compiled_regex, watch)] for parameterized paths (R1)

        if not self.ts.identity.ip:
            self.ts.identity.ip = lambda r: r.client.host if r.client else "0.0.0.0"

        self.ts.request.path = lambda r: r.url.path
        self.ts.request.user_agent = lambda r: r.headers.get("user-agent", "unknown")
        self.ts.request.method = lambda r: r.method

        # R3 + R10: defer trap registration and watch setup to app startup so that
        # all ts.trap() / ts.watch() calls in user code have run first.
        self.app.on_startup.append(self._startup)
        self._patch_asgi_handler()

    def _startup(self):
        self._inject_traps()   # R14: real Litestar routes; R10: traps before watches
        self._setup_watches()  # R13: build O(1) watch_map

    def _inject_traps(self):
        # R14: register traps as real Litestar routes so they appear in the route
        # table and are indistinguishable from application endpoints during scanning.
        # app.register() calls construct_routing_trie() on the live asgi_router, so
        # routes propagate into the already-built asgi_handler.
        # Handler must have a clean (request: Request) -> Response signature —
        # Litestar's DI system inspects parameters and cannot resolve arbitrary defaults.
        from litestar import Request, Response
        from litestar.handlers import HTTPRouteHandler

        ts = self.ts

        for idx, trap in enumerate(self.ts.traps):
            def make_handler(_trap):
                async def trap_handler(request: Request) -> Response:
                    try:  # R12: fire-and-forget, never block the request
                        response_body, response_config = ts._trigger_trap_event(request, _trap)
                    except Exception as e:
                        ts.logger.error("trappsec trap error: %s", e)
                        response_body = ""
                        response_config = {"status_code": 200, "mime_type": "application/json"}
                    return Response(
                        content=response_body,
                        status_code=response_config["status_code"],
                        media_type=response_config["mime_type"],
                    )
                return trap_handler

            route_handler = HTTPRouteHandler(
                path=trap["path"],
                http_method=trap["methods"],
                include_in_schema=False,
                name=f"trappsec_trap_{idx}",
            )(make_handler(trap))
            self.app.register(route_handler)

    def _setup_watches(self):
        # R13: build O(1) watch lookup map indexed by route pattern.
        for watch in self.ts.watches:
            self.watch_map[watch["path"]] = watch

            # R1: compile regex for parameterized patterns (e.g., /users/{id})
            if "{" in watch["path"]:
                escaped = re.escape(watch["path"])
                regex = re.compile("^" + re.sub(r"\\\{[^}]+\\\}", "[^/]+", escaped) + "$")
                self.watch_patterns.append((watch["path"], regex, watch))

    def _resolve_watch(self, path):
        # R1: match raw URL path to a watch using its route pattern.
        # O(1) for exact-match paths; O(k) for parameterized (k = parameterized watch count).
        watch = self.watch_map.get(path)
        if watch:
            return watch
        for _, regex, w in self.watch_patterns:
            if regex.match(path):
                return w
        return None

    def _patch_asgi_handler(self):
        original_handler = self.app.asgi_handler

        async def wrapped(scope, receive, send):
            if scope.get("type") != "http":
                return await original_handler(scope, receive, send)

            headers = {
                k.decode("latin1").lower(): v.decode("latin1")
                for k, v in scope.get("headers", [])
            }
            path = scope.get("path", "/")

            # Traps are handled by real Litestar routes registered in _inject_traps (R14).
            # Watch handling — R1: resolve raw path to watch using route pattern
            watch = self._resolve_watch(path)
            if not watch:
                return await original_handler(scope, receive, send)

            body_bytes = b""
            more_body = True
            while more_body:
                message = await receive()
                body_bytes += message.get("body", b"")
                more_body = message.get("more_body", False)

            found_fields = []
            query_fields = watch.get("query_fields", {})
            body_fields = watch.get("body_fields", {})

            if query_fields:
                qs = scope.get("query_string", b"").decode("utf-8")
                q_dict = parse_qs(qs) if qs else {}
                q_dict, mod, touched = self.ts._detect_honey_fields(q_dict, query_fields, None)
                if mod:
                    found_fields.extend(mod)
                if touched:
                    scope["query_string"] = urlencode(q_dict, doseq=True).encode("utf-8")

            content_type = headers.get("content-type", "")
            body_data = {}
            new_body = body_bytes
            if body_fields and body_bytes:
                try:
                    if "application/json" in content_type:
                        body_data = json.loads(body_bytes.decode("utf-8"))
                        if isinstance(body_data, dict):
                            # R4: always strip — field removed regardless of value (Python convention)
                            body_data, mod, touched = self.ts._detect_honey_fields(body_data, body_fields, None)
                            if mod:
                                found_fields.extend(mod)
                            if touched:
                                new_body = json.dumps(body_data).encode("utf-8")
                    elif "application/x-www-form-urlencoded" in content_type:
                        body_data = {k: v[0] if isinstance(v, list) and v else v for k, v in parse_qs(body_bytes.decode("utf-8")).items()}
                        # R4: always strip — field removed regardless of value (Python convention)
                        body_data, mod, touched = self.ts._detect_honey_fields(body_data, body_fields, None)
                        if mod:
                            found_fields.extend(mod)
                        if touched:
                            new_body = urlencode(body_data, doseq=True).encode("utf-8")
                except Exception as e:
                    self.ts.logger.error("error reading body: %s", e)

            if found_fields:
                req = _ASGIRequest(scope, headers, body_data=body_data)
                try:  # R12: fire-and-forget, never block the request
                    self.ts._trigger_watch_event(req, found_fields)
                except Exception as e:
                    self.ts.logger.error("trappsec watch event error: %s", e)

            sent = False

            async def new_receive():
                nonlocal sent
                if sent:
                    return {"type": "http.request", "body": b"", "more_body": False}
                sent = True
                return {"type": "http.request", "body": new_body, "more_body": False}

            return await original_handler(scope, new_receive, send)

        self.app.asgi_handler = wrapped
