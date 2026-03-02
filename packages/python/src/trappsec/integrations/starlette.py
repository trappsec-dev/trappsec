from contextlib import asynccontextmanager
from urllib.parse import parse_qs, urlencode
import json


class StarletteIntegration:
    def __init__(self, ts, app):
        self.ts = ts
        self.app = app
        self.watch_map = {}

        if not self.ts.identity.ip:
            self.ts.identity.ip = lambda r: r.client.host if r.client else "0.0.0.0"

        self.ts.request.path = lambda r: str(r.url.path)
        self.ts.request.user_agent = lambda r: r.headers.get("user-agent", "unknown")
        self.ts.request.method = lambda r: r.method

        self.setup_middleware()
        self._patch_startup()

    def inject_traps(self):
        from starlette.responses import Response
        from starlette.routing import Route

        async def endpoint(req, trap):
            response_body, response_config = self.ts._trigger_trap_event(req, trap)
            return Response(
                response_body,
                status_code=response_config["status_code"],
                media_type=response_config["mime_type"],
            )

        routes = []
        for idx, trap in enumerate(self.ts.traps):
            methods = trap.get("methods", ["GET", "POST"])
            routes.append(
                Route(
                    trap["path"],
                    endpoint=lambda req, d=trap: endpoint(req, d),
                    methods=methods,
                    name=f"trappsec_{idx}",
                )
            )

        self.app.router.routes = routes + self.app.router.routes

    def setup_watches(self):
        self.watch_map = {w["path"]: w for w in self.ts.watches}

    def setup_middleware(self):
        from starlette.middleware.base import BaseHTTPMiddleware

        integration = self

        class TrappSecWatchMiddleware(BaseHTTPMiddleware):
            async def dispatch(self, request, call_next):
                route = request.scope.get("route")
                if route is not None:
                    watch = integration.watch_map.get(getattr(route, "path", None))
                    if watch:
                        found_fields = []
                        query_fields = watch["query_fields"]
                        body_fields = watch["body_fields"]

                        if query_fields:
                            qs = request.scope.get("query_string", b"").decode("utf-8")
                            if qs:
                                q_dict = parse_qs(qs)
                                q_dict, mod = integration.ts._detect_honey_fields(q_dict, query_fields, request)
                                if mod:
                                    found_fields.extend(mod)
                                    request.scope["query_string"] = urlencode(q_dict, doseq=True).encode("utf-8")
                                    if hasattr(request, "_query_params"):
                                        del request._query_params

                        if body_fields:
                            ctype = request.headers.get("content-type", "")
                            if "application/json" in ctype:
                                try:
                                    body_bytes = await request.body()
                                    data = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
                                    data, mod = integration.ts._detect_honey_fields(data, body_fields, request)
                                    if mod:
                                        found_fields.extend(mod)
                                        new_body = json.dumps(data).encode("utf-8")

                                        async def receive():
                                            return {"type": "http.request", "body": new_body, "more_body": False}

                                        request._receive = receive
                                except Exception as e:
                                    integration.ts.logger.error("error reading json body: %s", e)

                        if found_fields:
                            integration.ts._trigger_watch_event(request, found_fields)

                return await call_next(request)

        self.app.add_middleware(TrappSecWatchMiddleware)

    def _patch_startup(self):
        original_lifespan = self.app.router.lifespan_context

        @asynccontextmanager
        async def wrapped_lifespan(app_instance):
            self.inject_traps()
            self.setup_watches()
            async with original_lifespan(app_instance) as state:
                yield state

        self.app.router.lifespan_context = wrapped_lifespan
