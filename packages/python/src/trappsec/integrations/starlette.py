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

        self._patch_startup()

    def inject_traps(self):
        from starlette.responses import Response
        from starlette.routing import Route

        def make_endpoint(trap):
            async def endpoint(req):
                response_body, response_config = self.ts._trigger_trap_event(req, trap)
                return Response(
                    response_body,
                    status_code=response_config["status_code"],
                    media_type=response_config["mime_type"],
                )

            return endpoint

        routes = []
        for idx, trap in enumerate(self.ts.traps):
            methods = trap.get("methods", ["GET", "POST"])
            routes.append(
                Route(
                    trap["path"],
                    endpoint=make_endpoint(trap),
                    methods=methods,
                    name=f"trappsec_{idx}",
                )
            )

        self.app.router.routes = routes + self.app.router.routes

    def setup_watches(self):
        self.watch_map = {w["path"]: w for w in self.ts.watches}

        if not self.watch_map:
            return

        self._wrap_routes(self.app.router.routes, prefix="")

    def _wrap_routes(self, routes, prefix):
        from starlette.routing import Route, Router, Mount
        from starlette.routing import request_response

        for route in routes:
            if isinstance(route, Route):
                full_path = prefix + route.path
                watch = self.watch_map.get(full_path)
                if watch is not None:
                    route.endpoint = self._make_watch_endpoint(route.endpoint, watch)
                    # Rebuild route.app so it wraps the new endpoint; Starlette sets
                    # route.app = request_response(endpoint) at __init__ time and does
                    # not update it automatically when endpoint is replaced.
                    route.app = request_response(route.endpoint)
            elif isinstance(route, Mount):
                inner = route.app
                if isinstance(inner, Router):
                    # Mount.path strips the trailing slash in Starlette, and inner
                    # Route paths always begin with /, so concatenation produces the
                    # correct full path (e.g. "/api" + "/users/{id}" → "/api/users/{id}").
                    mount_prefix = prefix + (route.path or "")
                    self._wrap_routes(inner.routes, mount_prefix)
                # Non-Router mounts (e.g. StaticFiles) wrap an opaque ASGI app —
                # recursion is not possible; any watches under them will be missed.
                # Configure watches only on routes served by a Starlette Router.

    def _make_watch_endpoint(self, orig_endpoint, watch):
        from starlette.datastructures import FormData

        ts = self.ts

        async def watch_endpoint(request):
            found_fields = []
            query_fields = watch["query_fields"]
            body_fields = watch["body_fields"]

            if query_fields:
                qs = request.scope.get("query_string", b"").decode("utf-8")
                if qs:
                    q_dict = {k: v[0] if len(v) == 1 else v for k, v in parse_qs(qs).items()}
                    q_dict, mod, touched = ts._detect_honey_fields(q_dict, query_fields, request)
                    if mod:
                        found_fields.extend(mod)
                    if touched:
                        # Rewrite scope before request.query_params is first accessed;
                        # no cache busting needed since the property hasn't been read yet.
                        request.scope["query_string"] = urlencode(q_dict, doseq=True).encode("utf-8")

            if body_fields:
                ctype = request.headers.get("content-type", "")

                if "application/json" in ctype:
                    try:
                        data = await request.json()
                        data, mod, touched = ts._detect_honey_fields(data, body_fields, request)
                        if mod:
                            found_fields.extend(mod)
                        if touched:
                            # Replace the parsed JSON cache so the handler sees clean data
                            # when it calls await request.json(). The raw body bytes are
                            # left intact; handlers must use request.json(), not request.body(),
                            # to see the stripped result (starlette >= 0.14).
                            request._json = data
                    except Exception as e:
                        ts.logger.error("error reading json body: %s", e)

                elif "application/x-www-form-urlencoded" in ctype or "multipart/form-data" in ctype:
                    try:
                        form_data = await request.form()
                        flat = dict(form_data)
                        flat, mod, touched = ts._detect_honey_fields(flat, body_fields, request)
                        if mod:
                            found_fields.extend(mod)
                        if touched:
                            # Rebuild FormData from the original multi-items, dropping
                            # only the watched keys. Using multi_items() preserves both
                            # multi-value fields and UploadFile objects untouched.
                            # Replaces the parsed form cache so the handler's
                            # await request.form() returns the cleaned data (starlette >= 0.20).
                            cleaned_items = [(k, v) for k, v in form_data.multi_items() if k in flat]
                            request._form = FormData(cleaned_items)
                    except Exception as e:
                        ts.logger.error("error reading form body: %s", e)

            if found_fields:
                try:
                    ts._trigger_watch_event(request, found_fields)
                except Exception as e:
                    ts.logger.error("error triggering watch event: %s", e)

            return await orig_endpoint(request)

        return watch_endpoint

    def _patch_startup(self):
        original_lifespan = self.app.router.lifespan_context

        @asynccontextmanager
        async def wrapped_lifespan(app_instance):
            self.inject_traps()
            self.setup_watches()
            async with original_lifespan(app_instance) as state:
                yield state

        self.app.router.lifespan_context = wrapped_lifespan
