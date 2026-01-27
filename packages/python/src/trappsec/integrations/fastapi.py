from functools import partial

class FastAPIIntegration:
    def __init__(self, ts, app):
        self.ts = ts
        self.app = app
        self.watch_map = None

        if not self.ts.identity.ip: 
            self.ts.identity.ip = lambda r: r.client.host if r.client else "0.0.0.0"

        self.ts.request.path = lambda r: str(r.url.path)
        self.ts.request.user_agent = lambda r: r.headers.get("user-agent", "unknown")
        self.ts.request.method = lambda r: r.method
        
        self.setup_middleware()
        self._patch_startup()

    def inject_traps(self):
        from fastapi import Request, Response
        from fastapi.routing import APIRoute

        async def endpoint(req: Request, trap):
            response_body, response_config = self.ts._trigger_trap_event(req, trap)

            return Response(response_body, 
                status_code=response_config["status_code"], 
                media_type=response_config["mime_type"])

        new_routes = []
        for idx, trap in enumerate(self.ts.traps):
            new_routes.append(APIRoute(trap["path"], partial(endpoint, trap=trap), 
                methods=trap["methods"], name=f"trappsec_{idx}", include_in_schema=False))
    
        self.app.router.routes = new_routes + self.app.router.routes

    def setup_watches(self):
        watch_map = dict()
        for watch in self.ts.watches:
            watch_map[watch["path"]] = watch
        self.watch_map = watch_map
    
    def setup_middleware(self):        
        from fastapi import Request, Depends
        from starlette.datastructures import FormData
        from starlette.middleware.base import BaseHTTPMiddleware
        from urllib.parse import parse_qs, urlencode

        async def trappsec_watcher(request: Request):
            route = request.scope.get("route")
            if route is None:
                return

            if route.path not in self.watch_map:
                return
            
            matched_rule = self.watch_map[route.path]
            query_fields = matched_rule["query_fields"]
            body_fields = matched_rule["body_fields"]
            found_fields = []
            
            if query_fields:
                qs = request.scope.get("query_string", b"").decode("utf-8")
                if qs:
                    q_dict = parse_qs(qs).to_dict(flat=False)                    
                    q_dict, mod = self.ts._detect_honey_fields(q_dict, query_fields, request)
                    
                    if mod:
                        found_fields.extend(mod)
                        request.scope["query_string"] = urlencode(q_dict, doseq=True).encode("utf-8")
                        if hasattr(request, "_query_params"):
                            del request._query_params
                
            if body_fields:
                ctype = request.headers.get("content-type", "")
                if "application/json" in ctype:
                    try:
                        body = await request.json()
                        b, mod = self.ts._detect_honey_fields(body, body_fields, request)
                        if mod:
                            found_fields.extend(mod)
                            request._json = b
                    except Exception as e: 
                        self.ts.logger.error("error reading json body: %s", e)
                elif "application/x-www-form-urlencoded" in ctype or "multipart/form-data" in ctype:
                    try:
                        form_data = await request.form()
                        data = dict(form_data)
                        b, mod = self.ts._detect_honey_fields(data, body_fields, request)
                        if mod:
                            found_fields.extend(mod)
                            request._form = FormData(b)
                    except Exception as e: 
                        self.ts.logger.error("error reading form body: %s", e)
            
            if found_fields:
                self.ts._trigger_watch_event(request, found_fields)

        if self.app.router.dependencies is None:
            self.app.router.dependencies = []

        self.app.router.dependencies.append(Depends(trappsec_watcher))
    
    def _patch_startup(self):
        from contextlib import asynccontextmanager
        original_lifespan = self.app.router.lifespan_context

        @asynccontextmanager
        async def wrapped_lifespan(app_instance):
            self.inject_traps()
            self.setup_watches()

            async with original_lifespan(app_instance) as state:
                yield state

        self.app.router.lifespan_context = wrapped_lifespan
        
    
