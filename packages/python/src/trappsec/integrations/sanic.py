class SanicIntegration:
    def __init__(self, ts, app):
        self.ts = ts
        self.app = app
        self.watch_map = {}

        if not self.ts.identity.ip:
            self.ts.identity.ip = lambda r: r.remote_addr or "0.0.0.0"

        self.ts.request.path = lambda r: r.path
        self.ts.request.user_agent = lambda r: r.headers.get("user-agent", "unknown")
        self.ts.request.method = lambda r: r.method

        self._patch_startup()

    def inject_traps(self):
        from sanic.response import HTTPResponse

        for trap in self.ts.traps:
            async def endpoint(request, d=trap):
                response_body, response_config = self.ts._trigger_trap_event(request, d)
                return HTTPResponse(
                    body=response_body,
                    status=response_config["status_code"],
                    content_type=response_config["mime_type"],
                )

            self.app.add_route(endpoint, trap["path"], methods=trap["methods"], name=f"trappsec_{trap['path']}")

    def setup_watches(self):
        self.watch_map = {w["path"]: w for w in self.ts.watches}

        @self.app.on_request
        async def trappsec_watcher(request):
            route = getattr(request, "route", None)
            matched_path = getattr(route, "path", request.path) if route else request.path
            watch = self.watch_map.get(matched_path)
            if not watch:
                return

            found_fields = []
            query_fields = watch["query_fields"]
            body_fields = watch["body_fields"]

            if query_fields and request.args:
                args_dict = dict(request.args)
                args_dict, mod = self.ts._detect_honey_fields(args_dict, query_fields, request)
                if mod:
                    found_fields.extend(mod)
                    try:
                        request.args = args_dict
                    except Exception:
                        pass

            if body_fields:
                if isinstance(request.json, dict):
                    data, mod = self.ts._detect_honey_fields(dict(request.json), body_fields, request)
                    if mod:
                        found_fields.extend(mod)
                        try:
                            request._json = data
                        except Exception:
                            pass

                if request.form:
                    form_dict = dict(request.form)
                    data, mod = self.ts._detect_honey_fields(form_dict, body_fields, request)
                    if mod:
                        found_fields.extend(mod)
                        try:
                            request.form = data
                        except Exception:
                            pass

            if found_fields:
                self.ts._trigger_watch_event(request, found_fields)

    def _patch_startup(self):
        @self.app.main_process_start
        async def trappsec_init(_app):
            self.inject_traps()
            self.setup_watches()
