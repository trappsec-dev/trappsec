import re


class SanicIntegration:
    def __init__(self, ts, app):
        self.ts = ts
        self.app = app
        self.watch_map = {}
        self._typed_param_pattern = re.compile(r"<([^:>]+):[^>]+>")

        if not self.ts.identity.ip:
            self.ts.identity.ip = lambda r: r.remote_addr or "0.0.0.0"

        self.ts.request.path = lambda r: r.path
        self.ts.request.user_agent = lambda r: r.headers.get("user-agent", "unknown")
        self.ts.request.method = lambda r: r.method

        self._patch_request_accessors()
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
        self.watch_map = {self._normalize_route_pattern(w["path"]): w for w in self.ts.watches}

        @self.app.on_request
        async def trappsec_watcher(request):
            route = getattr(request, "route", None)
            watch = None

            candidates = []
            if route is not None:
                for attr in ("path", "uri", "pattern"):
                    value = getattr(route, attr, None)
                    if value:
                        candidates.append(str(value))
            candidates.append(request.path)

            for raw_path in candidates:
                matched_path = self._normalize_route_pattern(raw_path)
                watch = self.watch_map.get(matched_path)
                if watch:
                    break

            if not watch:
                return

            found_fields = []
            query_fields = watch["query_fields"]
            body_fields = watch["body_fields"]

            if query_fields and request.args:
                args_dict = dict(request.args)
                args_dict, mod, touched = self.ts._detect_honey_fields(args_dict, query_fields, request)
                if mod:
                    found_fields.extend(mod)
                if touched:
                    setattr(request.ctx, "_trappsec_override_args", args_dict)

            if body_fields:
                content_type = request.content_type or ""
                if "application/json" in content_type and isinstance(request.json, dict):
                    data, mod, touched = self.ts._detect_honey_fields(dict(request.json), body_fields, request)
                    if mod:
                        found_fields.extend(mod)
                    if touched:
                        setattr(request.ctx, "_trappsec_override_json", data)

                if request.form:
                    form_dict = dict(request.form)
                    data, mod, touched = self.ts._detect_honey_fields(form_dict, body_fields, request)
                    if mod:
                        found_fields.extend(mod)
                    if touched:
                        setattr(request.ctx, "_trappsec_override_form", data)

            if found_fields:
                self.ts._trigger_watch_event(request, found_fields)

    def _normalize_route_pattern(self, path):
        # Normalize dynamic param syntax so `/x/<id:str>` and `/x/<id>` match.
        normalized = self._typed_param_pattern.sub(r"<\1>", str(path))
        if not normalized.startswith("/"):
            normalized = f"/{normalized}"
        if len(normalized) > 1:
            normalized = normalized.rstrip("/")
        return normalized

    def _patch_request_accessors(self):
        from sanic.request import Request

        if getattr(Request, "_trappsec_overrides_patched", False):
            return

        def patch_property(name):
            prop = getattr(Request, name, None)
            if not isinstance(prop, property) or not prop.fget:
                return

            original_getter = prop.fget
            marker = f"_trappsec_override_{name}"

            def patched_getter(req, _orig=original_getter, _marker=marker):
                ctx = getattr(req, "ctx", None)
                if ctx is not None and hasattr(ctx, _marker):
                    return getattr(ctx, _marker)
                return _orig(req)

            setattr(Request, name, property(patched_getter, prop.fset, prop.fdel, prop.__doc__))

        patch_property("args")
        patch_property("json")
        patch_property("form")
        Request._trappsec_overrides_patched = True

    def _patch_startup(self):
        @self.app.before_server_start
        async def trappsec_init(_app, loop):
            self.inject_traps()
            self.setup_watches()
