import json
from urllib.parse import parse_qs, urlencode


class TornadoIntegration:
    def __init__(self, ts, app):
        self.ts = ts
        self.app = app
        self.watch_map = {}
        self._patched_handlers = set()

        if not self.ts.identity.ip:
            self.ts.identity.ip = lambda r: getattr(r, "remote_ip", "0.0.0.0")

        self.ts.request.path = lambda r: getattr(r, "path", getattr(r, "uri", "").split("?")[0])
        self.ts.request.user_agent = lambda r: r.headers.get("User-Agent", "unknown")
        self.ts.request.method = lambda r: getattr(r, "method", None)

        self._patch_startup()

    def inject_traps(self):
        import tornado.web

        for idx, trap in enumerate(self.ts.traps):
            methods = set([m.upper() for m in trap["methods"]])
            ts = self.ts

            class TrapHandler(tornado.web.RequestHandler):
                def _serve(self):
                    response_body, response_config = ts._trigger_trap_event(self.request, trap)
                    self.set_status(response_config["status_code"])
                    self.set_header("Content-Type", response_config["mime_type"])
                    self.write(response_body)

                async def get(self):
                    if "GET" in methods:
                        self._serve()
                    else:
                        self.set_status(405)

                async def post(self):
                    if "POST" in methods:
                        self._serve()
                    else:
                        self.set_status(405)

                async def put(self):
                    if "PUT" in methods:
                        self._serve()
                    else:
                        self.set_status(405)

                async def patch(self):
                    if "PATCH" in methods:
                        self._serve()
                    else:
                        self.set_status(405)

                async def delete(self):
                    if "DELETE" in methods:
                        self._serve()
                    else:
                        self.set_status(405)

            TrapHandler.__name__ = f"TrappsecTrapHandler{idx}"
            self.app.add_handlers(r".*$", [(trap["path"], TrapHandler)])

    def setup_watches(self):
        self.watch_map = {w["path"]: w for w in self.ts.watches}

        for rule in getattr(self.app.wildcard_router, "rules", []):
            handler_cls = getattr(rule, "target", None)
            if not handler_cls or handler_cls in self._patched_handlers:
                continue

            original_prepare = getattr(handler_cls, "prepare", None)
            integration = self

            async def wrapped_prepare(self, _orig=original_prepare):
                if _orig:
                    result = _orig(self)
                    if result is not None:
                        await result

                watch = integration.watch_map.get(self.request.path)
                if not watch:
                    return

                found_fields = []
                query_fields = watch["query_fields"]
                body_fields = watch["body_fields"]

                if query_fields and self.request.query_arguments:
                    q_dict = {
                        k: [v.decode("utf-8", errors="ignore") for v in vals]
                        for k, vals in self.request.query_arguments.items()
                    }
                    q_dict, mod = integration.ts._detect_honey_fields(q_dict, query_fields, self.request)
                    if mod:
                        found_fields.extend(mod)
                        self.request.query = urlencode(q_dict, doseq=True)

                if body_fields and self.request.body:
                    ctype = self.request.headers.get("Content-Type", "")
                    try:
                        if "application/json" in ctype:
                            data = json.loads(self.request.body.decode("utf-8"))
                            data, mod = integration.ts._detect_honey_fields(data, body_fields, self.request)
                            if mod:
                                found_fields.extend(mod)
                                self.request.body = json.dumps(data).encode("utf-8")
                        elif "application/x-www-form-urlencoded" in ctype:
                            form_data = {k: v[0] if isinstance(v, list) else v for k, v in parse_qs(self.request.body.decode("utf-8")).items()}
                            form_data, mod = integration.ts._detect_honey_fields(form_data, body_fields, self.request)
                            if mod:
                                found_fields.extend(mod)
                                self.request.body = urlencode(form_data, doseq=True).encode("utf-8")
                    except Exception as e:
                        integration.ts.logger.error("error reading body: %s", e)

                if found_fields:
                    integration.ts._trigger_watch_event(self.request, found_fields)

            handler_cls.prepare = wrapped_prepare
            self._patched_handlers.add(handler_cls)

    def _patch_startup(self):
        original_listen = self.app.listen

        def wrapped_listen(*args, **kwargs):
            self.inject_traps()
            self.setup_watches()
            return original_listen(*args, **kwargs)

        self.app.listen = wrapped_listen
