import json
from urllib.parse import parse_qs, urlencode


def _make_trap_handler(trap, methods, ts):
    """Factory that captures trap/methods/ts by value, avoiding the loop-variable closure bug."""
    import tornado.web

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

    return TrapHandler


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
        trap_handler_classes = set()

        for idx, trap in enumerate(self.ts.traps):
            methods = frozenset(m.upper() for m in trap["methods"])
            handler_cls = _make_trap_handler(trap, methods, self.ts)
            handler_cls.__name__ = f"TrappsecTrapHandler{idx}"
            self.app.add_handlers(r".*$", [(trap["path"], handler_cls)])
            trap_handler_classes.add(handler_cls)

        # R2: reorder rules so trap handlers come first (Tornado is order-based)
        rules = getattr(self.app.wildcard_router, "rules", None)
        if rules is not None:
            trap_rules = [r for r in rules if getattr(r, "target", None) in trap_handler_classes]
            other_rules = [r for r in rules if getattr(r, "target", None) not in trap_handler_classes]
            self.app.wildcard_router.rules = trap_rules + other_rules

    def setup_watches(self):
        self.watch_map = {w["path"]: w for w in self.ts.watches}

        # R1: build a per-handler-class list of (matcher, watch) pairs so that
        # a class registered on multiple routes resolves the right watch per request.
        # matcher._path is the canonical plain-string path (e.g. "/auth/register"),
        # which matches the watch key directly — no regex loop needed for static routes.
        class_rules = {}  # handler_cls -> [(matcher, watch), ...]

        for rule in getattr(self.app.wildcard_router, "rules", []):
            handler_cls = getattr(rule, "target", None)
            if not handler_cls:
                continue
            matcher = getattr(rule, "matcher", None)
            if not matcher:
                continue

            path = getattr(matcher, "_path", None)
            watch = self.watch_map.get(path) if path else None
            if watch is None:
                continue

            class_rules.setdefault(handler_cls, []).append((matcher, watch))

        for handler_cls, rules in class_rules.items():
            if handler_cls in self._patched_handlers:
                continue

            original_prepare = getattr(handler_cls, "prepare", None)
            integration = self
            _rules = rules  # [(matcher, watch), ...]

            async def wrapped_prepare(self, _orig=original_prepare, _rules=_rules):
                if _orig:
                    result = _orig(self)
                    if result is not None:
                        await result

                # R1: resolve the watch for this specific request path by testing
                # each rule's regex — O(1) for the common single-route case
                watch = None
                for matcher, w in _rules:
                    if matcher.regex.match(self.request.path):
                        watch = w
                        break

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
                    # R4: unpack touched; use touched (not mod) to gate mutation
                    q_dict, mod, touched_q = integration.ts._detect_honey_fields(q_dict, query_fields, self.request)
                    if mod:
                        found_fields.extend(mod)
                    if touched_q:
                        # R6: update query_arguments and arguments so get_argument() sees the change
                        for k in list(self.request.query_arguments.keys()):
                            if k not in q_dict:
                                del self.request.query_arguments[k]
                                self.request.arguments.pop(k, None)
                        self.request.query = urlencode(q_dict, doseq=True)

                if body_fields and self.request.body:
                    ctype = self.request.headers.get("Content-Type", "")
                    try:
                        if "application/json" in ctype:
                            data = json.loads(self.request.body.decode("utf-8"))
                            # R4: unpack touched; use touched to gate mutation
                            data, mod, touched_b = integration.ts._detect_honey_fields(data, body_fields, self.request)
                            if mod:
                                found_fields.extend(mod)
                            if touched_b:
                                self.request.body = json.dumps(data).encode("utf-8")
                                # R6: update body_arguments and arguments so get_body_argument() sees the change
                                for k in list(self.request.body_arguments.keys()):
                                    if k not in data:
                                        del self.request.body_arguments[k]
                                        self.request.arguments.pop(k, None)
                        elif "application/x-www-form-urlencoded" in ctype:
                            form_data = {k: v[0] if isinstance(v, list) else v for k, v in parse_qs(self.request.body.decode("utf-8")).items()}
                            # R4: unpack touched; use touched to gate mutation
                            form_data, mod, touched_b = integration.ts._detect_honey_fields(form_data, body_fields, self.request)
                            if mod:
                                found_fields.extend(mod)
                            if touched_b:
                                self.request.body = urlencode(form_data, doseq=True).encode("utf-8")
                                # R6: update body_arguments and arguments so get_body_argument() sees the change
                                for k in list(self.request.body_arguments.keys()):
                                    if k not in form_data:
                                        del self.request.body_arguments[k]
                                        self.request.arguments.pop(k, None)
                        elif "multipart/form-data" in ctype:
                            # Tornado eagerly parses multipart into body_arguments;
                            # operate on that rather than rebuilding raw bytes.
                            mp_data = {
                                k: [v.decode("utf-8", errors="ignore") for v in vals]
                                for k, vals in self.request.body_arguments.items()
                            }
                            mp_flat = {
                                k: v[0] if isinstance(v, list) and len(v) == 1 else v
                                for k, v in mp_data.items()
                            }
                            mp_flat, mod, touched_b = integration.ts._detect_honey_fields(mp_flat, body_fields, self.request)
                            if mod:
                                found_fields.extend(mod)
                            if touched_b:
                                for k in list(self.request.body_arguments.keys()):
                                    if k not in mp_flat:
                                        del self.request.body_arguments[k]
                                        self.request.arguments.pop(k, None)
                    except Exception as e:
                        integration.ts.logger.error("error reading body: %s", e)

                if found_fields:
                    # R12: fire-and-forget — never let handler emission crash the request
                    try:
                        integration.ts._trigger_watch_event(self.request, found_fields)
                    except Exception as e:
                        integration.ts.logger.error("error triggering watch event: %s", e)

            handler_cls.prepare = wrapped_prepare
            self._patched_handlers.add(handler_cls)

    def _patch_startup(self):
        original_listen = self.app.listen

        def wrapped_listen(*args, **kwargs):
            self.inject_traps()
            self.setup_watches()
            return original_listen(*args, **kwargs)

        self.app.listen = wrapped_listen
