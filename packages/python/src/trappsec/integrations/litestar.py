import json
from urllib.parse import parse_qs, urlencode


class _ASGIRequest:
    def __init__(self, scope, headers, body_data=None):
        self.scope = scope
        self.headers = headers
        self.path = scope.get("path", "/")
        self.method = scope.get("method", "GET")
        client = scope.get("client") or ("0.0.0.0", 0)
        self.client = type("Client", (), {"host": client[0]})()
        self.body_data = body_data or {}


class LitestarIntegration:
    def __init__(self, ts, app):
        self.ts = ts
        self.app = app

        if not self.ts.identity.ip:
            self.ts.identity.ip = lambda r: r.headers.get("x-real-ip", r.client.host if r.client else "0.0.0.0")

        self.ts.request.path = lambda r: r.path
        self.ts.request.user_agent = lambda r: r.headers.get("user-agent", "unknown")
        self.ts.request.method = lambda r: r.method

        self._patch_asgi_handler()

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
            method = scope.get("method", "GET")

            # Trap handling
            trap = None
            for d in self.ts.traps:
                if d["path"] == path and method in d.get("methods", []):
                    trap = d
                    break

            if trap:
                req = _ASGIRequest(scope, headers)
                response_body, response_config = self.ts._trigger_trap_event(req, trap)
                await send({
                    "type": "http.response.start",
                    "status": response_config["status_code"],
                    "headers": [(b"content-type", response_config["mime_type"].encode("latin1"))],
                })
                await send({
                    "type": "http.response.body",
                    "body": response_body.encode("utf-8") if isinstance(response_body, str) else response_body,
                    "more_body": False,
                })
                return

            # Watch handling
            watch = None
            for w in self.ts.watches:
                if w["path"] == path:
                    watch = w
                    break

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
                q_dict, mod = self.ts._detect_honey_fields(q_dict, query_fields, None)
                if mod:
                    found_fields.extend(mod)
                    scope["query_string"] = urlencode(q_dict, doseq=True).encode("utf-8")

            content_type = headers.get("content-type", "")
            body_data = {}
            new_body = body_bytes
            if body_fields and body_bytes:
                try:
                    if "application/json" in content_type:
                        body_data = json.loads(body_bytes.decode("utf-8"))
                        if isinstance(body_data, dict):
                            body_data, mod = self.ts._detect_honey_fields(body_data, body_fields, None)
                            if mod:
                                found_fields.extend(mod)
                                new_body = json.dumps(body_data).encode("utf-8")
                    elif "application/x-www-form-urlencoded" in content_type:
                        body_data = {k: v[0] if isinstance(v, list) and v else v for k, v in parse_qs(body_bytes.decode("utf-8")).items()}
                        body_data, mod = self.ts._detect_honey_fields(body_data, body_fields, None)
                        if mod:
                            found_fields.extend(mod)
                            new_body = urlencode(body_data, doseq=True).encode("utf-8")
                except Exception as e:
                    self.ts.logger.error("error reading body: %s", e)

            if found_fields:
                req = _ASGIRequest(scope, headers, body_data=body_data)
                self.ts._trigger_watch_event(req, found_fields)

            sent = False

            async def new_receive():
                nonlocal sent
                if sent:
                    return {"type": "http.request", "body": b"", "more_body": False}
                sent = True
                return {"type": "http.request", "body": new_body, "more_body": False}

            return await original_handler(scope, new_receive, send)

        self.app.asgi_handler = wrapped
