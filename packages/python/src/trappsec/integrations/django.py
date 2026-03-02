import io
import json
from urllib.parse import parse_qs, urlencode


class _DjangoLikeRequest:
    def __init__(self, environ):
        self.path = environ.get("PATH_INFO", "/")
        self.method = environ.get("REQUEST_METHOD", "GET")
        self.remote_addr = environ.get("REMOTE_ADDR", "0.0.0.0")
        self.headers = {}
        self.META = {}

        for key, value in environ.items():
            if key.startswith("HTTP_"):
                header = key[5:].replace("_", "-").lower()
                self.headers[header] = value
                self.META[key] = value


class DjangoIntegration:
    def __init__(self, ts, app):
        self.ts = ts
        self.app = app

        if not self.ts.identity.ip:
            self.ts.identity.ip = lambda r: r.headers.get("x-real-ip", r.remote_addr)

        self.ts.request.path = lambda r: r.path
        self.ts.request.user_agent = lambda r: r.headers.get("user-agent", "unknown")
        self.ts.request.method = lambda r: r.method

        self._patch_wsgi()

    def _patch_wsgi(self):
        original_call = self.app.__call__

        def wrapped_call(environ, start_response):
            path = environ.get("PATH_INFO", "/")
            method = environ.get("REQUEST_METHOD", "GET")
            request_obj = _DjangoLikeRequest(environ)

            # Trap handling
            for trap in self.ts.traps:
                if trap["path"] == path and method in trap.get("methods", []):
                    response_body, response_config = self.ts._trigger_trap_event(request_obj, trap)
                    status_line = f"{response_config['status_code']} OK"
                    headers = [("Content-Type", response_config["mime_type"])]
                    start_response(status_line, headers)
                    body = response_body.encode("utf-8") if isinstance(response_body, str) else response_body
                    return [body]

            # Watch handling
            watch = None
            for w in self.ts.watches:
                if w["path"] == path:
                    watch = w
                    break

            if watch:
                found_fields = []
                query_fields = watch.get("query_fields", {})
                body_fields = watch.get("body_fields", {})

                if query_fields:
                    qs = environ.get("QUERY_STRING", "")
                    q_dict = parse_qs(qs) if qs else {}
                    q_dict, mod = self.ts._detect_honey_fields(q_dict, query_fields, request_obj)
                    if mod:
                        found_fields.extend(mod)
                        environ["QUERY_STRING"] = urlencode(q_dict, doseq=True)

                if body_fields:
                    ctype = environ.get("CONTENT_TYPE", "")
                    body_bytes = b""
                    wsgi_input = environ.get("wsgi.input")
                    content_length = int(environ.get("CONTENT_LENGTH") or 0)
                    if wsgi_input and content_length > 0:
                        body_bytes = wsgi_input.read(content_length)

                    new_body = body_bytes
                    if body_bytes:
                        try:
                            if "application/json" in ctype:
                                data = json.loads(body_bytes.decode("utf-8"))
                                if isinstance(data, dict):
                                    data, mod = self.ts._detect_honey_fields(data, body_fields, request_obj)
                                    if mod:
                                        found_fields.extend(mod)
                                        new_body = json.dumps(data).encode("utf-8")
                            elif "application/x-www-form-urlencoded" in ctype:
                                data = {k: v[0] if isinstance(v, list) and v else v for k, v in parse_qs(body_bytes.decode("utf-8")).items()}
                                data, mod = self.ts._detect_honey_fields(data, body_fields, request_obj)
                                if mod:
                                    found_fields.extend(mod)
                                    new_body = urlencode(data, doseq=True).encode("utf-8")
                        except Exception as e:
                            self.ts.logger.error("error reading body: %s", e)

                    environ["wsgi.input"] = io.BytesIO(new_body)
                    environ["CONTENT_LENGTH"] = str(len(new_body))

                if found_fields:
                    self.ts._trigger_watch_event(request_obj, found_fields)

            return original_call(environ, start_response)

        self.app.__call__ = wrapped_call
