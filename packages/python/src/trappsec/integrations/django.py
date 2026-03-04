import io
import json
from urllib.parse import parse_qs, urlencode

from django.http import HttpResponse, QueryDict


class DjangoIntegration:
    def __init__(self, ts, app):
        self.ts = ts
        self.app = app
        self.trap_map = {}
        self.watch_map = {}

        if not self.ts.identity.ip:
            self.ts.identity.ip = lambda r: r.headers.get("x-real-ip", r.META.get("REMOTE_ADDR", "0.0.0.0"))

        self.ts.request.path = lambda r: r.path
        self.ts.request.user_agent = lambda r: r.headers.get("user-agent", "unknown")
        self.ts.request.method = lambda r: r.method

        self.setup_traps()
        self.setup_watches()
        self._patch_middleware_chain()

    def setup_traps(self):
        self.trap_map = {t["path"]: t for t in self.ts.traps}

    def setup_watches(self):
        self.watch_map = {w["path"]: w for w in self.ts.watches}

    def _patch_middleware_chain(self):
        if not self.watch_map and not self.trap_map:
            return

        # Django builds the request middleware chain lazily.
        if getattr(self.app, "_middleware_chain", None) is None:
            self.app.load_middleware()

        original_chain = self.app._middleware_chain

        def wrapped_chain(request):
            trap = self.trap_map.get(request.path)
            if trap and request.method in trap.get("methods", []):
                response_body, response_config = self.ts._trigger_trap_event(request, trap)
                body = response_body.encode("utf-8") if isinstance(response_body, str) else response_body
                return HttpResponse(
                    body,
                    status=response_config["status_code"],
                    content_type=response_config["mime_type"],
                )

            self._watch_request(request)
            return original_chain(request)

        self.app._middleware_chain = wrapped_chain

    def _watch_request(self, request):
        watch = self.watch_map.get(request.path)
        if not watch:
            return

        found_fields = []
        query_fields = watch.get("query_fields", {})
        body_fields = watch.get("body_fields", {})

        if query_fields and request.GET:
            query_data = {
                k: (v[0] if isinstance(v, list) and len(v) == 1 else v)
                for k, v in request.GET.lists()
            }
            query_data, mod = self.ts._detect_honey_fields(query_data, query_fields, request)
            if mod:
                found_fields.extend(mod)
                request.GET = self._to_querydict(query_data)
                request.META["QUERY_STRING"] = urlencode(query_data, doseq=True)

        if body_fields:
            content_type = request.META.get("CONTENT_TYPE", "")
            new_body = None

            try:
                body_bytes = request.body
            except Exception:
                body_bytes = b""

            if body_bytes:
                try:
                    if "application/json" in content_type:
                        data = json.loads(body_bytes.decode("utf-8"))
                        if isinstance(data, dict):
                            data, mod = self.ts._detect_honey_fields(data, body_fields, request)
                            if mod:
                                found_fields.extend(mod)
                                new_body = json.dumps(data).encode("utf-8")
                    elif "application/x-www-form-urlencoded" in content_type:
                        data = {
                            k: v[0] if isinstance(v, list) and v else v
                            for k, v in parse_qs(body_bytes.decode("utf-8")).items()
                        }
                        data, mod = self.ts._detect_honey_fields(data, body_fields, request)
                        if mod:
                            found_fields.extend(mod)
                            new_body = urlencode(data, doseq=True).encode("utf-8")
                except Exception as e:
                    self.ts.logger.error("error reading body: %s", e)

            if new_body is not None:
                request._body = new_body
                request._stream = io.BytesIO(new_body)
                request.META["CONTENT_LENGTH"] = str(len(new_body))

                if hasattr(request, "_post"):
                    del request._post
                if hasattr(request, "_files"):
                    del request._files

        if found_fields:
            self.ts._trigger_watch_event(request, found_fields)

    def _to_querydict(self, data):
        query_dict = QueryDict("", mutable=True)
        for key, value in data.items():
            if isinstance(value, list):
                for item in value:
                    query_dict.appendlist(key, item)
            else:
                query_dict[key] = value
        query_dict._mutable = False
        return query_dict
