import io
import json
import importlib
from urllib.parse import parse_qs, urlencode

from django.conf import settings
from django.http import HttpResponse, QueryDict
from django.urls import path
from django.views.decorators.csrf import csrf_exempt


class DjangoIntegration:
    def __init__(self, ts, app):
        self.ts = ts
        self.app = app
        self.watch_map = {}

        if not self.ts.identity.ip:
            self.ts.identity.ip = lambda r: r.headers.get("x-real-ip", r.META.get("REMOTE_ADDR", "0.0.0.0"))

        self.ts.request.path = lambda r: r.path
        self.ts.request.user_agent = lambda r: r.headers.get("user-agent", "unknown")
        self.ts.request.method = lambda r: r.method

        self.inject_traps()
        self.setup_watches()
        self._patch_get_response()

    def inject_traps(self):
        if not self.ts.traps:
            return

        root_urlconf = getattr(self.app, "urlconf", settings.ROOT_URLCONF)
        urlconf_module = importlib.import_module(root_urlconf) if isinstance(root_urlconf, str) else root_urlconf
        urlpatterns = list(getattr(urlconf_module, "urlpatterns", []))

        def make_trap_view(trap):
            @csrf_exempt
            def trap_view(request, _trap=trap):
                if request.method not in _trap.get("methods", []):
                    return HttpResponse(status=405)

                response_body, response_config = self.ts._trigger_trap_event(request, _trap)
                body = response_body.encode("utf-8") if isinstance(response_body, str) else response_body
                return HttpResponse(
                    body,
                    status=response_config["status_code"],
                    content_type=response_config["mime_type"],
                )

            return trap_view

        trap_patterns = []
        for idx, trap in enumerate(self.ts.traps):
            route = trap["path"].lstrip("/")
            trap_patterns.append(path(route, make_trap_view(trap), name=f"trappsec_{idx}"))

        if trap_patterns:
            urlconf_module.urlpatterns = trap_patterns + urlpatterns

    def setup_watches(self):
        self.watch_map = {w["path"]: w for w in self.ts.watches}

    def _patch_get_response(self):
        if not self.watch_map:
            return

        original_get_response = self.app.get_response

        def wrapped_get_response(request):
            self._watch_request(request)
            return original_get_response(request)

        self.app.get_response = wrapped_get_response

    def _watch_request(self, request):
        watch = self.watch_map.get(request.path)
        if not watch:
            return

        found_fields = []
        query_fields = watch.get("query_fields", {})
        body_fields = watch.get("body_fields", {})

        if query_fields and request.GET:
            query_data = {k: list(v) for k, v in request.GET.lists()}
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
