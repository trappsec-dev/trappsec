import importlib
import io
import json
import threading
from urllib.parse import parse_qs, urlencode

from django.http import HttpResponse, HttpResponseNotAllowed, QueryDict
from django.urls import resolve, Resolver404


class DjangoIntegration:
    _bootstrapped = False

    def __init__(self, ts, app):
        if DjangoIntegration._bootstrapped:
            raise RuntimeError("trappsec error: DjangoIntegration already bootstrapped.")
        DjangoIntegration._bootstrapped = True

        self.ts = ts
        self.app = app
        self.watch_map = {}
        self._initialized = False
        self._init_lock = threading.Lock()

        if not self.ts.identity.ip:
            self.ts.identity.ip = lambda r: r.META.get("REMOTE_ADDR", "0.0.0.0")

        self.ts.request.path = lambda r: r.path
        self.ts.request.user_agent = lambda r: r.headers.get("user-agent", "unknown")
        self.ts.request.method = lambda r: r.method

        self._patch_middleware_chain()

    def setup_watches(self):
        self.watch_map = {w["path"]: w for w in self.ts.watches}

    def _register_traps(self):
        from django.conf import settings
        from django.urls import path, clear_url_caches

        urlconf = importlib.import_module(settings.ROOT_URLCONF)

        trap_patterns = []
        for trap in self.ts.traps:
            def make_view(trap_config):
                def trap_view(request):
                    if request.method not in trap_config["methods"]:
                        return HttpResponseNotAllowed(trap_config["methods"])
                    body, cfg = self.ts._trigger_trap_event(request, trap_config)
                    if isinstance(body, str):
                        body = body.encode("utf-8")
                    return HttpResponse(
                        body,
                        status=cfg["status_code"],
                        content_type=cfg["mime_type"],
                    )
                trap_view.__name__ = "trappsec_trap"
                return trap_view
            trap_patterns.append(
                path(trap["path"].lstrip("/"), make_view(trap))
            )

        # Prepend so traps take priority over application routes
        urlconf.urlpatterns = trap_patterns + urlconf.urlpatterns

        # Invalidate Django's cached URL resolver so the new patterns are picked up
        clear_url_caches()

    def _patch_middleware_chain(self):
        # Django builds the request middleware chain lazily.
        if getattr(self.app, "_middleware_chain", None) is None:
            self.app.load_middleware()

        original_chain = self.app._middleware_chain

        def wrapped_chain(request):
            if not self._initialized:
                with self._init_lock:
                    if not self._initialized:  # re-check: another thread may have finished while we waited
                        self.setup_watches()
                        self._register_traps()
                        self._initialized = True

            try:
                route_pattern = "/" + resolve(request.path).route
            except Resolver404:
                route_pattern = request.path

            self._watch_request(request, route_pattern)
            return original_chain(request)

        self.app._middleware_chain = wrapped_chain

    def _watch_request(self, request, route_pattern):
        watch = self.watch_map.get(route_pattern)
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
                # Mutates private WSGIRequest internals to replace body bytes and invalidate
                # Django's cached parsed forms. Tested against Django 4.x–5.x.
                # On upgrade: verify _body, _stream, _post, _files attribute names in
                # django/core/handlers/wsgi.py and django/http/request.py.
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
