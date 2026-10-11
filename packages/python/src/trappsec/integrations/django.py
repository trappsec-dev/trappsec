from importlib import import_module
import io
import threading
import uuid
from urllib.parse import urlencode

from django.http import HttpResponse, HttpResponseNotAllowed, QueryDict
from django.utils.datastructures import MultiValueDict
from django.views.decorators.csrf import csrf_exempt

from . import _jsonbody


class TrapConflictError(RuntimeError):
    """A trap path exactly duplicates an existing application route."""


def _scalar_dict(multi):
    """MultiValueDict -> {k: scalar | [v, ...]} (lists only for repeated keys)."""
    return {k: (v[0] if len(v) == 1 else list(v)) for k, v in multi.lists()}


class DjangoIntegration:
    def __init__(self, ts, app):
        self.ts = ts
        self.app = app
        self.watch_map = {}
        self._is_async = False
        self._bootstrapped = False
        self._init_lock = threading.RLock()

        if not self.ts.identity.ip:
            self.ts.identity.ip = lambda r: r.META.get("REMOTE_ADDR", "0.0.0.0")

        self.ts.request.path = lambda r: r.path
        self.ts.request.user_agent = lambda r: r.headers.get("user-agent", "unknown")
        self.ts.request.method = lambda r: r.method

        self._patch_middleware_chain()

    # ------------------------------------------------------------------ public

    def bootstrap(self):
        """Install traps and watches. Idempotent and thread-safe."""
        if self._bootstrapped:
            return
        with self._init_lock:
            if self._bootstrapped:
                return
            self.setup_watches()
            self._register_traps()
            self._bootstrapped = True

    def setup_watches(self):
        self.watch_map = {w["path"]: w for w in self.ts.watches}
        if not self.watch_map:
            return
        # Watches run as the first process_view hook: after every middleware's
        # request phase (so request.user / sessions exist for identify_user) and
        # once the URL has been resolved (so the matched route pattern is known),
        # but before CSRF validation and the view read the body. Django awaits
        # every view-middleware hook under ASGI, so the hook must be async there.
        view_mw = getattr(self.app, "_view_middleware", None)
        if view_mw is not None:
            hook = self._process_view
            if self._is_async:
                async def hook(request, view_func, view_args, view_kwargs):
                    return self._process_view(request, view_func, view_args, view_kwargs)
            view_mw.insert(0, hook)

    # ------------------------------------------------------------------- traps

    @staticmethod
    def _conflicting_route(urlconf, trap_path):
        """The existing route a trap path would exactly duplicate, or None.

        The path is resolved against the URLconf, which covers re_path, converters
        and include(). A route that also matches a different value in the trap's
        last segment is a wildcard/catch-all (the trap simply takes priority over
        it, R2) and not a duplicate.
        """
        from django.urls import Resolver404, resolve

        def lookup(p):
            try:
                return resolve(p, urlconf=urlconf)
            except Resolver404:
                return None

        match = lookup("/" + trap_path.lstrip("/"))
        if match is None or getattr(match.func, "_trappsec_trap", False):
            return None
        segments = trap_path.strip("/").split("/")
        segments[-1] = "trappsec-probe-" + uuid.uuid4().hex
        probe = lookup("/" + "/".join(segments))
        if probe is not None and probe.func is match.func and probe.route == match.route:
            return None
        return match

    def _register_traps(self):
        from django.conf import settings
        from django.urls import path, clear_url_caches

        urlconf = import_module(settings.ROOT_URLCONF)
        traps = self.ts.traps

        for trap in traps:
            if self._conflicting_route(settings.ROOT_URLCONF, trap["path"]) is not None:
                raise TrapConflictError(
                    "trappsec error: trap %s duplicates an existing route." % trap["path"]
                )

        trap_patterns = []
        for trap in traps:
            def make_view(trap_config):
                @csrf_exempt
                def trap_view(request, *_args, **_kwargs):  # path arguments are ignored
                    if request.method not in trap_config["methods"]:
                        return HttpResponseNotAllowed(trap_config["methods"])
                    try:
                        body, cfg = self.ts._trigger_trap_event(request, trap_config)
                    except Exception as e:
                        self.ts.logger.error("trappsec trap handling failed: %s", e)
                        body, cfg = self.ts._trap_fallback(trap_config)
                    if isinstance(body, str):
                        body = body.encode("utf-8")
                    return HttpResponse(
                        body,
                        status=cfg["status_code"],
                        content_type=cfg["mime_type"],
                    )
                trap_view.__name__ = "trappsec_trap"
                trap_view._trappsec_trap = True
                return trap_view
            trap_patterns.append(
                path(trap["path"].lstrip("/"), make_view(trap))
            )

        # Prepend so traps take priority over application routes
        urlconf.urlpatterns = trap_patterns + list(urlconf.urlpatterns)

        # Invalidate Django's cached URL resolver so the new patterns are picked up
        clear_url_caches()

    # ----------------------------------------------------------------- startup

    def _patch_middleware_chain(self):
        # Django builds the request middleware chain lazily.
        if getattr(self.app, "_middleware_chain", None) is None:
            self.app.load_middleware()

        original_chain = self.app._middleware_chain
        self._is_async = False

        def ensure_bootstrapped():
            if not self._bootstrapped:
                try:
                    self.bootstrap()
                except TrapConflictError:
                    raise
                except Exception as e:
                    self.ts.logger.error("trappsec bootstrap failed: %s", e)
                    self._bootstrapped = True

        try:
            from asgiref.sync import iscoroutinefunction, markcoroutinefunction
            self._is_async = iscoroutinefunction(original_chain)
        except Exception:
            pass

        if self._is_async:
            async def wrapped_chain(request):
                ensure_bootstrapped()
                return await original_chain(request)
            try:
                markcoroutinefunction(wrapped_chain)
            except Exception:
                pass
        else:
            def wrapped_chain(request):
                ensure_bootstrapped()
                return original_chain(request)

        self.app._middleware_chain = wrapped_chain

    def _process_view(self, request, view_func, view_args, view_kwargs):
        try:
            match = getattr(request, "resolver_match", None)
            route = getattr(match, "route", None)
            if route is None:
                return None
            self._watch_request(request, "/" + route)
        except Exception as e:
            self.ts.logger.error("trappsec watch failed: %s", e)
        return None

    # ----------------------------------------------------------------- watches

    def _watch_request(self, request, route_pattern):
        watch = self.watch_map.get(route_pattern)
        if not watch:
            return

        found_fields = []
        query_fields = watch.get("query_fields", {})
        body_fields = watch.get("body_fields", {})

        if query_fields and request.GET:
            query_data = _scalar_dict(request.GET)
            query_data, mod, touched = self.ts._detect_honey_fields(query_data, query_fields, request, source="query")
            found_fields.extend(mod)
            if touched:
                request.GET = self._to_querydict(query_data)
                request.META["QUERY_STRING"] = urlencode(query_data, doseq=True)

        if body_fields:
            try:
                found_fields.extend(self._watch_body(request, body_fields))
            except Exception as e:
                self.ts.logger.error("error inspecting request body: %s", e)

        if found_fields:
            self.ts._trigger_watch_event(request, found_fields)

    def _watch_body(self, request, body_fields):
        found = []
        content_type = request.META.get("CONTENT_TYPE", "").lower()

        if "multipart/form-data" in content_type:
            # Django parses multipart into POST and FILES together. Force the
            # parse now, then overwrite both caches so that neither a later
            # request.FILES nor request.POST access re-parses the original body.
            if request.method != "POST":
                return found
            self._buffer_multipart_body(request)
            post_data = _scalar_dict(request.POST)
            post_data, mod, post_touched = self.ts._detect_honey_fields(post_data, body_fields, request, source="body")
            found.extend(mod)
            file_data = _scalar_dict(request.FILES)
            file_data, fmod, files_touched = self.ts._detect_honey_fields(file_data, body_fields, request, source="body")
            found.extend(fmod)
            if post_touched:
                request._post = self._to_querydict(post_data)
            if files_touched:
                request._files = MultiValueDict(
                    {k: v if isinstance(v, list) else [v] for k, v in file_data.items()})
            return found

        try:
            body_bytes = request.body
        except Exception:
            return found
        if not body_bytes:
            return found

        new_body = None
        is_form = "application/x-www-form-urlencoded" in content_type
        if not is_form:
            # json.loads(bytes) auto-detects UTF-8/16/32 like the app; sniff any
            # content type since request.body is parsed by the app regardless.
            if "json" in content_type:
                try:
                    data = _jsonbody.parse_json_bytes(body_bytes)
                except Exception:
                    return found
            else:
                data = _jsonbody.sniff_json(body_bytes)
            if data is None:
                return found
            data, mod, touched = self.ts._detect_honey_fields(data, body_fields, request, source="body")
            found.extend(mod)
            if touched:
                new_body = _jsonbody.serialize(data)
                ct = _jsonbody.fix_charset(request.META.get("CONTENT_TYPE", ""))
                if ct is not None:
                    request.META["CONTENT_TYPE"] = ct
        else:
            qd = QueryDict(body_bytes, encoding=request.encoding)
            data = _scalar_dict(qd)
            data, mod, touched = self.ts._detect_honey_fields(data, body_fields, request, source="body")
            found.extend(mod)
            if touched:
                new_body = urlencode(data, doseq=True).encode("utf-8")

        if new_body is not None:
            # Mutates private WSGIRequest internals to replace body bytes and invalidate
            # Django's cached parsed forms; the stripped bytes are then what every later
            # POST/FILES/body access sees. Tested against Django 4.x-6.x.
            # On upgrade: verify _body, _stream, _post, _files attribute names in
            # django/core/handlers/wsgi.py and django/http/request.py.
            request._body = new_body
            request._stream = io.BytesIO(new_body)
            request.META["CONTENT_LENGTH"] = str(len(new_body))
            for attr in ("_post", "_files"):
                if hasattr(request, attr):
                    delattr(request, attr)
        return found

    @staticmethod
    def _buffer_multipart_body(request):
        """Read request.body before request.POST so the view can still read request.body.

        Django raises RawPostDataException for body-after-POST on multipart. Only
        done when the body fits DATA_UPLOAD_MAX_MEMORY_SIZE; larger bodies keep
        streaming through the multipart parser (POST/FILES only).
        """
        from django.conf import settings

        limit = settings.DATA_UPLOAD_MAX_MEMORY_SIZE
        try:
            length = int(request.META.get("CONTENT_LENGTH") or 0)
        except ValueError:
            return
        if limit is not None and length > limit:
            return
        try:
            request.body
        except Exception:
            pass

    def _to_querydict(self, data):
        query_dict = QueryDict("", mutable=True)
        for key, value in data.items():
            if isinstance(value, (list, tuple)):
                for item in value:
                    query_dict.appendlist(key, item)
            else:
                query_dict.appendlist(key, value)
        query_dict._mutable = False
        return query_dict
