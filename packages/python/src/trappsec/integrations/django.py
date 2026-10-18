from contextvars import ContextVar
from importlib import import_module
import io
import itertools
import re
import threading
import uuid
from urllib.parse import urlencode

from django.http import HttpResponse, HttpResponseNotAllowed, QueryDict
from django.urls import URLPattern, URLResolver, get_resolver
from django.urls.resolvers import RoutePattern
from django.utils.datastructures import MultiValueDict
from django.utils.regex_helper import normalize
from django.views.decorators.csrf import csrf_exempt

from . import _jsonbody


class TrapConflictError(RuntimeError):
    """A trap would answer a method that an existing application route serves."""


# Method of the request being routed: Django URL patterns are method-agnostic, so
# a trap overlapping a real route reads it to decline the methods it does not own.
_request_method = ContextVar("trappsec_request_method", default=None)


class _TrapURLPattern(URLPattern):
    """A trap route. With ``only_methods`` set it matches only those methods."""

    def __init__(self, pattern, callback, only_methods=None):
        super().__init__(pattern, callback)
        self.only_methods = only_methods

    def resolve(self, path):
        if self.only_methods is not None:
            method = _request_method.get()
            if method is not None and method.upper() not in self.only_methods:
                return None
        return super().resolve(path)


def _walk_routes(resolver, prefix="", _ids=None):
    """Yield (full regex, callback) for every endpoint below ``resolver``."""
    ids = _ids if _ids is not None else itertools.count()
    for entry in resolver.url_patterns:
        try:
            part = entry.pattern.regex.pattern
        except Exception:
            continue
        part = part[1:] if part.startswith("^") else part
        # Group names repeat across include() levels; make them unique.
        part = re.sub(r"\(\?P<(\w+)>", lambda m: "(?P<%s_%d>" % (m.group(1), next(ids)), part)
        if isinstance(entry, URLResolver):
            yield from _walk_routes(entry, prefix + part, ids)
        elif isinstance(entry, URLPattern):
            yield "^" + prefix + part, entry.callback


_PLACEHOLDER = re.compile(r"%\(\w+\)s")
_PROBE = "trappsec-probe-" + uuid.uuid4().hex
_SAMPLES = ("1", "trappsec", "00000000-0000-4000-8000-000000000000")


def _shapes(regex):
    """Structural shapes of a route regex: lists of segments where a segment is
    ("lit", text), ("param",) for a whole-segment parameter, or ("mixed", text)."""
    try:
        possibilities = normalize(regex)
    except Exception:
        return []
    shapes = []
    for fmt, _params in possibilities:
        segments = []
        for seg in fmt.split("/"):
            bare = _PLACEHOLDER.sub("\0", seg).replace("%%", "%")
            if bare == "\0":
                segments.append(("param",))
            elif "\0" in bare:
                segments.append(("mixed", bare))
            else:
                segments.append(("lit", bare))
        shapes.append(segments)
    return shapes


def _mixed_matches(mixed, text):
    pattern = ".+?".join(re.escape(part) for part in mixed.split("\0"))
    return re.fullmatch(pattern, text) is not None


def _samples(shape, limit=4):
    """Parameter values to try: every combination for the first ``limit`` parameters."""
    n = sum(seg[0] == "param" for seg in shape)
    for combo in itertools.product(_SAMPLES, repeat=min(n, limit)):
        yield combo + (_SAMPLES[0],) * (n - len(combo))


def _matches(compiled, path):
    return compiled.search(path) is not None


def _concrete(shape, values, probe_at=None):
    """A concrete path (no leading slash) for ``shape``, parameters taken from
    ``values`` and the segment at ``probe_at`` replaced by a random probe."""
    values = iter(values)
    out = []
    for i, seg in enumerate(shape):
        if seg[0] == "param":
            value = next(values)
        else:
            value = seg[1] if seg[0] == "lit" else seg[1].replace("\0", "1")
        out.append(_PROBE if i == probe_at else value)
    return "/".join(out)


def _is_wildcard_over(trap, route_rx, positions):
    """Whether the route accepts the trap's URL, and any other value at one of the
    trap's literal ``positions`` too (a genuine wildcard/catch-all, R2). None when
    the route never accepts the trap's URL."""
    for values in _samples(trap):
        if _matches(route_rx, _concrete(trap, values)):
            return any(_matches(route_rx, _concrete(trap, values, i)) for i in positions)
    return None


def _overlap(trap, trap_rx, route, route_rx):
    """Whether the real route ``route`` (a shape) shares URLs with the trap without
    being a wildcard/catch-all over it. Converters and parameter names are ignored:
    ``<int:pk>`` and ``<str:id>`` in the same place are the same route."""
    if len(trap) != len(route):
        # Different segment counts: a multi-segment parameter (``<path:>``, ``.*``)
        # or an optional trailing slash (``/?``). A real catch-all loses to the trap
        # (R2); a trap whose own path parameter swallows the real route shadows it.
        literals = [i for i, seg in enumerate(trap) if seg[0] != "param"]
        wildcard = _is_wildcard_over(trap, route_rx, literals)
        if wildcard is not None:
            return not wildcard
        return any(_matches(trap_rx, _concrete(route, s)) for s in _samples(route))

    trap_wider, route_wider = False, []
    for i, (t, r) in enumerate(zip(trap, route)):
        if t == r or (t[0] == r[0] == "param"):
            continue
        if t[0] == "param":
            trap_wider = True                     # the trap swallows this literal
        elif r[0] == "param":
            route_wider.append(i)
        elif t[0] == "lit" and r[0] == "mixed":
            if not _mixed_matches(r[1], t[1]):
                return False
            route_wider.append(i)
        elif t[0] == "mixed" and r[0] == "lit":
            if not _mixed_matches(t[1], r[1]):
                return False
            trap_wider = True
        else:
            return False                          # different literals: disjoint
    if trap_wider or not route_wider:
        return True                               # trap shadows (part of) the route

    # The route has a parameter where the trap has a literal. It is a genuine
    # wildcard (the trap wins, R2) only if it also accepts any other value there;
    # a narrow converter (``<int:pk>`` for a trap at ``/x/5``) means the trap
    # would take over a real URL. A route that never accepts the literal is disjoint.
    return _is_wildcard_over(trap, route_rx, route_wider) is False


def _overlapping_routes(trap_path, routes):
    """The real routes (display, callback) a trap at ``trap_path`` would shadow."""
    trap_regex = RoutePattern(trap_path.lstrip("/"), is_endpoint=True).regex
    trap_shapes = _shapes(trap_regex.pattern)
    found = []
    for regex, callback in routes:
        try:
            route_rx = re.compile(regex)
        except re.error:
            continue
        for shape in _shapes(regex):
            if any(_overlap(t, trap_regex, shape, route_rx) for t in trap_shapes):
                found.append((_display(shape), callback))
                break
    return found


def _display(shape):
    return "/".join(
        seg[1].replace("\0", "<param>") if seg[0] != "param" else "<param>" for seg in shape)


def _served_methods(callback):
    """Upper-case HTTP methods a class-based view (Django or DRF) answers, or None."""
    cls = getattr(callback, "view_class", None) or getattr(callback, "cls", None)
    if cls is None:
        return None
    actions = getattr(callback, "actions", None)  # DRF ViewSet: {"get": "list", ...}
    if actions:
        served = {m for m in actions}
        if hasattr(cls, "options"):
            served.add("options")
    else:
        names = getattr(cls, "http_method_names", ())
        served = {m for m in names if hasattr(cls, m)}
    if "get" in served:
        served.add("head")                        # View.setup() maps HEAD to GET
    return {m.upper() for m in served}


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
        self._watches_installed = False
        self._init_lock = threading.RLock()

        if not self.ts.identity.ip:
            self.ts.identity.ip = lambda r: r.META.get("REMOTE_ADDR", "0.0.0.0")

        self.ts.request.path = lambda r: r.path
        self.ts.request.user_agent = lambda r: r.headers.get("user-agent", "unknown")
        self.ts.request.method = lambda r: r.method

        self._patch_middleware_chain()

    # ------------------------------------------------------------------ public

    def bootstrap(self, strict=True):
        """Install traps and watches. Idempotent and thread-safe.

        Raises ``TrapConflictError`` (installing no trap) when a trap would shadow
        a real route; call it after declaring traps (e.g. at the end of wsgi.py /
        asgi.py) so a conflict stops the server at startup. The lazy first-request
        bootstrap passes ``strict=False``: it logs each conflict and keeps serving.
        """
        if self._bootstrapped:
            return
        with self._init_lock:
            if self._bootstrapped:
                return
            if not self._watches_installed:
                self.setup_watches()
                self._watches_installed = True
            self._register_traps(strict)
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

    def _register_traps(self, strict=True):
        """Prepend trap patterns to the root URLconf.

        A trap overlapping a real route (``_overlapping_routes``) only matches the
        methods it declares, so every other method falls through to the real view.
        It fails loud (R20) when the real view serves one of the trap's methods, or
        when its methods cannot be read (a plain function view). With ``strict``
        false (lazy first-request bootstrap) conflicting traps are logged and
        skipped instead, so a bad trap never takes the application down.
        """
        from django.conf import settings
        from django.urls import clear_url_caches

        urlconf = import_module(settings.ROOT_URLCONF)
        installed = [
            route for route in _walk_routes(get_resolver(settings.ROOT_URLCONF))
            if not getattr(route[1], "_trappsec_trap", False)
        ]

        plan, errors = [], []
        for trap in self.ts.traps:
            methods = {m.upper() for m in trap["methods"]}
            overlaps = _overlapping_routes(trap["path"], installed)
            problem = None
            for display, callback in overlaps:
                served = _served_methods(callback)
                if served is None:
                    problem = (
                        "trap %s duplicates the existing route /%s, whose view does not say "
                        "which methods it serves; move the trap or use a class-based view"
                        % (trap["path"], display))
                elif served & methods:
                    problem = (
                        "trap %s duplicates the existing route /%s for %s"
                        % (trap["path"], display, ", ".join(sorted(served & methods))))
                if problem:
                    break
            if problem:
                errors.append("trappsec error: " + problem + ".")
            else:
                plan.append((trap, methods if overlaps else None))

        if errors:
            if strict:
                raise TrapConflictError(" ".join(errors))
            for message in errors:
                self.ts.logger.error("%s The trap is not installed.", message)

        trap_patterns = [
            _TrapURLPattern(
                RoutePattern(trap["path"].lstrip("/"), is_endpoint=True),
                self._make_trap_view(trap),
                only_methods,
            )
            for trap, only_methods in plan
        ]

        # Prepend so traps take priority over application routes
        urlconf.urlpatterns = trap_patterns + list(urlconf.urlpatterns)

        # Invalidate Django's cached URL resolver so the new patterns are picked up
        clear_url_caches()

    def _make_trap_view(self, trap_config):
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
                    self.bootstrap(strict=False)
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
                token = _request_method.set(request.method)
                try:
                    return await original_chain(request)
                finally:
                    _request_method.reset(token)
            try:
                markcoroutinefunction(wrapped_chain)
            except Exception:
                pass
        else:
            def wrapped_chain(request):
                ensure_bootstrapped()
                token = _request_method.set(request.method)
                try:
                    return original_chain(request)
                finally:
                    _request_method.reset(token)

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
