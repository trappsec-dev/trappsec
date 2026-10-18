import io
import threading
from urllib.parse import urlencode

from . import _jsonbody


class TrapConflictError(RuntimeError):
    """A trap path+method exactly duplicates an existing application route."""


def _scalar_dict(multidict):
    """MultiDict -> {k: scalar | [v, ...]} (lists only for repeated keys)."""
    return {k: (v[0] if len(v) == 1 else v) for k, v in multidict.to_dict(flat=False).items()}


class FlaskIntegration:
    def __init__(self, ts, app):
        self.ts = ts
        self.app = app
        self._bootstrapped = False
        self._lock = threading.RLock()

        if not self.ts.identity.ip:
            self.ts.identity.ip = lambda r: r.remote_addr or "0.0.0.0"

        self.ts.request.path = lambda r: r.path
        self.ts.request.user_agent = lambda r: str(r.user_agent)
        self.ts.request.method = lambda r: r.method

        self._trap_views = []
        self._csrf_exempted = set()
        self._patch_startup()

    # ------------------------------------------------------------------ public

    def bootstrap(self):
        """Install traps and watches. Idempotent and thread-safe."""
        if self._bootstrapped:
            return
        with self._lock:
            if self._bootstrapped:
                return
            self.inject_traps()
            self.setup_watches()
            self._bootstrapped = True

    # ------------------------------------------------------------------- traps

    def _check_conflicts(self, decoy):
        wanted = set(m.upper() for m in decoy["methods"])
        for rule in self.app.url_map.iter_rules():
            if rule.rule == decoy["path"] and (rule.methods or set()) & wanted:
                raise TrapConflictError(
                    "trappsec error: trap %s %s duplicates an existing route (endpoint `%s`)."
                    % (sorted(wanted), decoy["path"], rule.endpoint)
                )

    def inject_traps(self):
        from flask import request, Response

        traps = self.ts.traps
        for decoy in traps:
            self._check_conflicts(decoy)

        def make_endpoint(d):
            # Path arguments (<id>, <path:p>) are accepted and ignored.
            def endpoint(*_args, **_kwargs):
                try:
                    response_body, response_config = self.ts._trigger_trap_event(request, d)
                except Exception as e:
                    self.ts.logger.error("trappsec trap handling failed: %s", e)
                    response_body, response_config = self.ts._trap_fallback(d)

                return Response(
                    response_body,
                    status=response_config["status_code"],
                    headers=response_config.get("headers"),
                    mimetype=response_config["mime_type"])
            return endpoint

        for idx, decoy in enumerate(traps):
            endpoint = make_endpoint(decoy)
            endpoint.__name__ = "trappsec_%d" % idx
            self.app.add_url_rule(decoy["path"], endpoint.__name__, endpoint, methods=decoy["methods"])
            self._trap_views.append(endpoint)

    def _exempt_traps_from_csrf(self):
        """R22: Flask-WTF's CSRFProtect would answer a POST trap with 400 and no
        event. Exempt the trap views from whichever instance the app registers,
        whenever it is registered (checked per request: one dict lookup)."""
        csrf = self.app.extensions.get("csrf")
        if csrf is None or id(csrf) in self._csrf_exempted or not hasattr(csrf, "exempt"):
            return
        for view in self._trap_views:
            csrf.exempt(view)
        self._csrf_exempted.add(id(csrf))

    # ----------------------------------------------------------------- watches

    def setup_watches(self):
        if not self.ts.watches:
            return

        from flask import request
        from werkzeug.datastructures import ImmutableMultiDict

        watch_map = dict()
        for watch in self.ts.watches:
            watch_map[watch["path"]] = watch

        @self.app.before_request
        def trappsec_watcher():
            try:
                self._watch(request, watch_map, ImmutableMultiDict)
            except Exception as e:
                self.ts.logger.error("trappsec watch failed: %s", e)

    def _watch(self, request, watch_map, ImmutableMultiDict):
        if request.url_rule is None:
            return

        watch = watch_map.get(request.url_rule.rule)
        if watch is None:
            return

        query_fields = watch["query_fields"]
        body_fields = watch["body_fields"]
        found_fields = []

        if query_fields and request.args:
            q_dict = _scalar_dict(request.args)
            q_dict, mod, touched = self.ts._detect_honey_fields(q_dict, query_fields, request, source="query")
            found_fields.extend(mod)
            if touched:
                request.args = ImmutableMultiDict(q_dict)
                # Keep query_string / full_path / url consistent with the stripped args.
                qs = urlencode(q_dict, doseq=True)
                request.environ["QUERY_STRING"] = qs
                request.query_string = qs.encode("latin-1")

        if body_fields:
            media = _jsonbody.media_type(request.content_type)
            if not _jsonbody.is_form_media(media):
                # get_json(force=True) ignores Content-Type, so sniff any body.
                raw = request.get_data(cache=True)
                if _jsonbody.is_json_media(media):
                    try:
                        data = _jsonbody.parse_json_bytes(raw)
                    except Exception:
                        data = None
                else:
                    data = _jsonbody.sniff_json(raw)
                if data is not None:
                    data, mod, touched = self.ts._detect_honey_fields(data, body_fields, request, source="body")
                    found_fields.extend(mod)
                    if touched:
                        self._replace_raw_body(request, data)

            if request.form:
                form = _scalar_dict(request.form)
                form, mod, touched = self.ts._detect_honey_fields(form, body_fields, request, source="body")
                found_fields.extend(mod)
                if touched:
                    request.form = ImmutableMultiDict(form)

            if request.files:
                files = _scalar_dict(request.files)
                files, mod, touched = self.ts._detect_honey_fields(files, body_fields, request, source="body")
                found_fields.extend(mod)
                if touched:
                    request.files = ImmutableMultiDict(files)

        if found_fields:
            self.ts._trigger_watch_event(request, found_fields)

    @staticmethod
    def _replace_raw_body(request, data):
        """Make every body accessor (get_json, get_data, data, stream) see the stripped body."""
        new_body = _jsonbody.serialize(data)
        # Werkzeug caches parsed JSON as a (strict, silent) tuple.
        request._cached_json = (data, data)
        request._cached_data = new_body
        request.environ["wsgi.input"] = io.BytesIO(new_body)
        request.environ["CONTENT_LENGTH"] = str(len(new_body))
        request.__dict__["stream"] = io.BytesIO(new_body)
        ct = _jsonbody.fix_charset(request.environ.get("CONTENT_TYPE", ""))
        if ct is not None:
            request.environ["CONTENT_TYPE"] = ct

    # ----------------------------------------------------------------- startup

    def _patch_startup(self):
        original_wsgi_app = self.app.wsgi_app

        def trappsec_wrapper(environ, start_response):
            # The wrapper stays installed permanently so that middleware wrapped
            # around app.wsgi_app after Sentry() (e.g. ProxyFix) is preserved.
            if not self._bootstrapped:
                try:
                    self.bootstrap()
                except TrapConflictError:
                    raise
                except Exception as e:
                    self.ts.logger.error("trappsec bootstrap failed: %s", e)
                    self._bootstrapped = True  # do not retry on every request

            if self._trap_views:
                try:
                    self._exempt_traps_from_csrf()
                except Exception as e:
                    self.ts.logger.error("trappsec could not exempt traps from CSRF protection: %s", e)
            return original_wsgi_app(environ, start_response)

        self.app.wsgi_app = trappsec_wrapper
