import threading


class TrapConflictError(RuntimeError):
    """A trap path+method exactly duplicates an existing application route."""


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

        for idx, decoy in enumerate(traps):
            def endpoint(d=decoy):
                try:
                    response_body, response_config = self.ts._trigger_trap_event(request, d)
                except Exception as e:
                    self.ts.logger.error("trappsec trap handling failed: %s", e)
                    response_body, response_config = self._fallback(d)

                return Response(
                    response_body,
                    status=response_config["status_code"],
                    mimetype=response_config["mime_type"])

            endpoint.__name__ = "trappsec_%d" % idx
            self.app.add_url_rule(decoy["path"], endpoint.__name__, endpoint, methods=decoy["methods"])

    @staticmethod
    def _fallback(trap):
        import json
        cfg = trap["response.unauthenticated"]
        body = cfg.get("response_body")
        if callable(body):
            body = {}
        if not isinstance(body, (str, bytes)):
            body = json.dumps(body, default=str)
        return body, cfg

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
            q_dict = request.args.to_dict(flat=False)
            q_dict, mod, touched = self.ts._detect_honey_fields(q_dict, query_fields, request, source="query")
            found_fields.extend(mod)
            if touched:
                request.args = ImmutableMultiDict(q_dict)

        if body_fields:
            if request.is_json:
                data = request.get_json(silent=True)
                if data is not None:
                    data, mod, touched = self.ts._detect_honey_fields(data, body_fields, request, source="body")
                    found_fields.extend(mod)
                    if touched:
                        # Werkzeug caches parsed JSON as a (strict, silent) tuple.
                        request._cached_json = (data, data)

            if request.form:
                form = request.form.to_dict(flat=False)
                form, mod, touched = self.ts._detect_honey_fields(form, body_fields, request, source="body")
                found_fields.extend(mod)
                if touched:
                    request.form = ImmutableMultiDict(form)

            if request.files:
                files = request.files.to_dict(flat=False)
                files, mod, touched = self.ts._detect_honey_fields(files, body_fields, request, source="body")
                found_fields.extend(mod)
                if touched:
                    request.files = ImmutableMultiDict(files)

        if found_fields:
            self.ts._trigger_watch_event(request, found_fields)

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

            return original_wsgi_app(environ, start_response)

        self.app.wsgi_app = trappsec_wrapper
