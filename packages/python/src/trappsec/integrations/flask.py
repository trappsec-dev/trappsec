
class FlaskIntegration:
    def __init__(self, ts, app):
        self.ts = ts
        self.app = app

        if not self.ts.identity.ip: 
            self.ts.identity.ip = lambda r: r.remote_addr or "0.0.0.0"
        
        self.ts.request.path = lambda r: r.path
        self.ts.request.user_agent = lambda r: str(r.user_agent)
        self.ts.request.method = lambda r: r.method

        self._patch_startup()

    def inject_traps(self):
        from flask import request, Response

        for idx, decoy in enumerate(self.ts.traps):
            def endpoint(d=decoy):
                response_body, response_config = self.ts._trigger_trap_event(request, d)
                
                return Response(
                    response_body,
                    status=response_config["status_code"], 
                    mimetype=response_config["mime_type"])
            
            endpoint.__name__ = f"trappsec_{idx}"
            self.app.add_url_rule(decoy["path"], endpoint.__name__, endpoint, methods=decoy["methods"])
    
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
            if request.url_rule is None:
                return
            
            matched_rule = request.url_rule.rule
            if matched_rule not in watch_map:
                return

            self.ts.logger.info(f"matched rule: {watch_map[matched_rule]}")
            query_fields = watch_map[matched_rule]["query_fields"]
            body_fields = watch_map[matched_rule]["body_fields"]
                
            found_fields = []
            if request.args and query_fields:
                q_dict = request.args.to_dict(flat=False)
                q_dict, mod = self.ts._detect_honey_fields(q_dict, query_fields, request)
                if mod: 
                    found_fields.extend(mod)
                    request.args = ImmutableMultiDict(q_dict)

            if request.is_json and body_fields:
                data = request.get_json(silent=True)
                if data:
                    data, mod = self.ts._detect_honey_fields(data, body_fields, request)
                    if mod:
                        found_fields.extend(mod)
                        current = getattr(request, '_cached_json', None)
                        if isinstance(current, tuple): 
                            request._cached_json = (data, current[1])
                        else: 
                            request._cached_json = data

            if request.form and body_fields:
                form_copy = request.form.to_dict(flat=True)
                form, mod = self.ts._detect_honey_fields(form_copy, body_fields, request)
                if mod: 
                    found_fields.extend(mod)
                    request.form = ImmutableMultiDict(form)
            
            if found_fields:
                self.ts._trigger_watch_event(request, found_fields)

    
    def _patch_startup(self):
        original_wsgi_app = self.app.wsgi_app

        def trappsec_wrapper(environ, start_response):
            self.inject_traps()
            self.setup_watches()

            # un-patch after first request
            self.app.wsgi_app = original_wsgi_app

            return original_wsgi_app(environ, start_response)

        self.app.wsgi_app = trappsec_wrapper

