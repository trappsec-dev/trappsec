const http = require('http');

class ExpressIntegration {
    constructor(ts, app) {
        this.ts = ts;
        this.app = app;

        if (!this.ts.identity.ip) {
            this.ts.identity.ip = r => r.ip || r.socket.remoteAddress || "0.0.0.0";
        }

        this.ts.requestContext.path = r => r.path;
        this.ts.requestContext.userAgent = r => r.get('User-Agent');
        this.ts.requestContext.method = r => r.method;

        const integration = this;

        app.listen = function (...args) {
            integration.inject_traps();
            integration.setup_watches();

            var server = http.createServer(app);
            return server.listen(...args);
        }
    }

    inject_traps() {
        const traps = this.ts.traps;
        for (const decoy of traps) {
            const path = decoy.path;
            const methods = decoy.methods.map(m => m.toLowerCase());

            const handler = (req, res) => {
                const { response_body, response_config } = this.ts._trigger_trap_event(req, decoy);
                res.status(response_config.status_code);
                res.type(response_config.mime_type);
                res.send(response_body);
            };

            if (methods.includes('get')) this.app.get(path, handler);
            if (methods.includes('post')) this.app.post(path, handler);
            if (methods.includes('put')) this.app.put(path, handler);
            if (methods.includes('delete')) this.app.delete(path, handler);
            if (methods.includes('patch')) this.app.patch(path, handler);
        }
    }

    setup_watches() {
        const watches = this.ts.watches;
        if (watches.length === 0) return;

        const watchMap = {};
        for (const w of watches) {
            watchMap[w.path] = w;
        }

        this._wrapRouterStack(this.app.router.stack, watchMap);
    }

    _wrapRouterStack(stack, watchMap) {
        const ts = this.ts;

        for (const layer of stack) {
            if (!layer || typeof layer.handle !== 'function') continue;

            // Sub-router: layer.route is null and the handle function carries its own
            // .stack of child layers. Recurse so inner route layers get wrapped.
            // The mount prefix is baked into req.baseUrl by the time the inner
            // handler runs, so no prefix tracking is needed here.
            if (!layer.route && Array.isArray(layer.handle.stack)) {
                this._wrapRouterStack(layer.handle.stack, watchMap);
                continue;
            }

            // Only wrap route-matched layers; skip plain middleware and already-wrapped layers.
            if (!layer.route || layer.handle.__trappsecWrapped) continue;

            const oldHandler = layer.handle;
            const wrapped = function (req, res, next) {
                if (req.route) {
                    // req.baseUrl is the mount prefix stripped by any parent router
                    // (empty string for top-level routes). Concatenating with
                    // req.route.path reconstructs the full registered pattern, which
                    // is the key used in watchMap.
                    const fullPath = (req.baseUrl || '') + req.route.path;
                    const watch = watchMap[fullPath];
                    if (watch) {
                        const query_fields = watch.query_fields;
                        const body_fields = watch.body_fields;
                        let found = [];

                        if (Object.keys(query_fields).length > 0 && req.query) {
                            const { data, found_fields, touched } = ts._detect_honey_fields(req.query, query_fields, req);
                            if (found_fields.length > 0) found.push(...found_fields);
                            if (touched) Object.defineProperty(req, 'query', { value: data, writable: true, configurable: true });
                        }

                        if (Object.keys(body_fields).length > 0 && req.body) {
                            const { data, found_fields, touched } = ts._detect_honey_fields(req.body, body_fields, req);
                            if (found_fields.length > 0) found.push(...found_fields);
                            if (touched) req.body = data;
                        }

                        if (found.length > 0) {
                            ts._trigger_watch_event(req, found);
                        }
                    }
                }
                return oldHandler(req, res, next);
            };

            wrapped.__trappsecWrapped = true;
            layer.handle = wrapped;
        }
    }
}

module.exports = ExpressIntegration;
