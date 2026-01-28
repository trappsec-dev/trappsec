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

        const ts = this.ts;

        for (let layer of this.app.router.stack) {
            const oldHandler = layer.handle

            layer.handle = function (req, res, next) {
                if (req.route) {
                    const watch = watchMap[req.route.path];
                    if (watch) {
                        const query_fields = watch.query_fields;
                        const body_fields = watch.body_fields;
                        let found = [];

                        if (Object.keys(query_fields).length > 0 && req.query) {
                            const { data, found_fields } = ts._detect_honey_fields(req.query, query_fields, req);
                            if (found_fields.length > 0) {
                                found.push(...found_fields);
                                req.query = data;
                            }
                        }

                        if (Object.keys(body_fields).length > 0 && req.body) {
                            const { data, found_fields } = ts._detect_honey_fields(req.body, body_fields, req);
                            if (found_fields.length > 0) {
                                found.push(...found_fields);
                                req.body = data;
                            }
                        }

                        if (found.length > 0) {
                            ts._trigger_watch_event(req, found);
                        }
                    }
                }
                oldHandler(req, res, next);
            }
        }
    }
}

module.exports = ExpressIntegration;
