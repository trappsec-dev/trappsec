class FastifyIntegration {
    constructor(ts, app) {
        this.ts = ts;
        this.app = app;
        this._bootstrapped = false;
        this._watchHookInstalled = false;

        if (!this.ts.identity.ip) {
            this.ts.identity.ip = (req) => req.ip || req.socket?.remoteAddress || req.raw?.socket?.remoteAddress || "0.0.0.0";
        }

        this.ts.requestContext.path = (req) => this._normalizePath(req.url || req.raw?.url);
        this.ts.requestContext.userAgent = (req) => req.headers?.["user-agent"] || req.raw?.headers?.["user-agent"] || null;
        this.ts.requestContext.method = (req) => req.method || req.raw?.method || null;

        const integration = this;
        const originalListen = this.app.listen.bind(this.app);
        this.app.listen = function (...args) {
            integration._bootstrap();
            return originalListen(...args);
        };
    }

    _bootstrap() {
        if (this._bootstrapped) {
            return;
        }
        this._bootstrapped = true;
        this.inject_traps();
        this.setup_watches();
    }

    inject_traps() {
        for (const decoy of this.ts.traps) {
            const methods = decoy.methods.map((method) => method.toUpperCase());
            this.app.route({
                method: methods,
                url: decoy.path,
                handler: (req, reply) => {
                    try {
                        const { response_body, response_config } = this.ts._trigger_trap_event(req, decoy);
                        reply
                            .code(response_config.status_code)
                            .header("content-type", response_config.mime_type)
                            .send(response_body);
                    } catch (e) {
                        this.ts.logger.error("Trappsec error in Fastify trap handler:", e);
                        reply
                            .code(500)
                            .header("content-type", "application/json")
                            .send(JSON.stringify({ error: "internal error" }));
                    }
                },
            });
        }
    }

    setup_watches() {
        if (this._watchHookInstalled || this.ts.watches.length === 0) {
            return;
        }

        const watchMap = {};
        for (const watch of this.ts.watches) {
            const path = this._normalizePath(watch.path);
            if (path) {
                watchMap[path] = watch;
            }
        }

        this.app.addHook("preHandler", (req, _reply, done) => {
            try {
                const routePath = this._normalizePath(req.routeOptions?.url || req.routerPath || req.context?.config?.url || req.url);
                const watch = routePath ? watchMap[routePath] : null;
                if (!watch) {
                    done();
                    return;
                }

                const found = [];
                const queryFields = watch.query_fields || {};
                const bodyFields = watch.body_fields || {};

                if (req.query && Object.keys(queryFields).length > 0) {
                    const { data, found_fields } = this.ts._detect_honey_fields(req.query, queryFields, req);
                    if (found_fields.length > 0) {
                        found.push(...found_fields.map((f) => ({ ...f, type: "query" })));
                        req.query = data;
                    }
                }

                if (req.body && Object.keys(bodyFields).length > 0 && typeof req.body === "object") {
                    const { data, found_fields } = this.ts._detect_honey_fields(req.body, bodyFields, req);
                    if (found_fields.length > 0) {
                        found.push(...found_fields.map((f) => ({ ...f, type: "body" })));
                        req.body = data;
                    }
                }

                if (found.length > 0) {
                    this.ts._trigger_watch_event(req, found);
                }
            } catch (e) {
                this.ts.logger.error("Trappsec error in Fastify watch handler:", e);
            }
            done();
        });

        this._watchHookInstalled = true;
    }

    _normalizePath(path) {
        if (!path || typeof path !== "string") {
            return null;
        }

        let normalized = path.split("?")[0].split("#")[0].trim();
        if (!normalized) {
            return null;
        }
        if (!normalized.startsWith("/")) {
            normalized = `/${normalized}`;
        }
        if (normalized.length > 1 && normalized.endsWith("/")) {
            normalized = normalized.slice(0, -1);
        }
        return normalized;
    }
}

module.exports = FastifyIntegration;
