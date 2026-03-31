class HapiIntegration {
    constructor(ts, app) {
        this.ts = ts;
        this.app = app;
        this._bootstrapped = false;
        this._watchHookInstalled = false;

        if (!this.ts.identity.ip) {
            this.ts.identity.ip = (request) => request.info?.remoteAddress || request.raw?.req?.socket?.remoteAddress || "0.0.0.0";
        }

        this.ts.requestContext.path = (request) => this._normalizePath(request.path || request.url?.pathname || request.raw?.req?.url);
        this.ts.requestContext.userAgent = (request) => request.headers?.["user-agent"] || null;
        this.ts.requestContext.method = (request) => (request.method || "").toUpperCase();

        const integration = this;
        const originalStart = this.app.start.bind(this.app);
        this.app.start = async function (...args) {
            integration._bootstrap();
            return originalStart(...args);
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
            this.app.route({
                method: decoy.methods.map((m) => m.toUpperCase()),
                path: decoy.path,
                handler: (request, h) => {
                    try {
                        const { response_body, response_config } = this.ts._trigger_trap_event(request, decoy);
                        return h
                            .response(response_body)
                            .code(response_config.status_code)
                            .type(response_config.mime_type);
                    } catch (e) {
                        this.ts.logger.error("Trappsec error in Hapi trap handler:", e);
                        return h
                            .response(JSON.stringify({ error: "internal error" }))
                            .code(500)
                            .type("application/json");
                    }
                }
            });
        }
    }

    setup_watches() {
        if (this._watchHookInstalled || this.ts.watches.length === 0) {
            return;
        }

        const watchMap = {};
        for (const watch of this.ts.watches) {
            watchMap[this._normalizePath(watch.path)] = watch;
        }

        this.app.ext("onPreHandler", (request, h) => {
            try {
                const routePath = this._normalizePath(request.route?.path || request.path);
                const watch = routePath ? watchMap[routePath] : null;
                if (!watch) {
                    return h.continue;
                }

                const found = [];
                const queryFields = watch.query_fields || {};
                const bodyFields = watch.body_fields || {};

                if (request.query && Object.keys(queryFields).length > 0) {
                    const { data, found_fields } = this.ts._detect_honey_fields(request.query, queryFields, request);
                    if (found_fields.length > 0) {
                        found.push(...found_fields.map((f) => ({ ...f, type: "query" })));
                        request.query = data;
                    }
                }

                if (request.payload && typeof request.payload === "object" && Object.keys(bodyFields).length > 0) {
                    const { data, found_fields } = this.ts._detect_honey_fields(request.payload, bodyFields, request);
                    if (found_fields.length > 0) {
                        found.push(...found_fields.map((f) => ({ ...f, type: "body" })));
                        request.payload = data;
                    }
                }

                if (found.length > 0) {
                    this.ts._trigger_watch_event(request, found);
                }
            } catch (e) {
                this.ts.logger.error("Trappsec error in Hapi watch handler:", e);
            }

            return h.continue;
        });

        this._watchHookInstalled = true;
    }

    _normalizePath(path) {
        if (!path || typeof path !== "string") {
            return "/";
        }
        let normalized = path.split("?")[0].split("#")[0].trim();
        if (!normalized.startsWith("/")) {
            normalized = `/${normalized}`;
        }
        if (normalized.length > 1 && normalized.endsWith("/")) {
            normalized = normalized.slice(0, -1);
        }
        return normalized;
    }
}

module.exports = HapiIntegration;
