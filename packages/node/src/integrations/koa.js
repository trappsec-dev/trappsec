class KoaIntegration {
    constructor(ts, app) {
        this.ts = ts;
        this.app = app;
        this._bootstrapped = false;

        if (!this.ts.identity.ip) {
            this.ts.identity.ip = (ctx) => ctx.ip || ctx.request?.ip || ctx.req?.socket?.remoteAddress || "0.0.0.0";
        }

        this.ts.requestContext.path = (ctx) => ctx.path || null;
        this.ts.requestContext.userAgent = (ctx) => ctx.get?.("user-agent") || ctx.headers?.["user-agent"] || null;
        this.ts.requestContext.method = (ctx) => ctx.method || null;

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

        const watchMap = {};
        for (const watch of this.ts.watches) {
            watchMap[this._normalizePath(watch.path)] = watch;
        }

        const trapMap = {};
        for (const trap of this.ts.traps) {
            trapMap[this._normalizePath(trap.path)] = trap;
        }

        // Insert at the beginning so traps/watches run before application handlers.
        this.app.middleware.unshift(async (ctx, next) => {
            const path = this._normalizePath(ctx.path);
            const method = (ctx.method || "").toUpperCase();

            const trap = trapMap[path];
            if (trap && trap.methods.includes(method)) {
                try {
                    const { response_body, response_config } = this.ts._trigger_trap_event(ctx, trap);
                    ctx.status = response_config.status_code;
                    if (response_config.mime_type) {
                        ctx.type = response_config.mime_type;
                    }
                    ctx.body = response_body;
                } catch (e) {
                    this.ts.logger.error("Trappsec error in Koa trap handler:", e);
                    ctx.status = 500;
                    ctx.type = "application/json";
                    ctx.body = JSON.stringify({ error: "internal error" });
                }
                return;
            }

            const watch = watchMap[path];
            if (watch) {
                try {
                    this._inspect(ctx, watch);
                } catch (e) {
                    this.ts.logger.error("Trappsec error in Koa watch handler:", e);
                }
            }

            await next();
        });
    }

    _inspect(ctx, watch) {
        const queryFields = watch.query_fields || {};
        const bodyFields = watch.body_fields || {};
        const found = [];

        if (ctx.query && Object.keys(queryFields).length > 0) {
            const { data, found_fields } = this.ts._detect_honey_fields(ctx.query, queryFields, ctx);
            if (found_fields.length > 0) {
                found.push(...found_fields.map((f) => ({ ...f, type: "query" })));
                ctx.query = data;
            }
        }

        if (ctx.request?.body && Object.keys(bodyFields).length > 0 && typeof ctx.request.body === "object") {
            const { data, found_fields } = this.ts._detect_honey_fields(ctx.request.body, bodyFields, ctx);
            if (found_fields.length > 0) {
                found.push(...found_fields.map((f) => ({ ...f, type: "body" })));
                ctx.request.body = data;
            }
        }

        if (found.length > 0) {
            this.ts._trigger_watch_event(ctx, found);
        }
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

module.exports = KoaIntegration;
