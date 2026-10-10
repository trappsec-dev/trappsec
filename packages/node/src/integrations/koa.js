'use strict';

const {
    normalizePath, isObject, buildWatchMap, hasFields, replaceInPlace, detect,
    resolveTrap, emitWatch, warnOnce, BODY_METHODS
} = require('./_common');

// Watch paths are the FULL registered pattern, including any router prefix
// (new Router({prefix: '/v1'}) + router.get('/users/:id') -> '/v1/users/:id').
//
// Strategy (no private Koa/@koa/router context fields are read):
//  * watches: every method-bearing @koa/router layer found in app.middleware gets a
//    wrapper prepended to its own handler stack. It runs after the router resolved
//    params and after any router-level middleware, but BEFORE the application handler,
//    so honey fields are stripped before the handler sees them and are inspected
//    even if the handler throws.
//  * traps: a dedicated router registered immediately before the first application
//    router, i.e. after ordinary middleware (auth, body parsers) and before any
//    application route, so traps are real routes that cannot be shadowed.
class KoaIntegration {
    constructor(ts, app) {
        this.ts = ts;
        this.app = app;
        this._bootstrapped = false;
        this._warned = new Set();

        if (!this.ts.identity.ip) {
            this.ts.identity.ip = (ctx) => ctx.ip || ctx.request?.ip || ctx.req?.socket?.remoteAddress || "0.0.0.0";
        }

        this.ts.requestContext.path = (ctx) => ctx.path || null;
        this.ts.requestContext.userAgent = (ctx) => ctx.get?.("user-agent") || ctx.headers?.["user-agent"] || null;
        this.ts.requestContext.method = (ctx) => ctx.method || null;

        const integration = this;

        // app.callback() is what listen(), supertest and http.createServer(app.callback())
        // all go through, so this bootstraps before the first request in every case.
        const originalCallback = app.callback;
        app.callback = function (...args) {
            integration.bootstrap();
            return originalCallback.apply(this, args);
        };

        // Safety net: first request bootstraps if callback() ran before routes were added.
        const front = async function trappsecBootstrap(ctx, next) {
            if (!integration._bootstrapped) {
                try {
                    integration.bootstrap();
                } catch (e) {
                    integration.ts.logger.error('Trappsec bootstrap failed on first request: ', e);
                }
            }
            return next();
        };
        front.__trappsecFront = true;
        app.middleware.unshift(front);
    }

    // Public and idempotent.
    bootstrap() {
        if (this._bootstrapped) return;
        this._bootstrapped = true;
        this.inject_traps();
        this.setup_watches();
    }

    _routers() {
        return this.app.middleware
            .filter((m) => m && m.router && !m.__trappsecTrap)
            .map((m) => m.router);
    }

    _loadRouterClass(routers) {
        if (routers.length > 0 && typeof routers[0].constructor === 'function' && routers[0].constructor !== Object) {
            return routers[0].constructor;
        }
        for (const name of ['@koa/router', 'koa-router']) {
            for (const opts of [undefined, { paths: [process.cwd()] }]) {
                try {
                    return require(opts ? require.resolve(name, opts) : name);
                } catch (e) { /* try next */ }
            }
        }
        return null;
    }

    inject_traps() {
        const traps = this.ts.traps;
        if (traps.length === 0) return;

        const routers = this._routers();

        // Fail loud on exact duplicates of real application routes.
        for (const decoy of traps) {
            const methods = decoy.methods.map((m) => String(m).toUpperCase());
            for (const router of routers) {
                for (const layer of router.stack) {
                    if (!layer.methods || layer.methods.length === 0 || typeof layer.path !== 'string') continue;
                    if (normalizePath(layer.path) !== normalizePath(decoy.path)) continue;
                    const clash = methods.find((m) => layer.methods.includes(m));
                    if (clash) {
                        throw new Error(`trappsec error: trap ${clash} ${decoy.path} duplicates an existing application route.`);
                    }
                }
            }
        }

        const Router = this._loadRouterClass(routers);
        let mw;
        if (Router) {
            const trapRouter = new Router();
            for (const decoy of traps) {
                const methods = [...new Set(decoy.methods.map((m) => String(m).toUpperCase()))];
                trapRouter.register(decoy.path, methods, [async (ctx) => this._respondTrap(ctx, decoy)]);
            }
            mw = trapRouter.routes();
        } else {
            // Last resort when no router library can be loaded: exact-path matching.
            this.ts.logger.warn('Trappsec: @koa/router was not found; falling back to exact-path trap middleware (traps are still ordered before app handlers).');
            const map = Object.create(null);
            for (const decoy of traps) {
                for (const m of decoy.methods) map[String(m).toUpperCase() + ' ' + normalizePath(decoy.path)] = decoy;
            }
            mw = async (ctx, next) => {
                const decoy = map[String(ctx.method).toUpperCase() + ' ' + normalizePath(ctx.path)];
                if (!decoy) return next();
                return this._respondTrap(ctx, decoy);
            };
        }
        mw.__trappsecTrap = true;

        // Insert before the first application router, after ordinary middleware.
        const mws = this.app.middleware;
        let idx = mws.findIndex((m) => m && m.router && !m.__trappsecTrap);
        if (idx === -1) idx = mws.length;
        mws.splice(idx, 0, mw);
    }

    _respondTrap(ctx, decoy) {
        const { response_body, response_config } = resolveTrap(this.ts, decoy, ctx, 'Koa');
        try {
            ctx.status = response_config.status_code;
            ctx.body = response_body;
            if (response_config.mime_type) ctx.type = response_config.mime_type;
        } catch (e) {
            this.ts.logger.error('Trappsec error sending Koa trap response: ', e);
        }
    }

    setup_watches() {
        if (this.ts.watches.length === 0) return;
        const watchMap = buildWatchMap(this.ts);
        const routers = this._routers();
        if (routers.length === 0) {
            this.ts.logger.warn('Trappsec: no @koa/router instance found in app.middleware; watches cannot be installed. ' +
                'Register your router (app.use(router.routes())) before the app starts.');
            return;
        }

        const integration = this;
        for (const router of routers) {
            for (const layer of router.stack) {
                if (!layer.methods || layer.methods.length === 0 || typeof layer.path !== 'string') continue;
                const watch = watchMap[normalizePath(layer.path)];
                if (!watch) continue;

                // Cloned layers (router.use('/x', child.routes())) share their stack array
                // with the original, so replace the array instead of mutating it, and
                // drop any wrapper that belongs to a different layer.
                const clean = layer.stack.filter((fn) => !fn.__trappsecWatch);
                const wrapper = async function trappsecWatch(ctx, next) {
                    integration._inspect(ctx, watch);
                    return next();
                };
                wrapper.__trappsecWatch = true;
                layer.stack = [wrapper, ...clean];
            }
        }
    }

    _inspect(ctx, watch) {
        try {
            const found = [];

            if (hasFields(watch.query_fields)) {
                const query = ctx.query;
                if (isObject(query)) {
                    const { found: f, data, touched } = detect(this.ts, query, watch.query_fields, ctx, 'query');
                    found.push(...f);
                    if (touched) {
                        // Public setter: also rewrites ctx.querystring / ctx.url consistently.
                        ctx.query = data;
                    }
                }
            }

            if (hasFields(watch.body_fields)) {
                const body = ctx.request.body;
                if (body === undefined) {
                    if (BODY_METHODS.has(String(ctx.method).toUpperCase())) {
                        warnOnce(this.ts, this._warned, 'body:' + watch.path,
                            `Trappsec: body watches on ${watch.path} cannot run because ctx.request.body is undefined. ` +
                            'Register a body parser (e.g. koa-bodyparser) before your router.');
                    }
                } else if (isObject(body)) {
                    const { found: f, data, touched } = detect(this.ts, body, watch.body_fields, ctx, 'body');
                    found.push(...f);
                    if (touched) replaceInPlace(body, data);
                }
            }

            emitWatch(this.ts, ctx, found, 'Koa');
        } catch (e) {
            this.ts.logger.error('Trappsec error in Koa watch handler: ', e);
        }
    }
}

module.exports = KoaIntegration;
