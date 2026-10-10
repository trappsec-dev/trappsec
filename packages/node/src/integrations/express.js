'use strict';

const {
    normalizePath, isObject, buildWatchMap, hasFields, replaceInPlace, detect,
    resolveTrap, emitWatch, warnOnce, BODY_METHODS
} = require('./_common');

const TRAP_METHODS = ['get', 'post', 'put', 'delete', 'patch', 'head', 'options'];

class ExpressIntegration {
    // options.hookListen (default true): patch app.listen so bootstrap() runs when
    // the app starts listening. Nest passes false: it never calls app.listen.
    constructor(ts, app, options = {}) {
        this.ts = ts;
        this.app = app;
        this._bootstrapped = false;
        this._warned = new Set();

        if (!this.ts.identity.ip) {
            this.ts.identity.ip = r => r.ip || r.socket?.remoteAddress || r.connection?.remoteAddress || "0.0.0.0";
        }

        this.ts.requestContext.path = r => r.path;
        this.ts.requestContext.userAgent = r => (typeof r.get === 'function' ? r.get('User-Agent') : r.headers?.['user-agent']) || null;
        this.ts.requestContext.method = r => r.method;

        const integration = this;

        // Lazy, guarded bootstrap on the first request. Covers supertest, https.createServer(app),
        // custom servers and anything else that never goes through app.listen() (C5).
        const front = function trappsecBootstrap(req, res, next) {
            if (!integration._bootstrapped) {
                try {
                    integration.bootstrap();
                } catch (e) {
                    integration.ts.logger.error('Trappsec bootstrap failed on first request: ', e);
                }
            }
            next();
        };
        front.__trappsecFront = true;
        const stack = this._stack(true);
        const before = stack.length;
        app.use(front);
        const added = stack.splice(before);
        stack.unshift(...added);

        if (options.hookListen !== false && typeof app.listen === 'function') {
            const originalListen = app.listen;
            app.listen = function (...args) {
                integration.bootstrap();
                return originalListen.apply(this, args);
            };
        }
    }

    // Express 4 keeps the router on app._router (app.router is a throwing getter);
    // Express 5 exposes app.router.
    _router(create) {
        const app = this.app;
        if (app._router) return app._router;
        if (create && typeof app.lazyrouter === 'function') {
            app.lazyrouter();
            if (app._router) return app._router;
        }
        try {
            const r = app.router;
            if (r && Array.isArray(r.stack)) return r;
        } catch (e) { /* Express 4: deprecated getter throws */ }
        return null;
    }

    _stack(create) {
        const router = this._router(create);
        return router ? router.stack : null;
    }

    // Public and idempotent.
    bootstrap() {
        if (this._bootstrapped) return;
        this._bootstrapped = true;
        this.inject_traps();
        this.setup_watches();
    }

    _containsRoute(layer, seen) {
        if (!layer) return false;
        if (layer.route) return true;
        const sub = layer.handle && layer.handle.stack;
        if (!Array.isArray(sub) || seen.has(sub)) return false;
        seen.add(sub);
        return sub.some(l => this._containsRoute(l, seen));
    }

    _findConflict(stack, path, methods) {
        for (const layer of stack) {
            const route = layer && layer.route;
            if (!route || typeof route.path !== 'string') continue;
            if (normalizePath(route.path) !== normalizePath(path)) continue;
            const m = route.methods || {};
            for (const method of methods) {
                if (m[method] || m._all) return method.toUpperCase();
            }
        }
        return null;
    }

    inject_traps() {
        const traps = this.ts.traps;
        if (traps.length === 0) return;

        const stack = this._stack(true);
        if (!stack) {
            throw new Error('trappsec error: could not locate the Express router stack.');
        }

        // Fail loud on exact duplicates of real application routes.
        for (const decoy of traps) {
            const methods = decoy.methods.map(m => String(m).toLowerCase()).filter(m => TRAP_METHODS.includes(m));
            const conflict = this._findConflict(stack, decoy.path, methods);
            if (conflict) {
                throw new Error(`trappsec error: trap ${conflict} ${decoy.path} duplicates an existing application route.`);
            }
        }

        const before = stack.length;
        for (const decoy of traps) {
            const methods = [...new Set(decoy.methods.map(m => String(m).toLowerCase()))];
            const handler = (req, res) => this._respondTrap(req, res, decoy);
            for (const method of TRAP_METHODS) {
                if (methods.includes(method)) this.app[method](decoy.path, handler);
            }
        }

        // Express is order-based: move the freshly appended trap layers in front of the
        // first route layer (R2) but behind ordinary middleware such as auth and body
        // parsers (C6), so identify_user can see the user.
        const trapLayers = stack.splice(before);
        for (const layer of trapLayers) layer.__trappsecTrap = true;
        const seen = new Set();
        let idx = stack.findIndex(l => this._containsRoute(l, seen));
        if (idx === -1) idx = stack.length;
        stack.splice(idx, 0, ...trapLayers);
    }

    _respondTrap(req, res, decoy) {
        const { response_body, response_config } = resolveTrap(this.ts, decoy, req, 'Express');
        try {
            res.status(response_config.status_code);
            if (response_config.mime_type) res.type(response_config.mime_type);
            res.send(response_body);
        } catch (e) {
            this.ts.logger.error('Trappsec error sending Express trap response: ', e);
            if (!res.headersSent) {
                res.statusCode = response_config.status_code || 401;
                res.end();
            }
        }
    }

    setup_watches() {
        if (this.ts.watches.length === 0) return;
        const stack = this._stack(true);
        if (!stack) {
            throw new Error('trappsec error: could not locate the Express router stack.');
        }
        this._wrapRouterStack(stack, buildWatchMap(this.ts), new Set());
    }

    _wrapRouterStack(stack, watchMap, visited) {
        if (visited.has(stack)) return;
        visited.add(stack);

        for (const layer of stack) {
            if (!layer || typeof layer.handle !== 'function') continue;

            // Sub-router: recurse. req.baseUrl carries the mount prefix at request time.
            if (!layer.route && Array.isArray(layer.handle.stack)) {
                this._wrapRouterStack(layer.handle.stack, watchMap, visited);
                continue;
            }

            // Only route layers; never middleware (wrapping would break error-middleware arity).
            if (!layer.route || layer.__trappsecTrap || layer.handle.__trappsecWrapped) continue;

            const oldHandler = layer.handle;
            const integration = this;
            const wrapped = function (req, res, next) {
                integration._inspectRequest(req, watchMap);
                return oldHandler.apply(this, arguments);
            };
            wrapped.__trappsecWrapped = true;
            layer.handle = wrapped;
        }
    }

    _inspectRequest(req, watchMap) {
        try {
            if (!req.route || typeof req.route.path !== 'string') return;
            // req.baseUrl is the mount prefix of any parent router ('' at top level).
            const watch = watchMap[normalizePath((req.baseUrl || '') + req.route.path)];
            if (!watch) return;
            this._inspect(req, watch);
        } catch (e) {
            this.ts.logger.error('Trappsec error in Express watch handler: ', e);
        }
    }

    _inspect(req, watch) {
        const found = [];

        if (hasFields(watch.query_fields)) {
            const query = req.query;
            if (isObject(query)) {
                const { found: f, data, touched } = detect(this.ts, query, watch.query_fields, req, 'query');
                found.push(...f);
                if (touched) {
                    // Express 5's req.query is a getter that re-parses on every read, so an
                    // own data property is the only way to make the stripped copy stick.
                    Object.defineProperty(req, 'query', { value: data, writable: true, configurable: true, enumerable: true });
                }
            }
        }

        if (hasFields(watch.body_fields)) {
            const body = req.body;
            if (body === undefined) {
                if (BODY_METHODS.has(String(req.method).toUpperCase())) {
                    warnOnce(this.ts, this._warned, 'body:' + watch.path,
                        `Trappsec: body watches on ${watch.path} cannot run because req.body is undefined. ` +
                        'Register a body parser (e.g. express.json()) before your routes.');
                }
            } else if (isObject(body)) {
                const { found: f, data, touched } = detect(this.ts, body, watch.body_fields, req, 'body');
                found.push(...f);
                if (touched) replaceInPlace(body, data);
            }
        }

        emitWatch(this.ts, req, found, 'Express');
    }
}

module.exports = ExpressIntegration;
