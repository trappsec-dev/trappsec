'use strict';

const { AsyncLocalStorage } = require('node:async_hooks');

const {
    normalizePath, buildWatchMap, hasFields, trapMethods, inspectQuery, inspectBody,
    finishPending, resolveTrap, emitWatch, warnOnce, bodyLooksUnparsed, stripRawQuery
} = require('./_common');

const PENDING = Symbol('trappsec.pendingWatch');
const INSPECTED = Symbol('trappsec.inspectedWatch');
const pendingRequest = new AsyncLocalStorage();

const TRAP_METHODS = ['get', 'post', 'put', 'delete', 'patch', 'head', 'options'];

// The part of `path` that a mount layer (app.use / router.use) consumes, or null
// when the layer does not match it. Works on Express 4 and 5 layers; the layer's
// per-request match state is restored.
function mountPrefix(layer, path) {
    if (typeof layer.match !== 'function') return null;
    const saved = [layer.path, layer.params, layer.keys];
    try {
        if (!layer.match(path)) return null;
        return layer.path || '';
    } finally {
        [layer.path, layer.params, layer.keys] = saved;
    }
}

// The path left after removing a mount prefix, in canonical form.
function afterMount(path, prefix) {
    return normalizePath(path.slice(prefix.length)) || '/';
}

// A watch path as a regex over concrete URLs: ':param' segments match any value.
function watchRegex(full) {
    const src = full.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/:\w+/g, '[^/]+');
    return new RegExp('^' + src + '$');
}

// A router layer is a mounted sub-app when Express wrapped it in mounted_app().
const isSubApp = (layer) => !layer.route && layer.handle && layer.handle.name === 'mounted_app';
const isSubRouter = (layer) => !layer.route && layer.handle && Array.isArray(layer.handle.stack);

class ExpressIntegration {
    // options.hookListen (default true): patch app.listen so bootstrap() runs when
    // the app starts listening. Nest passes false: it never calls app.listen.
    constructor(ts, app, options = {}) {
        this.ts = ts;
        this.app = app;
        this._bootstrapped = false;
        this._warned = new Set();
        // NestJS runs its whole pipeline (interceptors such as multer, pipes, the
        // controller) inside one Express handler, so it finishes deferred body
        // inspection itself (from a global pipe) instead of at the route's final handler.
        this._finishAtHandler = options.finishAtHandler !== false;
        this._exposePending = !this._finishAtHandler; // only the NestJS pipe reads pendingRequest

        if (!this.ts.identity.ip) {
            this.ts.identity.ip = r => r.ip || r.socket?.remoteAddress || r.connection?.remoteAddress || "0.0.0.0";
        }

        this.ts.request.path = r => r.path;
        this.ts.request.user_agent = r => (typeof r.get === 'function' ? r.get('User-Agent') : r.headers?.['user-agent']) || null;
        this.ts.request.method = r => r.method;

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

    // Scans the stack and every mounted sub-router (`path` is relative to the stack).
    _findConflict(stack, path, methods, ancestors = new Set()) {
        const want = normalizePath(path);
        for (const layer of stack) {
            const route = layer && layer.route;
            if (route) {
                if (typeof route.path !== 'string' || normalizePath(route.path) !== want) continue;
                const m = route.methods || {};
                for (const method of methods) {
                    if (m[method] || m._all) return method.toUpperCase();
                }
            } else if (layer && isSubRouter(layer) && !ancestors.has(layer.handle.stack)) {
                const prefix = mountPrefix(layer, want);
                if (prefix === null) continue;
                ancestors.add(layer.handle.stack);
                const conflict = this._findConflict(layer.handle.stack, afterMount(want, prefix), methods, ancestors);
                ancestors.delete(layer.handle.stack);
                if (conflict) return conflict;
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
            const methods = trapMethods(decoy).map(m => m.toLowerCase()).filter(m => TRAP_METHODS.includes(m));
            const conflict = this._findConflict(stack, decoy.path, methods);
            if (conflict) {
                throw new Error(`trappsec error: trap ${conflict} ${decoy.path} duplicates an existing application route.`);
            }
        }

        const before = stack.length;
        for (const decoy of traps) {
            const methods = trapMethods(decoy).map(m => m.toLowerCase());
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
        // Watch keys are resolved against the router stack once, here: each entry is a
        // watch seen from the current router (`rel`), so a mount prefix is consumed on
        // the way down and a parameterised mount ('/users/:id') still resolves.
        const watchMap = buildWatchMap(this.ts);
        const entries = Object.keys(watchMap).map(key => ({ rel: key, full: key, watch: watchMap[key], mounted: false }));
        this._wrapRouterStack(stack, entries, new Set());
    }

    _wrapRouterStack(stack, entries, ancestors) {
        if (ancestors.has(stack)) return;
        ancestors.add(stack);

        for (const layer of stack) {
            if (!layer || typeof layer.handle !== 'function') continue;

            if (isSubApp(layer)) {
                // A sub-app is a separate Express instance with its own router: its
                // routes cannot be reached from here.
                for (const e of entries) {
                    const prefix = mountPrefix(layer, e.rel);
                    if (prefix === null) continue;
                    warnOnce(this.ts, this._warned, 'subapp:' + e.full,
                        `Trappsec: watch ${e.full} may be inside the sub-app mounted at ${prefix || '/'}; ` +
                        'sub-apps are not wrapped, so it will not fire. Install trappsec on the sub-app instead.');
                }
                continue;
            }

            // Sub-router: recurse with the watches that can live under this mount.
            if (isSubRouter(layer)) {
                const inner = [];
                for (const e of entries) {
                    const prefix = mountPrefix(layer, e.rel);
                    if (prefix === null) continue;
                    inner.push(prefix === '' ? e : { rel: afterMount(e.rel, prefix), full: e.full, watch: e.watch, mounted: true });
                }
                if (inner.length > 0) this._wrapRouterStack(layer.handle.stack, inner, ancestors);
                continue;
            }

            // Only route layers; never middleware (wrapping would break error-middleware arity).
            if (!layer.route || layer.__trappsecTrap) continue;
            const routeKey = typeof layer.route.path === 'string' ? normalizePath(layer.route.path) : null;
            const hits = routeKey ? entries.filter(e => e.rel === routeKey) : [];
            if (hits.length === 0) continue;

            // A router mounted twice reaches the same layer with different entries.
            const existing = layer.handle.__trappsecEntries;
            const list = existing || [];
            for (const e of hits) {
                if (!list.some(x => x.full === e.full)) {
                    list.push({ full: e.full, watch: e.watch, re: e.mounted ? watchRegex(e.full) : null });
                }
            }
            if (existing) continue;

            const oldHandler = layer.handle;
            const integration = this;
            const wrapped = function (req, res, next) {
                integration._inspectRequest(req, list, routeKey);
                return oldHandler.apply(this, arguments);
            };
            wrapped.__trappsecWrapped = true;
            wrapped.__trappsecEntries = list;
            layer.handle = wrapped;
            if (this._finishAtHandler) this._wrapRouteHandlers(layer.route);
        }
        ancestors.delete(stack);
    }

    /**
     * Route-level middleware (e.g. `app.post('/x', multer().none(), handler)` or a
     * route-level `express.json()`) parses the body only after the route is entered.
     * Body inspection deferred at route entry is completed right before the route's
     * final handler for the request method, once that middleware has run.
     */
    _wrapRouteHandlers(route) {
        if (!Array.isArray(route.stack)) return;
        const integration = this;
        route.stack.forEach((inner, i) => {
            if (!inner || typeof inner.handle !== 'function' || inner.handle.__trappsecWrapped) return;
            if (inner.handle.length >= 4) return; // error handler: keep its arity
            const original = inner.handle;
            const wrapped = function (req, res, next) {
                if (req[PENDING] && integration._isFinalHandler(route, i, req.method)) {
                    integration._finishInspection(req);
                }
                return original.apply(this, arguments);
            };
            wrapped.__trappsecWrapped = true;
            inner.handle = wrapped;
        });
    }

    _isFinalHandler(route, index, method) {
        const m = String(method || '').toLowerCase();
        const handles = (l) => {
            if (!l || typeof l.handle !== 'function' || l.handle.length >= 4) return false;
            if (!l.method) return true; // route.all()
            return l.method === m || (m === 'head' && l.method === 'get');
        };
        for (let j = index + 1; j < route.stack.length; j++) {
            if (handles(route.stack[j])) return false;
        }
        return true;
    }

    _inspectRequest(req, entries, routeKey) {
        try {
            let watch = null;
            let concrete; // the real URL of the route, built only for mounted entries
            for (const e of entries) {
                if (e.re === null) {
                    if (!req.baseUrl) { watch = e.watch; break; }
                    continue;
                }
                if (concrete === undefined) concrete = req.baseUrl + (routeKey === '/' ? '' : routeKey);
                if (e.re.test(concrete)) { watch = e.watch; break; }
            }
            if (watch) this._inspect(req, watch);
        } catch (e) {
            this.ts.logger.error('Trappsec error in Express watch handler: ', e);
        }
    }

    _inspect(req, watch) {
        const found = [];

        found.push(...inspectQuery(this.ts, req, req.query, watch, (data, keys) => {
            // Express 5's req.query is a getter that re-parses on every read, so an
            // own data property is the only way to make the stripped copy stick.
            Object.defineProperty(req, 'query', { value: data, writable: true, configurable: true, enumerable: true });
            req.url = stripRawQuery(req.url, keys); // originalUrl stays as received
        }));

        if (hasFields(watch.body_fields)) {
            if (bodyLooksUnparsed(req.body, req.headers, req._body === true)) {
                // Not parsed yet: a route-level parser may still run. Finish before the
                // final handler, or when the response ends if the route never gets there.
                req[PENDING] = { watch, found };
                if (this._exposePending) pendingRequest.enterWith(req); // lets the NestJS pipe find it later
                const res = req.res;
                if (res && typeof res.once === 'function') {
                    res.once('close', () => { if (req[PENDING]) this._finishInspection(req, true); });
                }
                return;
            }
            found.push(...inspectBody(this.ts, req, req.body, watch));
        }

        emitWatch(this.ts, req, found, 'Express');
    }

    _finishInspection(req, responseEnded = false) {
        const pending = req[PENDING];
        delete req[PENDING];
        req[INSPECTED] = pending.watch;
        finishPending(this.ts, this._warned, req, pending, {
            label: 'Express',
            body: req.body,
            method: req.method,
            responseEnded,
            warning: `Trappsec: body watches on ${pending.watch.path} cannot run because req.body is undefined. ` +
                'Register a body parser (e.g. express.json()) for this route.'
        });
    }
}

ExpressIntegration.PENDING = PENDING;
ExpressIntegration.INSPECTED = INSPECTED;
ExpressIntegration.pendingRequest = pendingRequest;

module.exports = ExpressIntegration;
