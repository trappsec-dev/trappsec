'use strict';

const {
    normalizePath, hasFields, createWatchLookup, trapMethods, detect, resolveTrap,
    emitWatch, stripRawQuery, warnOnce, BODY_METHODS
} = require('./_common');

// Hono keeps routes and middleware in one ordered list: every entry whose path
// and method match a request runs, in registration order, until one answers.
// app.use() and app.all() entries both have method "ALL"; an entry counts as
// middleware when it has method "ALL" and its handler takes next ((c, next)),
// as Hono middleware always does; everything else is a route. Watch paths are
// the FULL route pattern, including the prefix of an app.route('/api', sub) or
// basePath().
//
// Strategy (Hono's public fields only: app.router, app.routes, app.fetch,
// c.req.raw, c.req.bodyCache):
//  * app.fetch (which app.request, @hono/node-server, Bun and Workers all call)
//    bootstraps before the first request is routed, while routes can still be
//    added.
//  * app.router is replaced by a thin proxy whose match() reorders each match
//    result: trap entries move to just before the first route entry, i.e.
//    after ordinary middleware (auth, CORS) and before any application route,
//    so a catch-all registered earlier (app.get('*', serveStatic())) cannot
//    shadow them. Hono's own router replaces its match() after the first
//    request, which is why the proxy wraps the router object, not the method.
//  * watched routes get their handler wrapped in the same pass: the wrapper
//    runs after middleware and before the route's first handler (route-level
//    middleware such as a validator included), reads the body through
//    HonoRequest, strips honey fields and swaps in a rebuilt c.req.raw, so
//    c.req.json(), parseBody(), formData() and c.req.raw all see the stripped
//    request.
const ALL = 'ALL';
const COMPOSED_HANDLER = '__COMPOSED_HANDLER'; // hono/utils/constants: app.route() wrapper -> original

function isMiddleware(handler, route) {
    if (!route || route.method !== ALL) return false;
    const fn = (handler && handler[COMPOSED_HANDLER]) || handler;
    return typeof fn === 'function' && fn.length >= 2;
}
const DEFAULT_MAX_BODY = 10 * 1024 * 1024;

class HonoIntegration {
    constructor(ts, app) {
        this.ts = ts;
        this.app = app;
        this._bootstrapped = false;
        this._warned = new Set();
        this._reordered = new WeakMap(); // router match entries -> reordered entries
        this._wrapped = new WeakMap();   // route -> watch-wrapped handler
        this._inspected = new WeakSet(); // contexts already inspected
        this.max_body_bytes = DEFAULT_MAX_BODY;

        if (!this.ts.identity.ip) {
            // @hono/node-server passes the Node request as env.incoming. Other runtimes
            // need override_source_ip (e.g. Hono's getConnInfo helper for the runtime).
            this.ts.identity.ip = (c) => c?.env?.incoming?.socket?.remoteAddress || '0.0.0.0';
        }
        this.ts.request.path = (c) => c?.req?.path || null;
        this.ts.request.user_agent = (c) => c?.req?.header?.('user-agent') || null;
        this.ts.request.method = (c) => c?.req?.method || null;

        const router = app.router;
        this._router = router;
        const integration = this;
        app.router = {
            get name() { return router.name; },
            add: (method, path, handler) => router.add(method, path, handler),
            match: (method, path) => integration._match(router.match(method, path)),
        };

        const fetch = app.fetch;
        app.fetch = (request, ...rest) => {
            integration.bootstrap();
            return fetch(request, ...rest);
        };
    }

    // Public and idempotent. A trap that duplicates a route throws here, before
    // anything is installed, and again on every later call (and request).
    bootstrap() {
        if (this._bootstrapped) return;
        const traps = this.ts.traps;
        const routes = this.app.routes.slice();

        for (const decoy of traps) {
            const path = normalizePath(decoy.path);
            for (const method of trapMethods(decoy)) {
                if (routes.some((r) => (r.method === method || (r.method === ALL && !isMiddleware(r.handler, r))) &&
                        normalizePath(r.path) === path)) {
                    throw new Error(`trappsec error: trap ${method} ${decoy.path} duplicates an existing application route.`);
                }
            }
        }

        for (const decoy of traps) {
            const handler = (c) => this._respondTrap(c, decoy);
            handler.__trappsecTrap = true;
            for (const method of trapMethods(decoy)) {
                // Straight to the router: app.on() would prefix the app's basePath.
                const route = { basePath: '/', path: decoy.path, method, handler };
                this._router.add(method, decoy.path, [handler, route]);
                this.app.routes.push(route);
            }
        }

        this._watchFor = createWatchLookup(this.ts);
        this._hasTraps = traps.length > 0;
        this._hasWatches = this.ts.watches.length > 0;
        this._warnUnmatchedWatches(routes);
        this._bootstrapped = true;
    }

    _warnUnmatchedWatches(routes) {
        const served = new Set(routes.filter((r) => !isMiddleware(r.handler, r)).map((r) => normalizePath(r.path)));
        for (const watch of this.ts.watches) {
            if (!served.has(normalizePath(watch.path))) {
                warnOnce(this.ts, this._warned, 'unmatched:' + watch.path,
                    `Trappsec: watch ${watch.path} matches no registered route and will never fire ` +
                    '(watch paths are full route patterns, including app.route() and basePath() prefixes, e.g. /api/users/:id).');
            }
        }
    }

    // Reorders (and, for watched routes, rewraps) one router match result. Entries
    // are [[handler, route], params]; params stay with their entry, so moving an
    // entry keeps c.req.param() right. Results the router reuses (RegExpRouter
    // caches them) are never mutated: the reordered copy is memoised instead.
    _match(result) {
        if (!this._bootstrapped || (!this._hasTraps && !this._hasWatches)) return result;
        const entries = result[0];
        let out = this._reordered.get(entries);
        if (out === undefined) {
            out = this._reorder(entries);
            this._reordered.set(entries, out);
        }
        if (out === entries) return result;
        const copy = result.slice();
        copy[0] = out;
        return copy;
    }

    _reorder(entries) {
        let changed = false;
        const traps = [];
        const rest = [];
        for (const entry of entries) {
            const [handler, route] = entry[0];
            if (handler && handler.__trappsecTrap) {
                traps.push(entry);
                continue;
            }
            const watch = route && !isMiddleware(handler, route) ? this._watchFor(route.path) : null;
            if (watch) {
                rest.push([[this._wrap(handler, route, watch), route], entry[1]]);
                changed = true;
            } else {
                rest.push(entry);
            }
        }
        if (traps.length > 0) {
            let at = rest.findIndex((e) => !isMiddleware(e[0][0], e[0][1]));
            if (at === -1) at = rest.length;
            rest.splice(at, 0, ...traps);
            changed = changed || rest.some((e, i) => e !== entries[i]);
        }
        return changed ? rest : entries;
    }

    _wrap(handler, route, watch) {
        let wrapped = this._wrapped.get(route);
        if (!wrapped) {
            const integration = this;
            wrapped = async function trappsecWatch(c, next) {
                if (!integration._inspected.has(c)) {
                    integration._inspected.add(c);
                    await integration._inspect(c, watch);
                }
                return handler(c, next);
            };
            this._wrapped.set(route, wrapped);
        }
        return wrapped;
    }

    _respondTrap(c, decoy) {
        const { response_body, response_config } = resolveTrap(this.ts, decoy, c, 'Hono');
        const headers = response_config.mime_type ? { 'Content-Type': response_config.mime_type } : undefined;
        return c.body(response_body, response_config.status_code, headers);
    }

    async _inspect(c, watch) {
        try {
            const found = [];
            let url = null;
            let body;

            if (hasFields(watch.query_fields)) {
                const query = group(Object.entries(c.req.queries()).flatMap(([k, vs]) => vs.map((v) => [k, v])));
                const sent = Object.keys(query); // detection strips in place
                const r = detect(this.ts, query, watch.query_fields, c, 'query');
                found.push(...r.found);
                if (r.touched) {
                    const u = new URL(c.req.url);
                    const removed = sent.filter((k) => !has(r.data, k));
                    url = u.origin + stripRawQuery(u.pathname + u.search, removed);
                }
            }

            if (hasFields(watch.body_fields) && BODY_METHODS.has(c.req.method)) {
                const r = await this._inspectBody(c, watch);
                found.push(...r.found);
                body = r.body;
            }

            if (url !== null || body !== undefined) await this._replaceRequest(c, url, body);
            emitWatch(this.ts, c, found, 'Hono');
        } catch (e) {
            this.ts.logger.error('Trappsec error in Hono watch handler: ', e);
        }
    }

    // Detects (and strips) body honey fields. Returns {found, body}: body is the
    // rebuilt payload when something was stripped, otherwise undefined.
    async _inspectBody(c, watch) {
        const none = { found: [], body: undefined };
        const length = Number(c.req.header('content-length'));
        if (length > this.max_body_bytes) {
            warnOnce(this.ts, this._warned, 'size:' + watch.path,
                `Trappsec: a request to ${watch.path} is larger than ${this.max_body_bytes} bytes; its body was not inspected.`);
            return none;
        }
        const type = (c.req.header('content-type') || '').toLowerCase();
        const rules = watch.body_fields;

        if (type.includes('multipart/form-data')) {
            const form = await c.req.formData();
            const pairs = [...form.entries()];
            const r = detect(this.ts, group(pairs), rules, c, 'body');
            if (!r.touched) return { found: r.found, body: undefined };
            const kept = new FormData();
            for (const [k, v] of pairs) if (has(r.data, k)) kept.append(k, v);
            return { found: r.found, body: kept };
        }
        if (type.includes('application/x-www-form-urlencoded')) {
            const params = new URLSearchParams(await c.req.text());
            const pairs = [...params.entries()];
            const r = detect(this.ts, group(pairs), rules, c, 'body');
            if (!r.touched) return { found: r.found, body: undefined };
            return { found: r.found, body: new URLSearchParams(pairs.filter(([k]) => has(r.data, k))).toString() };
        }
        const text = await c.req.text();
        if (!text || !(type.includes('json') || /^\s*[[{]/.test(text))) return none;
        let data;
        try {
            data = JSON.parse(text);
        } catch (e) {
            return none;
        }
        const r = detect(this.ts, data, rules, c, 'body');
        return { found: r.found, body: r.touched ? JSON.stringify(r.data) : undefined };
    }

    // Swaps in a request carrying the stripped URL and/or body, and drops Hono's
    // body cache so every reader (json(), parseBody(), raw) sees the new one.
    async _replaceRequest(c, url, body) {
        const raw = c.req.raw;
        const headers = new Headers(raw.headers);
        if (body === undefined && BODY_METHODS.has(raw.method) && (raw.body || Object.keys(c.req.bodyCache).length > 0)) {
            body = await c.req.arrayBuffer();
        }
        if (body instanceof FormData) headers.delete('content-type'); // new boundary
        headers.delete('content-length');
        c.req.raw = new Request(url !== null ? url : raw.url, { method: raw.method, headers, body });
        c.req.bodyCache = {};
    }
}

const has = (obj, key) => Object.prototype.hasOwnProperty.call(obj, key);

// [[name, value], ...] -> object: a name sent once is a scalar, repeated an array.
// Null prototype, so a field named "__proto__" is just a field.
function group(pairs) {
    const out = Object.create(null);
    for (const [k, v] of pairs) {
        if (!has(out, k)) out[k] = v;
        else if (Array.isArray(out[k])) out[k].push(v);
        else out[k] = [out[k], v];
    }
    return out;
}

module.exports = HonoIntegration;
