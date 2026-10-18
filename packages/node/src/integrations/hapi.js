'use strict';

const {
    normalizePath, hasFields, replaceInPlace, createWatchLookup, trapMethods,
    inspectQuery, inspectBody, resolveTrap, applyHeaders, emitWatch, stripRawQuery
} = require('./_common');

// Watches run in `onPostAuth`: the payload is parsed and credentials are set (so
// identify_user can read request.auth), but route validation has not run yet, so
// honey fields are inspected and stripped even if the route validation would reject
// or strip them. Traps are real routes; hapi's specificity-based router guarantees a
// static trap path beats a parameterized route.
class HapiIntegration {
    constructor(ts, app) {
        this.ts = ts;
        this.app = app;
        this._bootstrapped = false;
        this._lookup = null;

        if (!this.ts.identity.ip) {
            this.ts.identity.ip = (request) => request.info?.remoteAddress || request.raw?.req?.socket?.remoteAddress || "0.0.0.0";
        }

        this.ts.request.path = (request) => normalizePath(request.path || request.url?.pathname || request.raw?.req?.url);
        this.ts.request.user_agent = (request) => request.headers?.["user-agent"] || null;
        this.ts.request.method = (request) => (request.method || "").toUpperCase();

        const integration = this;

        // Lazy bootstrap: onRequest runs before route lookup, so routes added here
        // already apply to the current request (server.inject() without start()).
        this.app.ext('onRequest', (request, h) => {
            if (!integration._bootstrapped) {
                try {
                    integration.bootstrap();
                } catch (e) {
                    integration.ts.logger.error('Trappsec bootstrap failed on first request: ', e);
                }
            }
            return h.continue;
        });

        // Registered once, up front, so it applies to every route regardless of when
        // the route was added. The watch map is filled in by bootstrap().
        this.app.ext('onPostAuth', (request, h) => {
            try {
                const lookup = integration._lookup;
                const watch = lookup && lookup(request.route?.path);
                if (watch) integration._inspect(request, watch);
            } catch (e) {
                integration.ts.logger.error("Trappsec error in Hapi watch handler: ", e);
            }
            return h.continue;
        });

        for (const name of ['initialize', 'start']) {
            if (typeof this.app[name] !== 'function') continue;
            const original = this.app[name].bind(this.app);
            this.app[name] = async function (...args) {
                integration.bootstrap();
                return original(...args);
            };
        }
    }

    // Public and idempotent.
    bootstrap() {
        if (this._bootstrapped) return;
        this._bootstrapped = true;
        this.inject_traps();
        this.setup_watches();
    }

    inject_traps() {
        for (const decoy of this.ts.traps) {
            // hapi serves HEAD for GET routes automatically and refuses explicit HEAD routes.
            const methods = trapMethods(decoy).filter((m) => m !== 'HEAD');
            if (methods.length === 0) continue;
            this.app.route({
                method: methods,
                path: decoy.path,
                handler: (request, h) => {
                    const { response_body, response_config } = resolveTrap(this.ts, decoy, request, 'Hapi');
                    const response = h.response(response_body).code(response_config.status_code);
                    applyHeaders(this.ts, response_config.headers, (k, v) => response.header(k, v), 'Hapi');
                    if (response_config.mime_type) response.type(response_config.mime_type);
                    return response;
                }
            });
        }
    }

    setup_watches() {
        if (this.ts.watches.length === 0) return;
        this._lookup = createWatchLookup(this.ts);
    }

    _inspect(request, watch) {
        const found = [];

        found.push(...inspectQuery(this.ts, request, request.query, watch, (data, keys) => {
            replaceInPlace(request.query, data);
            const raw = request.raw && request.raw.req;
            if (raw) raw.url = stripRawQuery(raw.url, keys);
            if (request.url && typeof request.url.search === 'string') {
                request.url.search = stripRawQuery('?' + request.url.search.slice(1), keys).slice(1);
            }
        }));

        if (hasFields(watch.body_fields)) found.push(...inspectBody(this.ts, request, request.payload, watch));

        emitWatch(this.ts, request, found, 'Hapi');
    }
}

module.exports = HapiIntegration;
