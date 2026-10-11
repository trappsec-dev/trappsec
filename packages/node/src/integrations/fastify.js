'use strict';

const {
    normalizePath, hasFields, replaceInPlace, createWatchLookup, trapMethods,
    inspectQuery, inspectBody, finishPending, resolveTrap, emitWatch, stripRawQuery
} = require('./_common');

const PENDING = Symbol('trappsec.pendingWatch');

// Two non-encapsulated plugins. The watch hooks are registered when Sentry is
// constructed, so they keep their place among the app's own hooks; the watch map
// is built on the first request. Traps are registered when the app boots (ready(),
// which listen() and inject() call), so routes declared after the plugin queue
// was flushed by an earlier `await app.register(...)` are still installed.
// The hooks are app-wide and resolve the route per request, so registering them
// before the trap routes cannot miss a trap (the concern behind R10).
//
// Watches run in `preValidation`: the body is already parsed, but JSON-schema
// validation has not run yet, so honey fields are seen and stripped even when the
// route schema would otherwise reject or silently remove them (additionalProperties /
// removeAdditional). Consequence: identify_user sees only request state set in
// onRequest/preParsing/preValidation hooks registered BEFORE Sentry; state set by
// preHandler-phase auth hooks is not visible to watch events (traps run as handlers
// and see everything).
class FastifyIntegration {
    // options.hookListen (default true): also call bootstrap() from app.listen().
    constructor(ts, app, options = {}) {
        this.ts = ts;
        this.app = app;
        this._registered = false;

        if (!this.ts.identity.ip) {
            this.ts.identity.ip = (req) => req.ip || req.socket?.remoteAddress || req.raw?.socket?.remoteAddress || "0.0.0.0";
        }

        this.ts.request.path = (req) => normalizePath(req.url || req.raw?.url);
        this.ts.request.user_agent = (req) => req.headers?.["user-agent"] || req.raw?.headers?.["user-agent"] || null;
        this.ts.request.method = (req) => req.method || req.raw?.method || null;

        const integration = this;
        if (options.hookListen !== false && typeof app.listen === 'function') {
            const originalListen = app.listen;
            app.listen = function (...args) {
                integration.bootstrap();
                return originalListen.apply(this, args);
            };
        }
        if (typeof app.ready === 'function') {
            const originalReady = app.ready;
            app.ready = function (...args) {
                integration.bootstrap();
                return originalReady.apply(this, args);
            };
        }

        this._register('trappsec-watches', (instance) => this.setup_watches(instance));
    }

    // Public and idempotent. Registers the plugin that installs traps.
    bootstrap() {
        if (this._registered) return;
        this._registered = this._register('trappsec', (instance) => this.inject_traps(instance));
    }

    _register(name, install) {
        const plugin = function trappsecPlugin(instance, _opts, done) {
            try {
                install(instance);
                done();
            } catch (e) {
                done(e);
            }
        };
        plugin[Symbol.for('skip-override')] = true; // do not encapsulate: hooks apply app-wide
        plugin[Symbol.for('fastify.display-name')] = name;
        try {
            this.app.register(plugin);
            return true;
        } catch (e) {
            this.ts.logger.error('Trappsec could not register with Fastify (was the instance already started? Install Sentry before ready()/listen()): ', e);
            throw e;
        }
    }

    inject_traps(instance = this.app) {
        for (const decoy of this.ts.traps) {
            instance.route({
                method: trapMethods(decoy),
                url: decoy.path,
                handler: (req, reply) => {
                    const { response_body, response_config } = resolveTrap(this.ts, decoy, req, 'Fastify');
                    try {
                        if (response_config.mime_type) reply.type(response_config.mime_type);
                        return reply.code(response_config.status_code).send(response_body);
                    } catch (e) {
                        this.ts.logger.error('Trappsec error sending Fastify trap response: ', e);
                        return reply.code(response_config.status_code || 401).send('');
                    }
                },
            });
        }
    }

    setup_watches(instance = this.app) {
        let lookup = null; // built once, on the first request: watches are fixed by then (R13)

        instance.addHook('preValidation', (req, _reply, done) => {
            try {
                if (lookup === null) lookup = createWatchLookup(this.ts);
                const watch = lookup(req.routeOptions?.url || req.routerPath || req.context?.config?.url);
                if (watch) this._inspect(req, watch);
            } catch (e) {
                this.ts.logger.error("Trappsec error in Fastify watch handler: ", e);
            }
            done();
        });

        // A body parsed by a preValidation hook registered after Sentry (e.g.
        // @fastify/multipart with attachFieldsToBody) is not there yet above: finish
        // right before the handler, or report what was seen if the request ends first.
        instance.addHook('preHandler', (req, _reply, done) => {
            if (req[PENDING]) this._finishInspection(req);
            done();
        });
        instance.addHook('onResponse', (req, _reply, done) => {
            if (req[PENDING]) this._finishInspection(req, true);
            done();
        });
    }

    _inspect(req, watch) {
        const found = [];

        found.push(...inspectQuery(this.ts, req, req.query, watch, (data, keys) => {
            replaceInPlace(req.query, data); // in place: req.query may be getter-only
            if (req.raw) req.raw.url = stripRawQuery(req.raw.url, keys); // req.url reads it
        }));

        if (hasFields(watch.body_fields)) {
            if (req.body === undefined || req.body === null) {
                req[PENDING] = { watch, found };
                return;
            }
            found.push(...inspectBody(this.ts, req, req.body, watch));
        }

        emitWatch(this.ts, req, found, 'Fastify');
    }

    _finishInspection(req, responseEnded = false) {
        const pending = req[PENDING];
        req[PENDING] = undefined;
        finishPending(this.ts, null, req, pending, { label: 'Fastify', body: responseEnded ? undefined : req.body, responseEnded });
    }
}

module.exports = FastifyIntegration;
