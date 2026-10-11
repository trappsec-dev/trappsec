'use strict';

const {
    normalizePath, isObject, buildWatchMap, hasFields, replaceInPlace, detect,
    resolveTrap, emitWatch
} = require('./_common');

const PENDING = Symbol('trappsec.pendingWatch');

// Traps and the watch hook are installed by a non-encapsulated plugin that is
// registered when Sentry is constructed. Fastify loads it at ready() time (before
// listen(), inject() or ready() resolve), after synchronous configuration code ran
// and with routes still addable, so `await app.ready()` / `app.inject()` before
// `listen()` work and nothing is registered inside a patched listen().
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

        this.ts.requestContext.path = (req) => normalizePath(req.url || req.raw?.url);
        this.ts.requestContext.userAgent = (req) => req.headers?.["user-agent"] || req.raw?.headers?.["user-agent"] || null;
        this.ts.requestContext.method = (req) => req.method || req.raw?.method || null;

        if (options.hookListen !== false && typeof app.listen === 'function') {
            const integration = this;
            const originalListen = app.listen;
            app.listen = function (...args) {
                integration.bootstrap();
                return originalListen.apply(this, args);
            };
        }

        this.bootstrap();
    }

    // Public and idempotent. Registers the plugin that installs traps and watches.
    bootstrap() {
        if (this._registered) return;
        this._registered = true;

        const integration = this;
        const plugin = function trappsecPlugin(instance, _opts, done) {
            try {
                integration.inject_traps(instance);
                integration.setup_watches(instance);
                done();
            } catch (e) {
                done(e);
            }
        };
        plugin[Symbol.for('skip-override')] = true; // do not encapsulate: hooks apply app-wide
        plugin[Symbol.for('fastify.display-name')] = 'trappsec';

        try {
            this.app.register(plugin);
        } catch (e) {
            this._registered = false;
            this.ts.logger.error('Trappsec could not register with Fastify (was the instance already started? Install Sentry before ready()/listen()): ', e);
            throw e;
        }
    }

    inject_traps(instance = this.app) {
        for (const decoy of this.ts.traps) {
            const methods = [...new Set(decoy.methods.map((m) => String(m).toUpperCase()))];
            instance.route({
                method: methods,
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
        if (this.ts.watches.length === 0) return;

        const watchMap = buildWatchMap(this.ts);

        instance.addHook('preValidation', (req, _reply, done) => {
            try {
                const routePath = normalizePath(req.routeOptions?.url || req.routerPath || req.context?.config?.url);
                const watch = routePath ? watchMap[routePath] : null;
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

        if (hasFields(watch.query_fields) && isObject(req.query)) {
            const { found: f, data, touched } = detect(this.ts, req.query, watch.query_fields, req, 'query');
            found.push(...f);
            if (touched) replaceInPlace(req.query, data); // in place: req.query may be getter-only
        }

        if (hasFields(watch.body_fields)) {
            if (req.body === undefined || req.body === null) {
                req[PENDING] = { watch, found };
                return;
            }
            found.push(...this._inspectBody(req, watch));
        }

        emitWatch(this.ts, req, found, 'Fastify');
    }

    _inspectBody(req, watch) {
        if (!isObject(req.body)) return [];
        const { found, data, touched } = detect(this.ts, req.body, watch.body_fields, req, 'body');
        if (touched) replaceInPlace(req.body, data);
        return found;
    }

    _finishInspection(req, responseEnded = false) {
        const pending = req[PENDING];
        req[PENDING] = undefined;
        try {
            const found = pending.found;
            if (!responseEnded) found.push(...this._inspectBody(req, pending.watch));
            emitWatch(this.ts, req, found, 'Fastify');
        } catch (e) {
            this.ts.logger.error("Trappsec error in Fastify watch handler: ", e);
        }
    }
}

module.exports = FastifyIntegration;
