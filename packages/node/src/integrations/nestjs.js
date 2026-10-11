'use strict';

const ExpressIntegration = require('./express');
const FastifyIntegration = require('./fastify');

// NestJS runs on top of Express or Fastify. This integration only detects the
// underlying HTTP adapter and delegates everything (traps, watches, request context,
// bootstrap) to the Express / Fastify integration, so behaviour is identical:
//  * Express adapter: traps are inserted before the first route layer (after Nest's
//    middleware and body parsers); only route layers are wrapped, error middleware
//    keeps its arity.
//  * Fastify adapter: traps and the preValidation watch hook are installed by a
//    plugin that runs at ready() time.
// Note: Nest middleware bound to a specific HTTP method (consumer.apply(mw).forRoutes
// with a method) is registered by Nest as an Express route layer, so traps are
// inserted ahead of it.
class NestIntegration {
    constructor(ts, app) {
        this.ts = ts;
        this.app = app;

        const httpAdapter = app.getHttpAdapter();
        const instance = httpAdapter.getInstance ? httpAdapter.getInstance() : httpAdapter.instance;
        this._adapterType = this._resolveAdapterType(httpAdapter, instance);

        if (this._adapterType === 'fastify') {
            this._delegate = new FastifyIntegration(ts, instance, { hookListen: false });
        } else if (this._adapterType === 'express') {
            this._delegate = new ExpressIntegration(ts, instance, { hookListen: false, finishAtHandler: false });
            this._installBodyPipe(app);
        } else {
            throw new Error('trappsec error: unsupported NestJS HTTP adapter (expected Express or Fastify).');
        }

        // Nest never calls instance.listen(); it goes through the adapter.
        const integration = this;
        const originalListen = httpAdapter.listen;
        httpAdapter.listen = function (...args) {
            integration.bootstrap();
            return originalListen.apply(this, args);
        };
    }

    /**
     * Route-level interceptors (AnyFilesInterceptor / FileInterceptor run multer)
     * fill req.body after the Express route was entered and after any global
     * interceptor. Global pipes run after all interceptors, right before the
     * controller method, so a global pipe completes the deferred body inspection:
     * it strips honey fields from req.body in place, from a value an earlier pipe
     * already copied (e.g. a ValidationPipe DTO), and hides a single honey field
     * requested with @Body('field').
     */
    _installBodyPipe(app) {
        if (typeof app.useGlobalPipes !== 'function') return;
        const delegate = this._delegate;
        const { PENDING, INSPECTED, pendingRequest } = ExpressIntegration;
        const pipe = {
            transform(value, metadata) {
                try {
                    const req = pendingRequest.getStore();
                    if (!req || !metadata || metadata.type !== 'body') return value;
                    if (req[PENDING]) delegate._finishInspection(req);
                    const watch = req[INSPECTED];
                    const fields = watch && watch.body_fields;
                    if (!fields) return value;
                    const isHoney = (k) => Object.prototype.hasOwnProperty.call(fields, k);
                    if (typeof metadata.data === 'string' && metadata.data) {
                        return isHoney(metadata.data) ? undefined : value;
                    }
                    if (value && typeof value === 'object' && value !== req.body) {
                        for (const k of Object.keys(value)) if (isHoney(k)) delete value[k];
                    }
                } catch (e) {
                    delegate.ts.logger.error('Trappsec error in NestJS body pipe: ', e);
                }
                return value;
            },
        };
        app.useGlobalPipes(pipe);
    }

    _resolveAdapterType(httpAdapter, instance) {
        const type = httpAdapter?.getType?.();
        if (type === 'express' || type === 'fastify') return type;
        if (instance && typeof instance.addHook === 'function') return 'fastify';
        if (instance && typeof instance.use === 'function' && typeof instance.get === 'function') return 'express';
        return 'unknown';
    }

    // Public and idempotent.
    bootstrap() {
        this._delegate.bootstrap();
    }

    inject_traps(...args) {
        return this._delegate.inject_traps(...args);
    }

    setup_watches(...args) {
        return this._delegate.setup_watches(...args);
    }
}

module.exports = NestIntegration;
