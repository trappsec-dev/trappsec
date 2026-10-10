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
            this._delegate = new ExpressIntegration(ts, instance, { hookListen: false });
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
