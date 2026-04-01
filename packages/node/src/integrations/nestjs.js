class NestIntegration {
    constructor(ts, app) {
        this.ts = ts;
        this.app = app;
        this._adapterType = this._resolveAdapterType();

        // Default identity provider if not set
        if (!this.ts.identity.ip) {
            this.ts.identity.ip = (req) => this._extractIp(req);
        }

        // Standard request context extractors
        this.ts.requestContext.path = (req) => this._extractPath(req);
        this.ts.requestContext.userAgent = (req) => this._extractUserAgent(req);
        this.ts.requestContext.method = (req) => req?.method || req?.raw?.method || null;

        this._patchBootstrapLifecycle();
    }

    _patchBootstrapLifecycle() {
        const integration = this;
        const httpAdapter = this.app.getHttpAdapter();
        const originalAdapterListen = httpAdapter.listen;

        httpAdapter.listen = function (...args) {
            integration._bootstrapTrappsec();
            return originalAdapterListen.apply(this, args);
        };
    }

    _bootstrapTrappsec() {
        this.inject_traps();
        this.setup_watches();
    }

    inject_traps() {
        const httpAdapter = this.app.getHttpAdapter();
        const traps = this.ts.traps;

        let originalStack = [];
        const expressStack = this._getExpressRouterStack(httpAdapter.instance);
        const isExpress = Array.isArray(expressStack);

        if (isExpress) {
            originalStack = [...expressStack];
            expressStack.length = 0;
        }

        for (const decoy of traps) {
            const path = decoy.path;
            const methods = decoy.methods.map(m => m.toLowerCase()); // e.g. ['get', 'post']

            const handler = (req, res) => {
                try {
                    const { response_body, response_config } = this.ts._trigger_trap_event(req, decoy);
                    this._sendResponse(res, response_config.status_code, response_config.mime_type, response_body);
                } catch (e) {
                    this.ts.logger.error("Trappsec error in Nest trap handler:", e);
                    this._sendResponse(res, 500, "application/json", JSON.stringify({ error: "internal error" }));
                }
            };

            // Register handler for each method
            const supportedMethods = ['get', 'post', 'put', 'delete', 'patch', 'head', 'options'];
            for (const method of supportedMethods) {
                if (methods.includes(method) && typeof httpAdapter[method] === 'function') {
                    httpAdapter[method](path, handler);
                }
            }
        }

        if (isExpress) {
            expressStack.push(...originalStack);
        }
    }

    _sendResponse(res, statusCode, mimeType, payload) {
        // Express response
        if (typeof res.status === 'function' && typeof res.send === 'function') {
            if (mimeType && typeof res.type === 'function') {
                res.type(mimeType);
            }
            res.status(statusCode).send(payload);
            return;
        }

        // Fastify reply
        if (typeof res.code === 'function' && typeof res.send === 'function') {
            if (mimeType && typeof res.header === 'function') {
                res.header('Content-Type', mimeType);
            }
            res.code(statusCode).send(payload);
            return;
        }

        // Raw Node response
        if (typeof res.writeHead === 'function' && typeof res.end === 'function') {
            const headers = {};
            if (mimeType) {
                headers['Content-Type'] = mimeType;
            }
            res.writeHead(statusCode, headers);
            res.end(payload);
        }
    }

    setup_watches() {
        const watches = this.ts.watches;
        if (watches.length === 0) return;

        const watchMap = {};
        for (const watch of watches) {
            const path = this._normalizePath(watch.path);
            if (path) {
                watchMap[path] = watch;
            }
        }

        const httpAdapter = this.app.getHttpAdapter();
        const instance = httpAdapter.instance;

        const expressStack = this._getExpressRouterStack(instance);
        if (Array.isArray(expressStack)) {
            this._setupExpressWatches(expressStack, watchMap);
            return;
        }

        if (instance && typeof instance.addHook === 'function') {
            this._setupFastifyWatches(instance, watchMap);
            return;
        }

        this.ts.logger.error("Trappsec failed to set up Nest watches: unknown HTTP adapter instance.");
    }

    _resolveAdapterType() {
        const httpAdapter = this.app.getHttpAdapter();
        const adapterType = httpAdapter?.getType?.();
        if (adapterType === 'express' || adapterType === 'fastify') {
            return adapterType;
        }

        const instance = httpAdapter?.instance;
        if (this._getExpressRouterStack(instance)) {
            return 'express';
        }
        if (instance && typeof instance.addHook === 'function') {
            return 'fastify';
        }

        return 'unknown';
    }

    _extractPath(req) {
        if (!req) return null;

        if (this._adapterType === 'fastify') {
            return this._stripQuery(req.url || req.raw?.url || null);
        }
        if (this._adapterType === 'express') {
            return this._stripQuery(req.path || req.originalUrl || req.url || null);
        }

        return this._stripQuery(req.path || req.url || req.raw?.url || null);
    }

    _extractUserAgent(req) {
        if (!req) return null;

        if (this._adapterType === 'fastify') {
            return req.headers?.['user-agent'] || req.raw?.headers?.['user-agent'] || null;
        }
        if (this._adapterType === 'express') {
            if (req.headers?.['user-agent']) return req.headers['user-agent'];
            if (typeof req.get === 'function') return req.get('User-Agent');
            return null;
        }

        return req.headers?.['user-agent'] || req.raw?.headers?.['user-agent'] || null;
    }

    _extractIp(req) {
        if (!req) return "0.0.0.0";

        if (this._adapterType === 'fastify') {
            return req.ip || req.raw?.socket?.remoteAddress || "0.0.0.0";
        }
        if (this._adapterType === 'express') {
            return req.ip || req.socket?.remoteAddress || "0.0.0.0";
        }

        return req.ip || req.raw?.socket?.remoteAddress || req.socket?.remoteAddress || "0.0.0.0";
    }

    _extractMatchedRoutePath(req) {
        if (!req) return null;

        if (this._adapterType === 'fastify') {
            return this._normalizePath(
                req.routeOptions?.url ||
                req.routerPath ||
                req.context?.config?.url ||
                req.raw?.url
            );
        }
        if (this._adapterType === 'express') {
            if (req.route?.path) {
                // req.baseUrl holds the mount prefix stripped by any parent router
                // (empty string for top-level routes). Concatenating with req.route.path
                // reconstructs the full registered pattern used as the watchMap key.
                return this._normalizePath((req.baseUrl || '') + req.route.path);
            }
            return null;
        }

        return this._normalizePath(
            req.route?.path ||
            req.routeOptions?.url ||
            req.routerPath ||
            req.context?.config?.url ||
            req.url ||
            req.raw?.url
        );
    }

    _getExpressRouterStack(instance) {
        if (!instance) return null;
        if (instance._router && Array.isArray(instance._router.stack)) {
            return instance._router.stack;
        }
        if (instance.router && Array.isArray(instance.router.stack)) {
            return instance.router.stack;
        }
        return null;
    }

    _setupExpressWatches(routerStack, watchMap) {
        const integration = this;
        for (const layer of routerStack) {
            if (!layer || typeof layer.handle !== 'function') continue;

            // Sub-router: layer.route is null and the handle carries its own .stack.
            // Recurse so inner route layers are wrapped. req.baseUrl is set correctly
            // by Express for each nesting level, so _extractMatchedRoutePath handles
            // path reconstruction without any prefix tracking here.
            if (!layer.route && Array.isArray(layer.handle.stack)) {
                this._setupExpressWatches(layer.handle.stack, watchMap);
                continue;
            }

            if (layer.handle.__trappsecWrapped) continue;

            const oldHandler = layer.handle;
            const wrapped = function (req, res, next) {
                try {
                    const routePath = integration._extractMatchedRoutePath(req);
                    if (routePath) {
                        const watch = watchMap[routePath];
                        if (watch) {
                            integration._inspect(req, watch);
                        }
                    }
                } catch (e) {
                    integration.ts.logger.error("Trappsec error in Nest (Express) watch handler:", e);
                }
                return oldHandler(req, res, next);
            };

            wrapped.__trappsecWrapped = true;
            layer.handle = wrapped;
        }
    }

    _setupFastifyWatches(appInstance, watchMap) {
        if (appInstance.__trappsecWatchHookInstalled) {
            return;
        }

        const integration = this;
        appInstance.addHook('preHandler', function (req, reply, done) {
            try {
                const routePath = integration._extractMatchedRoutePath(req);
                if (routePath) {
                    const watch = watchMap[routePath];
                    if (watch) {
                        integration._inspect(req, watch);
                    }
                }
            } catch (e) {
                integration.ts.logger.error("Trappsec error in Nest (Fastify) watch handler:", e);
            }
            done();
        });
        appInstance.__trappsecWatchHookInstalled = true;
    }

    _stripQuery(path) {
        if (!path || typeof path !== 'string') {
            return null;
        }
        return path.split('?')[0];
    }

    _normalizePath(path) {
        const strippedPath = this._stripQuery(path);
        if (!strippedPath) {
            return null;
        }

        let normalized = strippedPath.split('#')[0].trim();
        if (!normalized) return null;
        if (!normalized.startsWith('/')) {
            normalized = `/${normalized}`;
        }
        if (normalized.length > 1 && normalized.endsWith('/')) {
            normalized = normalized.slice(0, -1);
        }

        return normalized;
    }

    _replaceData(target, newData) {
        if (!target || typeof target !== 'object') {
            return newData;
        }

        for (const key of Object.keys(target)) {
            delete target[key];
        }
        Object.assign(target, newData);
        return target;
    }

    _toQueryString(data) {
        const params = new URLSearchParams();
        for (const [key, value] of Object.entries(data || {})) {
            if (Array.isArray(value)) {
                for (const item of value) {
                    params.append(key, String(item));
                }
            } else {
                params.append(key, String(value));
            }
        }
        return params.toString();
    }

    _applySanitizedQuery(req, data) {
        // Fastify: sanitize parsed query object only. URL mutation is adapter-specific
        // and not needed for route handlers to observe cleaned query values.
        if (this._adapterType === 'fastify') {
            if (req.query && typeof req.query === 'object') {
                this._replaceData(req.query, data);
                return;
            }
            try {
                req.query = data;
            } catch (_e) {
                // no-op: keep request flow intact even if adapter marks query readonly
            }
            return;
        }

        // Express 5 can expose req.query as a getter-only property. Mutate in place
        // where possible and always rewrite URL query so subsequent getter reads reflect
        // sanitized values.
        if (req.query && typeof req.query === 'object') {
            this._replaceData(req.query, data);
        }

        const queryString = this._toQueryString(data);
        const baseUrl = this._stripQuery(req.url || req.originalUrl || '') || '';
        const nextUrl = queryString ? `${baseUrl}?${queryString}` : baseUrl;

        if (typeof req.url === 'string') {
            req.url = nextUrl;
        }
        if (typeof req.originalUrl === 'string') {
            req.originalUrl = nextUrl;
        }

        // Clear Express parseurl cache so req.query getter re-parses updated URL.
        if (Object.prototype.hasOwnProperty.call(req, '_parsedUrl')) {
            req._parsedUrl = undefined;
        }
    }

    _withType(foundFields, type) {
        return foundFields.map((field) => ({
            ...field,
            type
        }));
    }

    _inspect(req, watch) {
        const query_fields = watch.query_fields;
        const body_fields = watch.body_fields;
        let found = [];

        if (Object.keys(query_fields).length > 0 && req.query) {
            const queryCopy = { ...req.query };
            const { data, found_fields, touched } = this.ts._detect_honey_fields(queryCopy, query_fields, req);
            if (found_fields.length > 0) {
                found.push(...this._withType(found_fields, "query"));
            }
            if (touched) {
                try {
                    this._applySanitizedQuery(req, data);
                } catch (e) {
                    this.ts.logger.error("Trappsec failed to sanitize query fields:", e);
                }
            }
        }

        if (Object.keys(body_fields).length > 0 && req.body) {
            const bodyCopy = { ...req.body };
            const { data, found_fields, touched } = this.ts._detect_honey_fields(bodyCopy, body_fields, req);
            if (found_fields.length > 0) {
                found.push(...this._withType(found_fields, "body"));
            }
            if (touched) {
                try {
                    req.body = this._replaceData(req.body, data);
                } catch (e) {
                    this.ts.logger.error("Trappsec failed to sanitize body fields:", e);
                }
            }
        }

        if (found.length > 0) {
            this.ts._trigger_watch_event(req, found);
        }
    }
}

module.exports = NestIntegration;
