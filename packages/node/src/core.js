const os = require('os');
const { TrapBuilder, WatchBuilder, NO_DEFAULT } = require('./builders');
const { LogHandler, WebhookHandler, SlackHandler, OTELHandler, safeStringify } = require('./handlers');

const MAX_STR = 1024;
const hasOwn = (o, k) => o != null && Object.prototype.hasOwnProperty.call(o, k);

function truncStr(v, limit = MAX_STR) {
    if (typeof v !== 'string') return v == null ? null : v;
    return v.length > limit ? v.slice(0, limit) + "..." : v;
}

function isPlainObject(v) {
    if (v === null || typeof v !== 'object') return false;
    const p = Object.getPrototypeOf(v);
    return p === Object.prototype || p === null;
}

/** Sanitize a recorded value (C3). */
function safe_value(v) {
    if (v === null || v === undefined) return null;
    const t = typeof v;
    if (t === 'boolean' || t === 'number') return v;
    if (t === 'bigint') return String(v);
    if (t === 'string') return truncStr(v);
    if (Array.isArray(v)) return v.slice(0, 20).map(safe_value);
    if (isPlainObject(v)) return truncStr(safeStringify(v));
    const name = (v && v.constructor && v.constructor.name) || 'Object';
    return `<${name}>`;
}

function canonical(v) {
    if (typeof v === 'boolean') return v ? "true" : "false";
    return String(v);
}

/** Loose-but-safe equality between a received value and the configured default (C3). */
function values_match(actual, expected) {
    if (actual === expected) return true;
    const isNum = (x) => typeof x === 'number' || typeof x === 'bigint';
    if (isNum(actual) && isNum(expected)) return Number(actual) === Number(expected);
    const scalar = (x) => typeof x === 'boolean' || isNum(x);
    if (typeof actual === 'string' && scalar(expected)) return actual === canonical(expected);
    if (typeof expected === 'string' && scalar(actual)) return expected === canonical(actual);
    return false;
}

class Sentry {
    constructor(app, service, environment) {
        this.logger = console;
        this.hostname = os.hostname();
        this.service = service;
        this.environment = environment;

        this.identity = {
            ip: null,
            auth: null
        };

        this.requestContext = {
            path: r => null,
            userAgent: r => null,
            method: r => null
        };

        this._traps = [];
        this._watches = [];
        this._templates = Object.create(null);
        this._handlers = [new LogHandler(this.logger)];

        this.default_responses = {
            "authenticated": {
                "status_code": 200,
                "response_body": {},
                "mime_type": "application/json"
            },
            "unauthenticated": {
                "status_code": 401,
                "response_body": {},
                "mime_type": "application/json"
            }
        };

        this._register(app);
    }

    template(name, status_code, response_body, mime_type = "application/json") {
        this._templates[name] = { "status_code": status_code, "response_body": response_body, "mime_type": mime_type };
        return this;
    }

    trap(path) {
        const builder = new TrapBuilder(this, path);
        this._traps.push(builder);
        return builder;
    }

    watch(path) {
        const builder = new WatchBuilder(path);
        this._watches.push(builder);
        return builder;
    }

    add_webhook(url, { secret = null, headers = null, heartbeat_interval = null, template = null, alerts_only = true } = {}) {
        const handler = new WebhookHandler(url, { secret, headers, service: this.service, environment: this.environment, heartbeat_interval, template, alerts_only });
        this._handlers.push(handler);
        return this;
    }

    add_otel() {
        this._handlers.push(new OTELHandler());
        return this;
    }

    add_slack(url, { alerts_only = true } = {}) {
        const handler = new SlackHandler(url, { alerts_only, service: this.service, environment: this.environment });
        this._handlers.push(handler);
        return this;
    }

    identify_user(callback) {
        this.identity.auth = callback;
        return this;
    }

    override_source_ip(callback) {
        if (this._default_ip === undefined) this._default_ip = this.identity.ip;
        this.identity.ip = callback;
        return this;
    }

    get traps() {
        return this._traps.map(t => t.build ? t.build() : t);
    }

    get watches() {
        return this._watches.map(w => w.build ? w.build() : w);
    }

    /** Idempotent: installs traps and watches (delegates to the integration). */
    bootstrap() {
        if (this.integration && typeof this.integration.bootstrap === 'function') {
            return this.integration.bootstrap();
        }
    }

    /** Stop heartbeats and flush in-flight deliveries (default timeout 5s). */
    async close(timeout = 5000) {
        await Promise.all(this._handlers.map(async (h) => {
            if (typeof h.close !== 'function') return;
            try {
                await h.close(timeout);
            } catch (e) {
                this.logger.error("error closing handler:", e);
            }
        }));
    }

    /** Emit a custom trappsec.rule_hit event. Never throws. */
    trigger(req, reason, intent = null, metadata = null) {
        try {
            const ctx = this._base_event(req, "trappsec.rule_hit");
            ctx.reason = reason === undefined ? null : reason;
            ctx.intent = intent === undefined ? null : intent;
            ctx.metadata = metadata === undefined ? null : metadata;
            this._trigger(ctx);
        } catch (e) {
            this.logger.error("error triggering rule_hit:", e);
        }
    }

    _trigger(trigger_ctx) {
        trigger_ctx.app = {
            service: this.service,
            environment: this.environment,
            hostname: this.hostname
        };

        for (const h of this._handlers) {
            try {
                h.emit(trigger_ctx);
            } catch (e) {
                this.logger.error("error invoking handler:", e);
            }
        }
    }

    _base_event(req, name) {
        const identity_ctx = this._get_identity_context(req);
        const request_ctx = this._get_request_context(req);
        const ctx = {
            timestamp: Date.now() / 1000,
            event: name,
            type: "signal",
            path: truncStr(request_ctx.path),
            method: request_ctx.method == null ? null : request_ctx.method,
            user_agent: truncStr(request_ctx.userAgent),
            ip: identity_ctx.ip == null ? null : identity_ctx.ip,
            user: null,
            role: null,
        };
        if (identity_ctx.user) {
            ctx.type = "alert";
            ctx.user = identity_ctx.user;
            ctx.role = identity_ctx.role == null ? null : identity_ctx.role;
        }
        return ctx;
    }

    _trigger_watch_event(req, found_fields) {
        try {
            const ctx = this._base_event(req, "trappsec.watch_hit");
            ctx.found_fields = found_fields;
            this._trigger(ctx);
        } catch (e) {
            this.logger.error("error triggering watch_hit:", e);
        }
    }

    _trigger_trap_event(req, trap) {
        let authenticated = false;
        try {
            const ctx = this._base_event(req, "trappsec.trap_hit");
            ctx.intent = trap.intent === undefined ? null : trap.intent;
            authenticated = ctx.type === "alert";
            this._trigger(ctx);
        } catch (e) {
            this.logger.error("error triggering trap_hit:", e);
        }

        const response_config = trap[authenticated ? "response.authenticated" : "response.unauthenticated"];
        let response_body = response_config["response_body"];

        if (typeof response_body === 'function') {
            try {
                response_body = response_body(req);
            } catch (e) {
                this.logger.error("dynamic trap response body failed:", e);
                response_body = {};
            }
        }

        if (typeof response_body !== 'string' && response_config["mime_type"] === "application/json") {
            response_body = safeStringify(response_body === undefined ? {} : response_body);
        }

        return { response_body, response_config };
    }

    /**
     * Inspect `data` for watched keys. Always strips watched keys (R4).
     * `source` is "query" or "body" and is recorded as found_fields[].type.
     */
    _detect_honey_fields(data, rules, request_obj = null, source = 'body') {
        if (Array.isArray(data)) {
            const all = [];
            let touched = false;
            for (const el of data) {
                if (el !== null && typeof el === 'object' && !Array.isArray(el)) {
                    const r = this._detect_honey_fields(el, rules, request_obj, source);
                    all.push(...r.found_fields);
                    touched = touched || r.touched;
                }
            }
            return { data, found_fields: all, touched };
        }

        const found_fields = [];
        let touched = false;
        if (data === null || typeof data !== 'object' || !rules) {
            return { data, found_fields, touched };
        }

        for (const key of Object.keys(data)) {
            if (!hasOwn(rules, key)) continue;
            touched = true;
            const rule_definition = rules[key] || {};
            let expected = hasOwn(rule_definition, 'default') ? rule_definition.default : NO_DEFAULT;

            try {
                if (typeof expected === 'function') {
                    try {
                        expected = expected(request_obj);
                    } catch (e) {
                        this.logger.error(`failed to evaluate callable expected value for ${source} field \`${key}\`:`, e);
                        expected = NO_DEFAULT;
                    }
                }

                let actual = data[key];
                if (Array.isArray(actual) && actual.length === 1) actual = actual[0];

                let violation;
                if (expected === NO_DEFAULT) {
                    violation = true;
                } else if (Array.isArray(actual) && actual.length > 1) {
                    violation = !actual.every(a => values_match(a, expected));
                } else {
                    violation = !values_match(actual, expected);
                }

                if (violation) {
                    found_fields.push({
                        type: source,
                        field: key,
                        value: safe_value(actual),
                        intent: rule_definition.intent === undefined ? null : rule_definition.intent,
                    });
                }
            } catch (e) {
                this.logger.error(`failed to inspect ${source} field \`${key}\`:`, e);
            }

            try {
                delete data[key];
            } catch (e) {
                this.logger.error(`failed to strip ${source} field \`${key}\`:`, e);
            }
        }
        return { data, found_fields, touched };
    }

    _get_identity_context(req) {
        let u = null;
        let r = null;
        let ip = null;

        if (this.identity.auth) {
            try {
                const auth_context = this.identity.auth(req);
                if (auth_context) {
                    u = auth_context.user || null;
                    r = auth_context.role == null ? null : auth_context.role;
                    if (!u) r = null;
                }
            } catch (e) {
                this.logger.error("identify_user callback failed:", e);
                u = null;
                r = null;
            }
        }

        if (this.identity.ip) {
            try {
                ip = this.identity.ip(req);
            } catch (e) {
                this.logger.error("override_source_ip callback failed:", e);
                ip = null;
                if (typeof this._default_ip === 'function' && this._default_ip !== this.identity.ip) {
                    try { ip = this._default_ip(req); } catch (e2) { ip = null; }
                }
            }
        }

        return { user: u, role: r, ip: ip == null ? null : ip };
    }

    _get_request_context(req) {
        const safe = (fn) => {
            try { return fn(req); } catch (e) {
                this.logger.error("request context extractor failed:", e);
                return null;
            }
        };
        return {
            path: safe(this.requestContext.path),
            userAgent: safe(this.requestContext.userAgent),
            method: safe(this.requestContext.method)
        };
    }

    _register(app) {
        if (!app) {
            throw new Error("trappsec error: unknown framework.");
        }

        const fn = (x) => typeof x === 'function';

        const integrations = [
            { detect: a => fn(a.getHttpAdapter) && fn(a.useGlobalInterceptors), path: './integrations/nestjs'  },
            { detect: a => fn(a.ext) && fn(a.start) && fn(a.route),             path: './integrations/hapi'    },
            { detect: a => fn(a.callback) && Array.isArray(a.middleware),       path: './integrations/koa'     },
            { detect: a => fn(a.addHook) && fn(a.register) && fn(a.listen),     path: './integrations/fastify' },
            { detect: a => fn(a.use) && fn(a.get) && fn(a.post) && !fn(a.ext) && !fn(a.callback), path: './integrations/express' },
        ];

        for (const { path } of integrations.filter(({ detect }) => detect(app))) {
            const Integration = require(path);
            this.integration = new Integration(this, app);
            return;
        }

        throw new Error("trappsec error: unknown framework.");
    }
}

module.exports = { Sentry, NO_DEFAULT, values_match, safe_value };
