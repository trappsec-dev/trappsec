const os = require('os');
const { mergeResponse, TrapBuilder, WatchBuilder, NO_DEFAULT } = require('./builders');
const { LogHandler, WebhookHandler, SlackHandler, OTELHandler, safeStringify, isAsyncResult } = require('./handlers');
const { normalizePath } = require('./integrations/_common');

const MAX_STR = 1024;
// Containers nested deeper than this are never matched and are recorded as
// NESTED (a top-level array or object is depth 1), so no input can exhaust the stack.
const MAX_DEPTH = 32;
const NESTED = "<nested>";

/** Truncate to `limit` code points (as Python and Go do), never splitting a surrogate pair. */
function truncStr(v, limit = MAX_STR) {
    if (typeof v !== 'string') return v == null ? null : v;
    if (v.length <= limit) return v; // UTF-16 length >= code point count
    const points = Array.from(v);
    return points.length > limit ? points.slice(0, limit).join("") + "..." : v;
}

function isPlainObject(v) {
    if (v === null || typeof v !== 'object') return false;
    const p = Object.getPrototypeOf(v);
    return p === Object.prototype || p === null;
}

/** Copy of `v` with every array / plain object deeper than MAX_DEPTH replaced by NESTED. */
function clip(v, depth) {
    const arr = Array.isArray(v);
    if (!arr && !isPlainObject(v)) return v;
    if (depth > MAX_DEPTH) return NESTED;
    if (arr) return v.map((x) => clip(x, depth + 1));
    const out = Object.create(null);
    for (const k of Object.keys(v)) out[k] = clip(v[k], depth + 1);
    return out;
}

function sanitize(v, depth) {
    if (v === null || v === undefined) return null;
    const t = typeof v;
    if (t === 'boolean' || t === 'number') return v;
    if (t === 'bigint') return String(v);
    if (t === 'string') return truncStr(v);
    if (Array.isArray(v)) return depth > MAX_DEPTH ? NESTED : v.slice(0, 20).map((x) => sanitize(x, depth + 1));
    if (isPlainObject(v)) {
        if (depth > MAX_DEPTH) return NESTED;
        let clipped;
        try { clipped = clip(v, depth); } catch (e) { return "<Object>"; } // throwing getter
        return truncStr(safeStringify(clipped, { sortKeys: true }));
    }
    const name = (v && v.constructor && v.constructor.name) || 'Object';
    return `<${name}>`;
}

/** Sanitize a recorded value (C3). */
function safe_value(v) {
    return sanitize(v, 1);
}

function canonical(v) {
    if (typeof v === 'boolean') return v ? "true" : "false";
    return String(v);
}

/** Loose-but-safe equality between a received value and the configured default (C3). */
function values_match(actual, expected, depth = 1) {
    const aArr = Array.isArray(actual), eArr = Array.isArray(expected);
    const aObj = isPlainObject(actual), eObj = isPlainObject(expected);
    if ((aArr || eArr || aObj || eObj) && depth > MAX_DEPTH) return false;
    if (actual === expected) return true;
    // Containers compare element-wise / key-wise with these same rules.
    if (aArr || eArr) {
        return aArr && eArr && actual.length === expected.length
            && actual.every((a, i) => values_match(a, expected[i], depth + 1));
    }
    if (aObj || eObj) {
        if (!aObj || !eObj) return false;
        const keys = Object.keys(actual);
        return keys.length === Object.keys(expected).length
            && keys.every(k => Object.hasOwn(expected, k) && values_match(actual[k], expected[k], depth + 1));
    }
    const isNum = (x) => typeof x === 'number' || typeof x === 'bigint';
    if (isNum(actual) && isNum(expected)) return Number(actual) === Number(expected);
    const scalar = (x) => typeof x === 'boolean' || isNum(x);
    if (typeof actual === 'string' && scalar(expected)) return actual === canonical(expected);
    if (typeof expected === 'string' && scalar(actual)) return expected === canonical(actual);
    return false;
}

// Path segments that match any single non-empty segment, and the forms that, as
// the LAST segment, match one or more remaining segments instead.
const PARAM_SEG = /^(:\w+\??|\{[^}]*\}|<[^>]*>|\*\w*)$/;
const CATCH_ALL_SEG = /^(\*\w*|\{[^}]*(\.\.\.|:path)\}|<path:[^>]*>)$/;

/** A trap path as {key} (no placeholders: exact lookup) or {segs, catchAll}. */
function compileTrapPath(path) {
    const want = normalizePath(path);
    if (!want) return null;
    const segs = want.split('/');
    const catchAll = segs.length > 1 && CATCH_ALL_SEG.test(segs[segs.length - 1]);
    if (!catchAll && !segs.some((seg) => PARAM_SEG.test(seg))) return { key: want };
    return { segs: segs.map((seg, i) => (i === segs.length - 1 && catchAll) || PARAM_SEG.test(seg) ? null : seg), catchAll };
}

function trapPatternMatches({ segs, catchAll }, parts) {
    if (catchAll ? parts.length < segs.length : parts.length !== segs.length) return false;
    for (let i = 0; i < segs.length; i++) {
        if (segs[i] === null ? parts[i] === '' : segs[i] !== parts[i]) return false;
    }
    // A catch-all needs a non-empty segment at its own position and after it.
    return !catchAll || parts.slice(segs.length - 1).every((p) => p !== '');
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

        // Same name and keys as Python's `ts.request`; `requestContext` and
        // `userAgent` remain as aliases.
        this.request = {
            path: r => null,
            user_agent: r => null,
            method: r => null
        };

        this._traps = [];
        this._trap_index = null;
        this._warnedAsync = new Set();
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
        // Integrations install their default extractor above; override_source_ip
        // falls back to it when the override fails.
        this._default_ip = this.identity.ip;
    }

    /** @deprecated Use `request`. */
    get requestContext() {
        return this.request;
    }

    set requestContext(value) {
        this.request = value;
    }

    /**
     * Default response for authenticated requests to traps that do not call
     * `respond`. Same options as `TrapBuilder.respond`: only the options you
     * pass change the default, and `template` replaces it.
     */
    default_response(opts = {}) {
        return this._set_default("authenticated", opts || {});
    }

    /** Default response for unauthenticated requests to traps that do not call `if_unauthenticated`. */
    default_unauthenticated_response(opts = {}) {
        return this._set_default("unauthenticated", opts || {});
    }

    _set_default(kind, opts) {
        this.default_responses[kind] = mergeResponse("default_response", this._templates, this.default_responses[kind], opts);
        return this;
    }

    template(name, status_code, response_body, mime_type = "application/json") {
        this._templates[name] = { "status_code": status_code, "response_body": response_body, "mime_type": mime_type };
        return this;
    }

    trap(path) {
        const builder = new TrapBuilder(this, path);
        this._traps.push(builder);
        this._traps_changed();
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
        this.identity.ip = callback;
        return this;
    }

    get traps() {
        return this._traps.map(t => t.build());
    }

    get watches() {
        return this._watches.map(w => w.build());
    }

    /** Idempotent: installs traps and watches (delegates to the integration). */
    bootstrap() {
        if (this.integration && typeof this.integration.bootstrap === 'function') {
            return this.integration.bootstrap();
        }
    }

    /**
     * Stop heartbeats and flush in-flight deliveries. `timeout` is in seconds
     * (default 5), as in Python. Values of 1000 or more are read as
     * milliseconds, the unit used before 0.3, with a deprecation warning.
     */
    async close(timeout = 5) {
        let ms = Number(timeout);
        if (!Number.isFinite(ms) || ms < 0) ms = 5;
        if (ms >= 1000) {
            if (!this._warnedCloseMs) {
                this._warnedCloseMs = true;
                this.logger.warn("trappsec: close(timeout) is now in seconds; reading " + timeout + " as milliseconds. Pass seconds instead.");
            }
        } else {
            ms *= 1000;
        }
        await Promise.all(this._handlers.map(async (h) => {
            if (typeof h.close !== 'function') return;
            try {
                await h.close(ms);
            } catch (e) {
                this.logger.error("error closing handler:", e);
            }
        }));
    }

    /**
     * True when the request targets a trap (method and path). Use it to skip
     * middleware that would otherwise reject a trap before it can answer, such as
     * CSRF protection (R22): a trap that answers 403 is both disabled and easy to
     * fingerprint. `:id`, `{id}` and `<id>` segments match any single segment.
     * Install such a wrapper at app level so the request path is the full path.
     * Never throws.
     */
    is_trap(req) {
        try {
            const method = String(this.request.method(req) || '').toUpperCase();
            const path = normalizePath(this.request.path(req));
            if (!method || !path) return false;
            const index = this._get_trap_index();
            if (index.exact.has(`${method} ${path}`)) return true;
            const patterns = index.patterns.get(method);
            if (!patterns) return false;
            const parts = path.split('/');
            return patterns.some((p) => trapPatternMatches(p, parts));
        } catch (e) {
            return false;
        }
    }

    /** Drop the is_trap index; call after a trap is added or its methods change. */
    _traps_changed() {
        this._trap_index = null;
    }

    /** Lazy lookup for is_trap: exact "METHOD path" keys plus compiled patterns per method. */
    _get_trap_index() {
        const idx = this._trap_index;
        if (idx && idx.src === this._traps && idx.len === this._traps.length) return idx;
        const built = { src: this._traps, len: this._traps.length, exact: new Set(), patterns: new Map() };
        for (const t of this._traps) {
            const compiled = compileTrapPath(t.config.path);
            if (!compiled) continue;
            for (const m of t.config.methods || []) {
                const method = String(m).toUpperCase();
                if (compiled.key !== undefined) {
                    built.exact.add(`${method} ${compiled.key}`);
                } else {
                    if (!built.patterns.has(method)) built.patterns.set(method, []);
                    built.patterns.get(method).push(compiled);
                }
            }
        }
        this._trap_index = built;
        return built;
    }

    /**
     * Emit a custom trappsec.rule_hit event: `trigger(req, reason, { intent, metadata })`.
     * The positional form `trigger(req, reason, intent, metadata)` is still accepted.
     * Never throws.
     */
    trigger(req, reason, opts = null, legacyMetadata = null) {
        try {
            let intent = opts;
            let metadata = legacyMetadata;
            if (opts !== null && typeof opts === 'object' && !Array.isArray(opts)) {
                intent = opts.intent === undefined ? null : opts.intent;
                metadata = opts.metadata === undefined ? null : opts.metadata;
            }
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
                if (this._async_result(response_body, "dynamic trap body")) response_body = {};
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
            if (!Object.hasOwn(rules, key)) continue;
            touched = true;
            const rule_definition = rules[key] || {};
            let expected = Object.hasOwn(rule_definition, 'default') ? rule_definition.default : NO_DEFAULT;

            try {
                if (typeof expected === 'function') {
                    try {
                        expected = expected(request_obj);
                        if (this._async_result(expected, "callable watch default")) expected = NO_DEFAULT;
                    } catch (e) {
                        this.logger.error(`failed to evaluate callable expected value for ${source} field \`${key}\`:`, e);
                        expected = NO_DEFAULT;
                    }
                }

                let actual = data[key];

                // Multi-valued fields arrive as arrays: unless the whole array
                // matches (an array default), every element must match.
                let violation;
                if (expected === NO_DEFAULT) {
                    violation = true;
                } else if (values_match(actual, expected)) {
                    violation = false;
                } else if (Array.isArray(actual) && actual.length > 0) {
                    violation = !actual.every(a => values_match(a, expected));
                } else {
                    violation = true;
                }

                // A one-element array is reported as its scalar.
                if (Array.isArray(actual) && actual.length === 1) actual = actual[0];

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
                let auth_context = this.identity.auth(req);
                if (this._async_result(auth_context, "identify_user")) auth_context = null;
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
                if (this._async_result(ip, "override_source_ip")) ip = this._fallback_ip(req);
            } catch (e) {
                this.logger.error("override_source_ip callback failed:", e);
                ip = this._fallback_ip(req);
            }
        }

        return { user: u, role: r, ip: ip == null ? null : ip };
    }

    /** The integration's default extractor, for when the override fails; null if there is none. */
    _fallback_ip(req) {
        if (typeof this._default_ip !== 'function' || this._default_ip === this.identity.ip) return null;
        try {
            const ip = this._default_ip(req);
            return this._async_result(ip, "default source ip") ? null : ip;
        } catch (e) {
            return null;
        }
    }

    /** True when a callback returned a promise (logged once; see isAsyncResult). */
    _async_result(result, kind) {
        if (!this._warnedAsync) this._warnedAsync = new Set();
        return isAsyncResult(result, this.logger, kind, this._warnedAsync);
    }

    _get_request_context(req) {
        const safe = (fn) => {
            try { return fn(req); } catch (e) {
                this.logger.error("request context extractor failed:", e);
                return null;
            }
        };
        const rc = this.request || {};
        return {
            path: safe(rc.path),
            userAgent: safe(rc.user_agent || rc.userAgent),
            method: safe(rc.method)
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
