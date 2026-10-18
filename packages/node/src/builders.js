const NO_DEFAULT = Symbol('NO_DEFAULT');

/**
 * Validated copy of a response `headers` object: string names and values, no
 * CR/LF. Throws a TypeError naming `label` otherwise.
 */
function checkHeaders(label, headers) {
    if (headers === null || typeof headers !== 'object' || Array.isArray(headers)) {
        throw new TypeError(`${label}: \`headers\` must be an object of header name to value.`);
    }
    const out = {};
    for (const [name, value] of Object.entries(headers)) {
        if (typeof value !== 'string') {
            throw new TypeError(`${label}: header values must be strings, got ${typeof value} for '${name}'.`);
        }
        if (!name || name === '__proto__' || /[\r\n:]/.test(name) || /[\r\n]/.test(value)) {
            throw new TypeError(`${label}: invalid header '${name}'.`);
        }
        out[name] = value;
    }
    return out;
}

// Never taken from configured headers: the framework computes them.
const FRAMING_HEADERS = new Set(["content-length", "transfer-encoding"]);

/** `base` with `extra` applied; names compare case-insensitively. */
function mergeHeaders(base, extra) {
    const out = { ...(base || {}) };
    for (const [name, value] of Object.entries(extra)) {
        for (const k of Object.keys(out)) {
            if (k.toLowerCase() === name.toLowerCase()) delete out[k];
        }
        out[name] = value;
    }
    return out;
}

/**
 * Status, mime type and headers to send. A configured Content-Type header
 * replaces mime_type; framing headers are dropped.
 */
function responseHead(cfg, headers) {
    const out = { status_code: cfg.status_code, mime_type: cfg.mime_type, headers: {} };
    for (const [name, value] of Object.entries(headers || {})) {
        const lower = name.toLowerCase();
        if (lower === "content-type") out.mime_type = value;
        else if (!FRAMING_HEADERS.has(lower)) out.headers[name] = value;
    }
    return out;
}

/**
 * Shared by `Sentry.default_response` and `TrapBuilder.respond`: returns the new
 * response settings for `base` (the settings so far) after applying `opts`.
 * Only the options passed change anything; `template` replaces everything.
 */
function mergeResponse(label, templates, base, { status, body, mime_type, template, headers } = {}) {
    const provided = (v) => v !== undefined && v !== null;
    if (provided(template)) {
        if (provided(status) || provided(body) || provided(mime_type) || provided(headers)) {
            throw new Error(`${label}: \`template\` cannot be used together with \`status\`, \`body\`, \`mime_type\`, or \`headers\`.`);
        }
        if (!Object.hasOwn(templates, template)) {
            throw new Error(`${label}: template '${template}' not found.`);
        }
        // Shallow copy: function bodies must survive.
        return { ...templates[template] };
    }
    const next = { ...base };
    if (provided(status)) next.status_code = status;
    if (provided(body)) next.response_body = body;
    if (provided(mime_type)) next.mime_type = mime_type;
    if (provided(headers)) next.headers = checkHeaders(label, headers);
    return next;
}

class TrapBuilder {
    constructor(ts, path) {
        this.ts = ts;
        this.config = {
            path: path,
            methods: ["GET", "POST"],
            intent: null,
        };
        // Per-kind overrides; defaults are resolved when build() is called so
        // that the order of default_responses configuration does not matter.
        this._overrides = { authenticated: null, unauthenticated: null };
        this._hook = null;
    }

    methods(...args) {
        this.config.methods = args;
        if (this.ts && typeof this.ts._traps_changed === 'function') this.ts._traps_changed();
        return this;
    }

    intent(intent) {
        this.config.intent = intent;
        return this;
    }

    _respond(kind, opts = {}) {
        this._overrides[kind] = mergeResponse("response_builder", this.ts._templates, this._overrides[kind] || {}, opts);
        return this;
    }

    respond(opts = {}) {
        return this._respond("authenticated", opts || {});
    }

    if_unauthenticated(opts = {}) {
        return this._respond("unauthenticated", opts || {});
    }

    /**
     * Per-request response hook, called as `hook(req, ctx)` on every hit, with
     * `ctx` = `{ authenticated, user, role }`. Return null/undefined to send the
     * static response for that auth state, or an object with any of `status`,
     * `body`, `mime_type` and `headers` to override it (`headers` are merged
     * into the static ones). It must be synchronous; if it fails, the static
     * response is sent.
     */
    respond_with(hook) {
        if (hook !== null && hook !== undefined && typeof hook !== 'function') {
            throw new TypeError("respond_with: `hook` must be a function or null.");
        }
        this._hook = hook || null;
        return this;
    }

    _resolve(kind) {
        const ov = this._overrides[kind];
        const base = { ...this.ts.default_responses[kind] };
        if (ov) {
            for (const k of ["status_code", "response_body", "mime_type", "headers"]) {
                if (Object.hasOwn(ov, k)) base[k] = ov[k];
            }
        }
        return base;
    }

    build() {
        return {
            ...this.config,
            methods: [...this.config.methods],
            "response.authenticated": this._resolve("authenticated"),
            "response.unauthenticated": this._resolve("unauthenticated"),
            // Sent when the trap's own body cannot be produced (R16).
            "fallback.authenticated": { ...this.ts.default_responses.authenticated },
            "fallback.unauthenticated": { ...this.ts.default_responses.unauthenticated },
            response_hook: this._hook,
        };
    }
}

// `{ default, intent }`, as in Python; `defaultValue` is the pre-0.3 name.
function fieldRule(opts) {
    const o = opts || {};
    let def = NO_DEFAULT;
    if (Object.hasOwn(o, 'default')) def = o.default;
    else if (Object.hasOwn(o, 'defaultValue')) def = o.defaultValue;
    if (def === undefined) def = NO_DEFAULT;
    return { default: def, intent: o.intent === undefined ? null : o.intent };
}

class WatchBuilder {
    constructor(path) {
        this.path = path;
        this._query = Object.create(null);
        this._body = Object.create(null);
    }

    query(name, opts = {}) {
        this._query[name] = fieldRule(opts);
        return this;
    }

    body(name, opts = {}) {
        this._body[name] = fieldRule(opts);
        return this;
    }

    build() {
        return {
            path: this.path,
            query_fields: this._query,
            body_fields: this._body
        };
    }
}

module.exports = { checkHeaders, mergeHeaders, responseHead, mergeResponse, TrapBuilder, WatchBuilder, NO_DEFAULT };
