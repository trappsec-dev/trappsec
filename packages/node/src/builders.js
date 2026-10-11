const NO_DEFAULT = Symbol('NO_DEFAULT');

/**
 * Shared by `Sentry.default_response` and `TrapBuilder.respond`: returns the new
 * response settings for `base` (the settings so far) after applying `opts`.
 * Only the options passed change anything; `template` replaces everything.
 */
function mergeResponse(label, templates, base, { status, body, mime_type, template } = {}) {
    const provided = (v) => v !== undefined && v !== null;
    if (provided(template)) {
        if (provided(status) || provided(body) || provided(mime_type)) {
            throw new Error(`${label}: \`template\` cannot be used together with \`status\`, \`body\`, or \`mime_type\`.`);
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

    _resolve(kind) {
        const ov = this._overrides[kind];
        const base = { ...this.ts.default_responses[kind] };
        if (ov) {
            for (const k of ["status_code", "response_body", "mime_type"]) {
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

module.exports = { mergeResponse, TrapBuilder, WatchBuilder, NO_DEFAULT };
