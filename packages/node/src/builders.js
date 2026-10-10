const NO_DEFAULT = Symbol('NO_DEFAULT');

const hasOwn = (o, k) => o != null && Object.prototype.hasOwnProperty.call(o, k);

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
        return this;
    }

    intent(intent) {
        this.config.intent = intent;
        return this;
    }

    _respond(kind, { status = undefined, body = undefined, mime_type = undefined, template = undefined } = {}) {
        const provided = (v) => v !== undefined && v !== null;
        const ov = this._overrides[kind] || {};

        if (provided(template)) {
            if (provided(status) || provided(body) || provided(mime_type)) {
                throw new Error("response_builder: `template` cannot be used together with `status`, `body`, or `mime_type`.");
            }

            const tmpl = hasOwn(this.ts._templates, template) ? this.ts._templates[template] : undefined;
            if (!tmpl) {
                throw new Error(`response_builder: template '${template}' not found.`);
            }

            // Shallow copy: function bodies must survive.
            this._overrides[kind] = { ...tmpl };
        } else {
            if (provided(status)) ov.status_code = status;
            if (provided(body)) ov.response_body = body;
            if (provided(mime_type)) ov.mime_type = mime_type;
            this._overrides[kind] = ov;
        }

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
                if (hasOwn(ov, k)) base[k] = ov[k];
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

class WatchBuilder {
    constructor(path) {
        this.path = path;
        this._query = Object.create(null);
        this._body = Object.create(null);
    }

    query(name, { defaultValue = NO_DEFAULT, intent = null } = {}) {
        this._query[name] = { default: defaultValue, intent: intent };
        return this;
    }

    body(name, { defaultValue = NO_DEFAULT, intent = null } = {}) {
        this._body[name] = { default: defaultValue, intent: intent };
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

module.exports = { TrapBuilder, WatchBuilder, NO_DEFAULT };
