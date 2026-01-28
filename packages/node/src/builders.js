const NO_DEFAULT = Symbol('NO_DEFAULT');

class TrapBuilder {
    constructor(ts, path) {
        this.ts = ts;
        this.config = {
            path: path,
            methods: ["GET", "POST"],
            intent: null,
            "response.authenticated": JSON.parse(JSON.stringify(this.ts.default_responses["authenticated"])),
            "response.unauthenticated": JSON.parse(JSON.stringify(this.ts.default_responses["unauthenticated"])),
        };
    }

    methods(...args) {
        this.config.methods = args;
        return this;
    }

    intent(intent) {
        this.config.intent = intent;
        return this;
    }

    _respond(key, { status = null, body = null, mime_type = null, template = null } = {}) {
        key = "response." + key;
        if (template) {
            if (status !== null || body !== null || mime_type !== null) {
                throw new Error("response_builder: `template` cannot be used together with `status`, `body`, or `mime_type`.");
            }

            const tmpl = this.ts._templates[template];
            if (!tmpl) {
                throw new Error(`response_builder: template '${template}' not found.`);
            }

            this.config[key] = JSON.parse(JSON.stringify(tmpl));
        } else {
            if (status) {
                this.config[key]["status_code"] = status;
            }

            if (body) {
                this.config[key]["response_body"] = body;
            }

            if (mime_type) {
                this.config[key]["mime_type"] = mime_type;
            }
        }

        return this;
    }

    respond({ status = null, body = null, mime_type = null, template = null } = {}) {
        this._respond("authenticated", { status, body, mime_type, template });
        return this;
    }

    if_unauthenticated({ status = null, body = null, mime_type = null, template = null } = {}) {
        this._respond("unauthenticated", { status, body, mime_type, template });
        return this;
    }

    build() {
        return this.config;
    }
}

class WatchBuilder {
    constructor(path) {
        this.path = path;
        this._query = {};
        this._body = {};
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
