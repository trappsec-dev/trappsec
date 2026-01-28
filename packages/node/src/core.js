const os = require('os');
const { TrapBuilder, WatchBuilder, NO_DEFAULT } = require('./builders');
const { LogHandler, WebhookHandler, OTELHandler } = require('./handlers');

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
        this._templates = {};
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

    add_webhook(url, { secret = null, headers = null, heartbeat_interval = null, template = null } = {}) {
        const handler = new WebhookHandler(url, { secret, headers, service: this.service, environment: this.environment, heartbeat_interval, template });
        this._handlers.push(handler);
        return this;
    }

    add_otel() {
        this._handlers.push(new OTELHandler());
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
        return this._traps.map(t => t.build ? t.build() : t);
    }

    get watches() {
        return this._watches.map(w => w.build ? w.build() : w);
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
                this.logger.error("error invoking handler: ", e);
            }
        }
    }

    _trigger_watch_event(req, found_fields) {
        const identity_ctx = this._get_identity_context(req);
        const request_ctx = this._get_request_context(req);

        const trigger_ctx = {
            timestamp: Date.now() / 1000,
            event: "trappsec.watch_hit",
            type: "signal",
            path: request_ctx.path,
            method: request_ctx.method,
            user_agent: request_ctx.userAgent,
            ip: identity_ctx.ip,
            found_fields: found_fields
        };

        if (identity_ctx.user) {
            trigger_ctx.type = "alert";
            trigger_ctx.user = identity_ctx.user;
            trigger_ctx.role = identity_ctx.role;
        }

        this._trigger(trigger_ctx);
    }

    _trigger_trap_event(req, trap) {
        const identity_ctx = this._get_identity_context(req);
        const request_ctx = this._get_request_context(req);

        const trigger_ctx = {
            timestamp: Date.now() / 1000,
            event: "trappsec.trap_hit",
            type: "signal",
            path: request_ctx.path,
            method: request_ctx.method,
            user_agent: request_ctx.userAgent,
            ip: identity_ctx.ip,
        };

        let response_key = "response.unauthenticated";

        if (identity_ctx.user) {
            trigger_ctx.type = "alert";
            trigger_ctx.user = identity_ctx.user;
            trigger_ctx.role = identity_ctx.role;
            response_key = "response.authenticated";
        }

        this._trigger(trigger_ctx);

        const response_config = trap[response_key];
        let response_body = response_config["response_body"];

        if (typeof response_body === 'function') {
            response_body = response_body(req);
        }

        if (response_config["mime_type"] === "application/json" && typeof response_body !== 'string') {
            response_body = JSON.stringify(response_body);
        }

        return { response_body, response_config };
    }

    _detect_honey_fields(data, rules, request_obj = null) {
        const found_fields = [];
        let modified = false;

        for (const key of Object.keys(data)) {
            if (rules[key]) {
                const rule_definition = rules[key];
                let expected = rule_definition.default;

                try {
                    if (typeof expected === 'function') {
                        expected = expected(request_obj);
                    }

                    if (expected === NO_DEFAULT || data[key] !== expected) {
                        found_fields.push({
                            type: "body",
                            field: key,
                            value: data[key],
                            intent: rule_definition.intent,
                        });
                        delete data[key];
                        modified = true;
                    }
                } catch (e) {
                    this.logger.error(`failed to evaluate callable expected value for body field \`\${key}\`: `, e);
                }
            }
        }
        return { data, found_fields };
    }

    _get_identity_context(req) {
        let u = null;
        let r = null;

        if (this.identity.auth) {
            const auth_context = this.identity.auth(req);
            if (auth_context) {
                u = auth_context.user;
                r = auth_context.role;
            }
        }

        return {
            user: u,
            role: r,
            ip: this.identity.ip ? this.identity.ip(req) : null
        };
    }

    _get_request_context(req) {
        return {
            path: this.requestContext.path(req),
            userAgent: this.requestContext.userAgent(req),
            method: this.requestContext.method(req)
        };
    }

    _register(app) {
        // Simple heuristic for now, can be improved
        if (app.use && app.get && app.post) {
            const ExpressIntegration = require('./integrations/express');
            this.integration = new ExpressIntegration(this, app);
        } else {
            throw new Error("trappsec error: unknown framework.");
        }
    }
}

module.exports = { Sentry, NO_DEFAULT };
