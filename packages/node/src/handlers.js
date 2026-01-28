const axios = require('axios');
const crypto = require('crypto');

class LogHandler {
    constructor(logger) {
        this.logger = logger;
    }

    emit(event) {
        this.logger.warn(JSON.stringify(event));
    }
}

class WebhookHandler {
    constructor(url, { secret = null, headers = null, service = null, environment = null, heartbeat_interval = null, template = null } = {}) {
        this.url = url;
        this.secret = secret;
        this.service = service;
        this.environment = environment;
        this.template = template;
        this.logger = console; // Default logger

        this.headers = { "Content-Type": "application/json" };
        if (headers) {
            Object.assign(this.headers, headers);
        }

        if (heartbeat_interval) {
            setInterval(() => this._heartbeat(), heartbeat_interval * 1000).unref();
        }
    }

    emit(event) {
        if (this.template) {
            try {
                event = this.template(event);
            } catch (e) {
                this.logger.error(`Failed to apply webhook template: ${e}`);
            }
        }

        const payload = JSON.stringify(event);
        this._send(payload);
    }

    _heartbeat() {
        const payload = JSON.stringify({
            timestamp: Date.now() / 1000,
            event: "trappsec.heartbeat",
            service: this.service,
            environment: this.environment,
        });
        this._send(payload);
    }

    _send(payload) {
        const headers = { ...this.headers };
        if (this.secret) {
            const hmac = crypto.createHmac('sha256', this.secret);
            hmac.update(payload);
            headers["x-trappsec-signature"] = hmac.digest('hex');
        }

        axios.post(this.url, payload, { headers: headers, timeout: 5000 })
            .catch(e => {
                this.logger.error(`Failed to send webhook: ${e.message}`);
            });
    }
}

class OTELHandler {
    constructor() {
        try {
            this.trace = require('@opentelemetry/api').trace;
        } catch (e) {
            throw new Error("opentelemetry-api library required for OTELHandler");
        }
    }

    emit(event) {
        const current_span = this.trace.getSpan(require('@opentelemetry/api').context.active());
        if (current_span && current_span.isRecording()) {
            current_span.setAttribute("trappsec.detected", true);
            current_span.setAttribute("trappsec.event", event.event);
            current_span.setAttribute("trappsec.type", event.type);

            if (event.user) current_span.setAttribute("trappsec.user", event.user);
            if (event.role) current_span.setAttribute("trappsec.role", event.role);
            if (event.ip) current_span.setAttribute("trappsec.ip", event.ip);

            if (event.event === "trappsec.watch_hit") {
                for (const field_info of event.found_fields) {
                    current_span.addEvent("watch_hit", field_info);
                }
            }

            if (event.event === "trappsec.trap_hit") {
                if (event.intent) current_span.setAttribute("trappsec.intent", event.intent);
            }

            if (event.event === "trappsec.rule_hit") {
                if (event.intent) current_span.setAttribute("trappsec.intent", event.intent);
                if (event.reason) current_span.setAttribute("trappsec.reason", event.reason);
            }

            if (event.metadata && typeof event.metadata === 'object' && !Array.isArray(event.metadata)) {
                for (const [k, v] of Object.entries(event.metadata)) {
                    current_span.setAttribute(`metadata.${k}`, v);
                }
            }
        }
    }
}

module.exports = { LogHandler, WebhookHandler, OTELHandler };
