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
    constructor(url, { secret = null, headers = null, service = null, environment = null, heartbeat_interval = null, template = null, alerts_only = true } = {}) {
        this.url = url;
        this.secret = secret;
        this.service = service;
        this.environment = environment;
        this.template = template;
        this.alerts_only = alerts_only;
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
        if (this.alerts_only && event?.type !== "alert") {
            return;
        }

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

function stringify(value) {
    if (value === null || value === undefined) return "-";
    if (typeof value === "object") return JSON.stringify(value);
    return String(value);
}

function truncate(value, limit = 180) {
    if (value.length <= limit) return value;
    if (limit <= 3) return value.slice(0, limit);
    return `${value.slice(0, limit - 3)}...`;
}

function buildSlackPayload(event, { service = null, environment = null } = {}) {
    const app = event?.app || {};
    const eventName = event?.event || "trappsec.event";
    const eventType = event?.type || "signal";
    const severity = eventType === "alert" ? "ALERT" : "SIGNAL";
    const emoji = eventType === "alert" ? ":rotating_light:" : ":large_blue_circle:";

    const svc = app.service || service || "unknown-service";
    const env = app.environment || environment || "unknown-env";
    const host = app.hostname || "unknown-host";
    const path = event?.path || "-";
    const method = event?.method || "-";
    const intent = event?.intent || "-";
    const reason = event?.reason || "-";
    const ip = event?.ip || "-";
    const user = event?.user || "-";
    const role = event?.role || "-";
    const ua = truncate(stringify(event?.user_agent), 120);

    const fields = [
        { type: "mrkdwn", text: `*Severity*\n${severity}` },
        { type: "mrkdwn", text: `*Event*\n\`${eventName}\`` },
        { type: "mrkdwn", text: `*Service*\n\`${svc}\`` },
        { type: "mrkdwn", text: `*Environment*\n\`${env}\`` },
        { type: "mrkdwn", text: `*Method*\n\`${method}\`` },
        { type: "mrkdwn", text: `*Path*\n\`${truncate(path, 80)}\`` },
        { type: "mrkdwn", text: `*User*\n\`${truncate(user, 80)}\`` },
        { type: "mrkdwn", text: `*Role*\n\`${truncate(role, 80)}\`` },
        { type: "mrkdwn", text: `*IP*\n\`${truncate(ip, 80)}\`` },
        { type: "mrkdwn", text: `*Host*\n\`${truncate(host, 80)}\`` },
    ];

    const blocks = [
        { type: "header", text: { type: "plain_text", text: `${emoji} Trappsec ${severity}` } },
        { type: "section", fields },
        { type: "context", elements: [{ type: "mrkdwn", text: `*User-Agent:* \`${ua}\`` }] },
    ];

    if (eventName === "trappsec.watch_hit" && Array.isArray(event?.found_fields)) {
        const lines = event.found_fields.slice(0, 8).map((f) => {
            const fieldName = truncate(stringify(f?.field), 40);
            const fieldType = truncate(stringify(f?.type), 20);
            const fieldIntent = truncate(stringify(f?.intent), 50);
            return `- \`${fieldType}\` \`${fieldName}\` (${fieldIntent})`;
        });
        if (lines.length > 0) {
            blocks.push({ type: "section", text: { type: "mrkdwn", text: `*Triggered Fields*\n${lines.join("\n")}` } });
        }
    }

    if (intent !== "-" || reason !== "-") {
        blocks.push({
            type: "section",
            fields: [
                { type: "mrkdwn", text: `*Intent*\n${truncate(intent, 120)}` },
                { type: "mrkdwn", text: `*Reason*\n${truncate(reason, 120)}` },
            ],
        });
    }

    return {
        text: `[${severity}] ${eventName} ${method} ${path} (${svc}/${env})`,
        blocks,
    };
}

class SlackHandler {
    constructor(url, { service = null, environment = null, alerts_only = true } = {}) {
        this.webhook = new WebhookHandler(url, {
            service,
            environment,
            alerts_only,
            template: (event) => buildSlackPayload(event, { service, environment }),
        });
    }

    emit(event) {
        this.webhook.emit(event);
    }
}

class OTELHandler {
    constructor() {
        try {
            this.otel = require('@opentelemetry/api');
        } catch (e) {
            throw new Error("opentelemetry-api library required for OTELHandler");
        }
    }

    emit(event) {
        const currentSpan = this.otel.trace.getSpan(this.otel.context.active());

        if (currentSpan && currentSpan.isRecording()) {
            currentSpan.setAttribute("trappsec.detected", true);
            currentSpan.setAttribute("trappsec.event", event.event);
            currentSpan.setAttribute("trappsec.type", event.type);

            if (event.user) currentSpan.setAttribute("trappsec.user", event.user);
            if (event.role) currentSpan.setAttribute("trappsec.role", event.role);
            if (event.ip) currentSpan.setAttribute("trappsec.ip", event.ip);

            if (event.event === "trappsec.watch_hit") {
                for (const field_info of event.found_fields) {
                    currentSpan.addEvent("watch_hit", field_info);
                }
            }

            if (event.event === "trappsec.trap_hit") {
                if (event.intent) currentSpan.setAttribute("trappsec.intent", event.intent);
            }

            if (event.event === "trappsec.rule_hit") {
                if (event.intent) currentSpan.setAttribute("trappsec.intent", event.intent);
                if (event.reason) currentSpan.setAttribute("trappsec.reason", event.reason);
            }

            if (event.metadata && typeof event.metadata === 'object' && !Array.isArray(event.metadata)) {
                for (const [k, v] of Object.entries(event.metadata)) {
                    currentSpan.setAttribute(`metadata.${k}`, v);
                }
            }
        }
    }
}

module.exports = { LogHandler, WebhookHandler, SlackHandler, OTELHandler };
