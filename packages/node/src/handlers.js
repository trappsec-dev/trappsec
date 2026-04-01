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

const EVENT_LABELS = {
    "trappsec.watch_hit": "Honey Field Accessed",
    "trappsec.trap_hit": "Decoy Route Triggered",
    "trappsec.rule_hit": "Security Rule Triggered",
};

function slackDateToken(timestamp) {
    const seconds = Math.floor(Number(timestamp));
    if (!Number.isFinite(seconds) || seconds <= 0) return "-";
    const fallback = new Date(seconds * 1000).toISOString().replace("T", " ").replace(".000Z", " UTC");
    return `<!date^${seconds}^{date_short_pretty} at {time_secs}|${fallback}>`;
}

function notificationText(eventName, severity, svc, user, path, method, foundFields) {
    const actor = user || "An unauthenticated request";
    if (eventName === "trappsec.watch_hit") {
        const names = (foundFields || []).slice(0, 3).map(f => f?.field).filter(Boolean).join(", ");
        const suffix = names ? ` (${names})` : "";
        return `[${severity}] ${actor} accessed a monitored field${suffix} on ${svc}`;
    }
    if (eventName === "trappsec.trap_hit") return `[${severity}] Honeypot endpoint hit on ${svc} - ${method} ${path}`;
    if (eventName === "trappsec.rule_hit") return `[${severity}] Security rule triggered on ${svc} - ${method} ${path}`;
    return `[${severity}] ${eventName} on ${svc}`;
}

function kvLine(key, value) {
    if (value === null || value === undefined || value === "") return null;
    return `*${key}:* ${value}`;
}

function compactLines(lines) {
    return lines.filter(Boolean);
}

function buildSlackPayload(event, { service = null, environment = null } = {}) {
    const app = event?.app || {};
    const eventName = event?.event || "trappsec.event";
    const eventType = event?.type || "signal";
    const level = eventType === "alert" ? "alert" : "signal";
    const color = level === "alert" ? "#CC0000" : "#0066CC";

    const svc = app.service || service || "unknown-service";
    const env = app.environment || environment || "unknown-env";
    const host = app.hostname || null;
    const path = event?.path || "-";
    const method = event?.method || "-";
    const intent = event?.intent || null;
    const reason = event?.reason || null;
    const ip = event?.ip || null;
    const user = event?.user || null;
    const role = event?.role || null;
    const ua = event?.user_agent != null ? truncate(stringify(event.user_agent), 120) : null;
    const when = slackDateToken(event?.timestamp);
    const foundFields = Array.isArray(event?.found_fields) ? event.found_fields : [];

    const route = (method === "-" && path === "-") ? "-" : `${method || ""} ${path || ""}`.trim();

    const eventLines = compactLines([
        kvLine("Event", EVENT_LABELS[eventName] || eventName),
        kvLine("Timestamp", when),
        kvLine("Service", svc),
        kvLine("Environment", env),
        kvLine("Host", host),
    ]);

    const requestLines = compactLines([
        kvLine("IP", ip),
        kvLine("Route", route),
        kvLine("User Agent", ua),
        kvLine("User", user),
        kvLine("Role", role),
    ]);

    const blocks = [
        { type: "section", text: { type: "mrkdwn", text: eventLines.join("\n") } },
        ...(requestLines.length > 0
            ? [{ type: "divider" }, { type: "section", text: { type: "mrkdwn", text: requestLines.join("\n") } }]
            : []),
    ];

    if (eventName === "trappsec.watch_hit" && foundFields.length > 0) {
        const lines = foundFields.slice(0, 8).map((f, idx) => {
            const name = stringify(f?.field);
            const ftype = stringify(f?.type);
            const fintent = stringify(f?.intent);
            const parts = [name];
            if (ftype !== "-") parts.push(`[${ftype}]`);
            if (fintent !== "-") parts.push(`- ${fintent}`);
            return kvLine(`Triggered Field ${idx + 1}`, parts.join(" "));
        });
        if (lines.length > 0) {
            blocks.push({ type: "divider" });
            blocks.push({ type: "section", text: { type: "mrkdwn", text: lines.join("\n") } });
        }
    }

    const details = compactLines([]);
    if (intent) details.push(kvLine("Intent", truncate(intent, 120)));
    if (reason) details.push(kvLine("Reason", truncate(reason, 120)));
    if (details.length > 0) {
        blocks.push({ type: "divider" });
        blocks.push({ type: "section", text: { type: "mrkdwn", text: details.join("\n") } });
    }

    return {
        text: "",
        attachments: [{ color, blocks }],
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
