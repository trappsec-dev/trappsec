const crypto = require('crypto');
const http = require('http');
const https = require('https');

const REQUEST_TIMEOUT_MS = 5000;

/** POST `body` and resolve with the status code. Uses node:http(s) rather than
 *  fetch: undici's pooled keep-alive sockets intermittently fail or stall when a
 *  receiver closes connections, which delays or loses alerts. */
function postJSON(url, headers, body) {
    return new Promise((resolve, reject) => {
        let target;
        try { target = new URL(url); } catch (e) { reject(e); return; }
        const mod = target.protocol === 'https:' ? https : http;
        const req = mod.request(target, {
            method: 'POST',
            headers: { ...headers, 'content-length': Buffer.byteLength(body) },
            timeout: REQUEST_TIMEOUT_MS,
        }, (res) => {
            res.resume();
            res.on('end', () => resolve(res.statusCode));
            res.on('error', reject);
        });
        req.on('timeout', () => req.destroy(new Error('request timed out')));
        req.on('error', reject);
        req.end(body);
    });
}

const MAX_IN_FLIGHT = 100;
const MAX_RETRIES = 2;
const WARN_INTERVAL_MS = 60000;

/**
 * JSON.stringify that never throws (bigint, cycles, getters that throw).
 * With sortKeys, plain-object keys are emitted in sorted order at every level.
 */
function safeStringify(value, { sortKeys = false } = {}) {
    try {
        const seen = new WeakSet();
        const out = JSON.stringify(value, (k, v) => {
            if (typeof v === 'bigint') return String(v);
            if (v !== null && typeof v === 'object') {
                if (seen.has(v)) return "[Circular]";
                seen.add(v);
                if (sortKeys && !Array.isArray(v) && typeof v.toJSON !== 'function') {
                    const sorted = {};
                    for (const key of Object.keys(v).sort()) sorted[key] = v[key];
                    return sorted;
                }
            }
            return v;
        });
        return out === undefined ? "null" : out;
    } catch (e) {
        try {
            return JSON.stringify({ error: "unserializable event", detail: String(e) });
        } catch (e2) {
            return "{}";
        }
    }
}

class LogHandler {
    constructor(logger) {
        this.logger = logger;
    }

    emit(event) {
        this.logger.warn(safeStringify(event));
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

        this._inFlight = 0;
        this._pending = new Set();
        this._closed = false;
        this._lastWarn = 0;
        this._timer = null;

        if (heartbeat_interval) {
            this._timer = setInterval(() => this._heartbeat(), heartbeat_interval * 1000);
            if (typeof this._timer.unref === 'function') this._timer.unref();
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
                this.logger.error("Failed to apply webhook template, dropping event:", e);
                return;
            }
            if (event === undefined || event === null) {
                return;
            }
        }

        this._send(safeStringify(event));
    }

    _heartbeat() {
        const payload = safeStringify({
            timestamp: Date.now() / 1000,
            event: "trappsec.heartbeat",
            service: this.service,
            environment: this.environment,
        });
        this._send(payload);
    }

    _warnRateLimited(msg) {
        const now = Date.now();
        if (now - this._lastWarn >= WARN_INTERVAL_MS) {
            this._lastWarn = now;
            this.logger.warn(msg);
        }
    }

    /** Fire-and-forget: never blocks the caller, never throws. */
    _send(payload) {
        if (this._closed) return;
        if (this._inFlight >= MAX_IN_FLIGHT) {
            this._warnRateLimited(`trappsec webhook: ${MAX_IN_FLIGHT} deliveries in flight, dropping event`);
            return;
        }
        this._inFlight++;
        const p = this._deliver(payload)
            .catch(e => {
                this.logger.error(`Failed to send webhook: ${e && e.message ? e.message : e}`);
            })
            .finally(() => {
                this._inFlight--;
                this._pending.delete(p);
            });
        this._pending.add(p);
    }

    _buildHeaders(payload) {
        const headers = { ...this.headers };
        if (this.secret) {
            const ts = String(Math.floor(Date.now() / 1000));
            const sig = crypto.createHmac('sha256', this.secret).update(`${ts}.${payload}`).digest('hex');
            headers["x-trappsec-timestamp"] = ts;
            headers["x-trappsec-signature"] = `sha256=${sig}`;
        }
        return headers;
    }

    async _deliver(payload) {
        let lastErr = null;
        for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
            if (attempt > 0) {
                await new Promise(r => setTimeout(r, 200 * 2 ** (attempt - 1)));
            }
            let retryable = true;
            try {
                const status = await postJSON(this.url, this._buildHeaders(payload), payload);
                if (status >= 200 && status < 300) return;
                this.logger.error(`trappsec webhook: non-2xx response ${status}`);
                lastErr = new Error(`HTTP ${status}`);
                retryable = status >= 500 || status === 429;
            } catch (e) {
                lastErr = e;
            }
            if (!retryable) return;
        }
        if (lastErr) throw lastErr;
    }

    /** Stop the heartbeat and wait (up to `timeout` ms) for in-flight deliveries. */
    async close(timeout = 5000) {
        this._closed = true;
        if (this._timer) {
            clearInterval(this._timer);
            this._timer = null;
        }
        if (this._pending.size === 0) return;
        let t;
        const limit = new Promise(r => { t = setTimeout(r, timeout); });
        await Promise.race([Promise.allSettled([...this._pending]), limit]);
        clearTimeout(t);
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

function esc(value) {
    return String(value).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

// `value` must already be escaped / trusted mrkdwn.
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
    const path = stringify(event?.path || "-");
    const method = stringify(event?.method || "-");
    const intent = event?.intent || null;
    const reason = event?.reason || null;
    const ip = event?.ip || null;
    const user = event?.user || null;
    const role = event?.role || null;
    const ua = event?.user_agent != null ? truncate(stringify(event.user_agent), 120) : null;
    const text = notificationText(
        eventName, level, esc(svc), user ? esc(user) : null, esc(path), esc(method),
        (Array.isArray(event?.found_fields) ? event.found_fields : []).map(f => ({ field: f?.field == null ? null : esc(stringify(f.field)) }))
    );
    const when = slackDateToken(event?.timestamp);
    const foundFields = Array.isArray(event?.found_fields) ? event.found_fields : [];

    const route = (method === "-" && path === "-") ? "-" : `${method || ""} ${path || ""}`.trim();

    const eventLines = compactLines([
        kvLine("Event", EVENT_LABELS[eventName] || eventName),
        kvLine("Timestamp", when),
        kvLine("Service", esc(svc)),
        kvLine("Environment", esc(env)),
        kvLine("Host", host ? esc(host) : null),
    ]);

    const requestLines = compactLines([
        kvLine("IP", ip ? esc(ip) : null),
        kvLine("Route", esc(route)),
        kvLine("User Agent", ua ? esc(ua) : null),
        kvLine("User", user ? esc(user) : null),
        kvLine("Role", role ? esc(role) : null),
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
            return kvLine(`Triggered Field ${idx + 1}`, esc(parts.join(" ")));
        });
        if (lines.length > 0) {
            blocks.push({ type: "divider" });
            blocks.push({ type: "section", text: { type: "mrkdwn", text: lines.join("\n") } });
        }
    }

    const details = compactLines([]);
    if (intent) details.push(kvLine("Intent", esc(truncate(stringify(intent), 120))));
    if (reason) details.push(kvLine("Reason", esc(truncate(stringify(reason), 120))));
    if (details.length > 0) {
        blocks.push({ type: "divider" });
        blocks.push({ type: "section", text: { type: "mrkdwn", text: details.join("\n") } });
    }

    return {
        text,
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

    close(timeout) {
        return this.webhook.close(timeout);
    }
}

function otelValue(v) {
    if (v === null || v === undefined) return undefined;
    const t = typeof v;
    if (t === 'string' || t === 'boolean') return v;
    if (t === 'number') return Number.isFinite(v) ? v : String(v);
    if (Array.isArray(v)) {
        const items = v.filter(x => x !== null && x !== undefined);
        const kinds = new Set(items.map(x => (typeof x === 'number' && !Number.isFinite(x)) ? 'other' : typeof x));
        if (kinds.size === 1 && (kinds.has('string') || kinds.has('number') || kinds.has('boolean'))) return items;
        return items.map(x => (typeof x === 'string' ? x : (typeof x === 'object' ? safeStringify(x) : String(x))));
    }
    if (t === 'object') return safeStringify(v);
    return String(v);
}

function otelAttributes(obj) {
    const out = {};
    for (const [k, v] of Object.entries(obj || {})) {
        const c = otelValue(v);
        if (c !== undefined) out[k] = c;
    }
    return out;
}

class OTELHandler {
    constructor() {
        try {
            this.otel = require('@opentelemetry/api');
        } catch (e) {
            throw new Error("@opentelemetry/api is required for OTELHandler (npm install @opentelemetry/api)");
        }
    }

    emit(event) {
        const currentSpan = this.otel.trace.getSpan(this.otel.context.active());

        if (currentSpan && currentSpan.isRecording()) {
            const set = (k, v) => {
                const c = otelValue(v);
                if (c !== undefined) currentSpan.setAttribute(k, c);
            };
            currentSpan.setAttribute("trappsec.detected", true);
            set("trappsec.event", event.event);
            set("trappsec.type", event.type);

            set("trappsec.user", event.user);
            set("trappsec.role", event.role);
            set("trappsec.ip", event.ip);

            if (event.event === "trappsec.watch_hit" && Array.isArray(event.found_fields)) {
                for (const field_info of event.found_fields) {
                    currentSpan.addEvent("watch_hit", otelAttributes(field_info));
                }
            }

            if (event.event === "trappsec.trap_hit") {
                set("trappsec.intent", event.intent);
            }

            if (event.event === "trappsec.rule_hit") {
                set("trappsec.intent", event.intent);
                set("trappsec.reason", event.reason);
            }

            if (event.metadata && typeof event.metadata === 'object' && !Array.isArray(event.metadata)) {
                for (const [k, v] of Object.entries(event.metadata)) {
                    set(`metadata.${k}`, v);
                }
            }
        }
    }
}

module.exports = { LogHandler, WebhookHandler, SlackHandler, OTELHandler, safeStringify, otelValue, esc };
