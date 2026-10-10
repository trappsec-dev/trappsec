'use strict';

// Helpers shared by every trappsec Node integration.

const hasOwn = (obj, key) => Object.prototype.hasOwnProperty.call(obj, key);

// Canonical form used for every watch/trap lookup key, in every integration:
// query string and fragment removed, leading slash ensured, trailing slash
// removed (except for the root path). Non-string input (RegExp, array) -> null.
function normalizePath(path) {
    if (!path || typeof path !== 'string') {
        return null;
    }
    let normalized = path.split('?')[0].split('#')[0].trim();
    if (!normalized) {
        return null;
    }
    if (!normalized.startsWith('/')) {
        normalized = '/' + normalized;
    }
    if (normalized.length > 1 && normalized.endsWith('/')) {
        normalized = normalized.slice(0, -1);
    }
    return normalized;
}

function isObject(value) {
    return value !== null && typeof value === 'object';
}

// Builds an O(1) lookup (null-prototype, so "constructor" / "__proto__" paths
// can never hit Object.prototype members) keyed by normalized path. Watches
// declared twice for the same path are merged.
function buildWatchMap(ts) {
    const map = Object.create(null);
    for (const watch of ts.watches) {
        const key = normalizePath(watch.path);
        if (!key) continue;
        const existing = map[key];
        if (existing) {
            map[key] = {
                path: existing.path,
                query_fields: Object.assign({}, existing.query_fields, watch.query_fields),
                body_fields: Object.assign({}, existing.body_fields, watch.body_fields)
            };
        } else {
            map[key] = watch;
        }
    }
    return map;
}

function hasFields(rules) {
    return !!rules && Object.keys(rules).length > 0;
}

// Replace the contents of `target` with `data` without changing its identity.
function replaceInPlace(target, data) {
    if (target === data || !isObject(target) || !isObject(data)) {
        return;
    }
    if (Array.isArray(target)) {
        target.length = 0;
        if (Array.isArray(data)) target.push(...data);
        return;
    }
    for (const key of Object.keys(target)) {
        delete target[key];
    }
    Object.assign(target, data);
}

// Runs core detection against one request container. The reported `type` is
// always forced to `source` ("query" | "body").
function detect(ts, target, rules, req, source) {
    if (!isObject(target) || !hasFields(rules)) {
        return { found: [], data: target, touched: false };
    }
    const result = ts._detect_honey_fields(target, rules, req, source);
    const found = (result.found_fields || []).map((f) => Object.assign({}, f, { type: source }));
    return { found, data: result.data, touched: !!result.touched };
}

function serializeBody(body, mimeType) {
    if (body === undefined || body === null) return '';
    if (typeof body === 'string' || Buffer.isBuffer(body)) return body;
    if (typeof mimeType === 'string' && mimeType.includes('json')) {
        try {
            return JSON.stringify(body);
        } catch (e) {
            return '{}';
        }
    }
    return typeof body === 'object' ? JSON.stringify(body) : String(body);
}

// The response a trap gives when its own machinery fails. It is the same
// unauthenticated decoy a scanner would normally get, so a failure inside
// trappsec is indistinguishable from a regular trap hit.
function decoyFallback(ts, decoy, req) {
    const cfg = (decoy && decoy['response.unauthenticated']) || ts.default_responses.unauthenticated;
    let body = cfg.response_body;
    if (typeof body === 'function') {
        try {
            body = body(req);
        } catch (e) {
            body = {};
        }
    }
    return {
        response_body: serializeBody(body, cfg.mime_type),
        response_config: cfg
    };
}

// Fires the trap event and returns the response to send. Never throws.
function resolveTrap(ts, decoy, req, label) {
    try {
        const out = ts._trigger_trap_event(req, decoy);
        return {
            response_body: serializeBody(out.response_body, out.response_config.mime_type),
            response_config: out.response_config
        };
    } catch (e) {
        ts.logger.error('Trappsec error in ' + label + ' trap handler: ', e);
        return decoyFallback(ts, decoy, req);
    }
}

function emitWatch(ts, req, found, label) {
    if (found.length === 0) return;
    try {
        ts._trigger_watch_event(req, found);
    } catch (e) {
        ts.logger.error('Trappsec error emitting ' + label + ' watch event: ', e);
    }
}

function warnOnce(ts, seen, key, message) {
    if (seen.has(key)) return;
    seen.add(key);
    try {
        ts.logger.warn(message);
    } catch (e) { /* logger failure must never matter */ }
}

const BODY_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

module.exports = {
    hasOwn,
    normalizePath,
    isObject,
    buildWatchMap,
    hasFields,
    replaceInPlace,
    detect,
    serializeBody,
    decoyFallback,
    resolveTrap,
    emitWatch,
    warnOnce,
    BODY_METHODS
};
