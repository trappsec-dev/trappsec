'use strict';

const { responseHead } = require('../builders');

// Helpers shared by every trappsec Node integration.

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

// Memoised raw route pattern -> watch lookup (null when unwatched). Route patterns
// are a small fixed set, so the normalisation runs once per route, not per request.
function createWatchLookup(ts) {
    const map = buildWatchMap(ts);
    const memo = new Map();
    return (raw) => {
        if (typeof raw !== 'string') return null;
        let watch = memo.get(raw);
        if (watch === undefined) {
            const key = normalizePath(raw);
            watch = (key && map[key]) || null;
            memo.set(raw, watch);
        }
        return watch;
    };
}

// Upper-cased, de-duplicated HTTP methods of a trap.
function trapMethods(decoy) {
    return [...new Set(decoy.methods.map((m) => String(m).toUpperCase()))];
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

// Query half of a watch inspection. `apply(data, keys)` writes the stripped query
// back in the framework's own way when a honey field was found. Returns the findings.
function inspectQuery(ts, req, query, watch, apply) {
    if (!hasFields(watch.query_fields) || !isObject(query)) return [];
    const { found, data, touched } = detect(ts, query, watch.query_fields, req, 'query');
    if (touched) apply(data, Object.keys(watch.query_fields));
    return found;
}

// Body half: detects in `body` and strips honey fields in place.
function inspectBody(ts, req, body, watch) {
    if (!isObject(body)) return [];
    const { found, data, touched } = detect(ts, body, watch.body_fields, req, 'body');
    if (touched) replaceInPlace(body, data);
    return found;
}

// Completes a deferred body inspection (see bodyLooksUnparsed). `body` is the
// framework's current body; `warning` (optional) is logged once when a body
// method has none.
function finishPending(ts, warned, req, pending, { label, body, method, responseEnded, warning }) {
    try {
        const found = pending.found;
        if (body !== undefined) {
            found.push(...inspectBody(ts, req, body, pending.watch));
        } else if (warning && !responseEnded && BODY_METHODS.has(String(method).toUpperCase())) {
            warnOnce(ts, warned, 'body:' + pending.watch.path, warning);
        }
        emitWatch(ts, req, found, label);
    } catch (e) {
        ts.logger.error(`Trappsec error in ${label} watch handler: `, e);
    }
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
// trappsec is indistinguishable from a regular trap hit. A function body is
// replaced by the default unauthenticated response (never `{}`).
function decoyFallback(ts, decoy, req) {
    const candidates = [
        decoy && decoy['response.unauthenticated'],
        (decoy && decoy['fallback.unauthenticated']) || ts.default_responses.unauthenticated,
    ];
    for (const cfg of candidates) {
        try {
            if (!cfg || typeof cfg.response_body === 'function') continue;
            return {
                response_body: serializeBody(cfg.response_body, cfg.mime_type),
                response_config: responseHead(cfg, cfg.headers),
            };
        } catch (e) { /* try the next one */ }
    }
    return { response_body: '', response_config: { status_code: 401, mime_type: 'application/json', headers: {} } };
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

// Sets the trap's configured headers through `set(name, value)`. Never throws.
function applyHeaders(ts, headers, set, label) {
    for (const [name, value] of Object.entries(headers || {})) {
        try {
            set(name, value);
        } catch (e) {
            ts.logger.error(`Trappsec error setting ${label} trap response header ${name}: `, e);
        }
    }
}

/**
 * True when the request has a body that no parser has produced yet. App-level
 * parsers leave a placeholder for content types they skip (body-parser 1.x sets
 * req.body = {}; koa-bodyparser ctx.request.body = {}), and a route-level parser
 * (multer, a route-level json()) fills it in later. `parsed` is the parser's own
 * "I parsed this" mark (req._body for body-parser, ctx.request.rawBody for Koa).
 */
function bodyLooksUnparsed(body, headers, parsed) {
    if (body === undefined || body === null) return true;
    if (parsed) return false;
    if (!isObject(body) || Array.isArray(body) || Object.keys(body).length > 0) return false;
    const h = headers || {};
    return Number(h['content-length']) > 0 || h['transfer-encoding'] !== undefined;
}

/**
 * Removes the watched query keys from a raw URL ("/path?a=1&b=2"), including
 * qs-style forms ("role[]=x", "role[a]=x") that a framework parses into the
 * same key. The parsed query object is not enough: a handler or a proxy that
 * reads the raw URL would still see the honey field (R6). Returns the URL
 * unchanged when nothing matches.
 */
function stripRawQuery(url, keys) {
    if (typeof url !== 'string') return url;
    const q = url.indexOf('?');
    if (q === -1) return url;
    const hash = url.indexOf('#', q);
    const query = url.slice(q + 1, hash === -1 ? undefined : hash);
    const names = [...keys];
    const parts = query.split('&');
    const kept = parts.filter((part) => {
        let key = part.split('=')[0];
        try { key = decodeURIComponent(key.replace(/\+/g, ' ')); } catch (e) { /* keep raw key */ }
        return !names.some((n) => key === n || key.startsWith(n + '['));
    });
    if (kept.length === parts.length) return url;
    const rest = hash === -1 ? '' : url.slice(hash);
    return url.slice(0, q) + (kept.length ? '?' + kept.join('&') : '') + rest;
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
    bodyLooksUnparsed,
    stripRawQuery,
    normalizePath,
    isObject,
    buildWatchMap,
    createWatchLookup,
    trapMethods,
    inspectQuery,
    inspectBody,
    finishPending,
    hasFields,
    replaceInPlace,
    detect,
    serializeBody,
    decoyFallback,
    resolveTrap,
    applyHeaders,
    emitWatch,
    warnOnce,
    BODY_METHODS
};
