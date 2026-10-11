'use strict';

const http = require('http');
const { Sentry } = require('../../src');

// Silent logger that remembers what was logged.
function quietLogger() {
    const logs = { error: [], warn: [], info: [] };
    return {
        logs,
        error: (...a) => logs.error.push(a.map(String).join(' ')),
        warn: (...a) => logs.warn.push(a.map(String).join(' ')),
        info: (...a) => logs.info.push(a.map(String).join(' ')),
        log: () => {},
        debug: () => {},
    };
}

// Creates a Sentry for `app` whose only handler records events.
function makeSentry(app) {
    const sentry = new Sentry(app, 'svc', 'test');
    const events = [];
    sentry._handlers = [{ emit: (ctx) => events.push(JSON.parse(JSON.stringify(ctx))) }];
    sentry.logger = quietLogger();
    return { sentry, events };
}

function request(server, { method = 'GET', path = '/', headers = {}, body } = {}) {
    return new Promise((resolve, reject) => {
        const { port } = server.address();
        const payload = body === undefined ? undefined : (typeof body === 'string' ? body : JSON.stringify(body));
        const h = Object.assign({}, headers);
        if (payload !== undefined) {
            if (!h['content-type']) h['content-type'] = 'application/json';
            h['content-length'] = Buffer.byteLength(payload);
        }
        const req = http.request({ host: '127.0.0.1', port, method, path, headers: h }, (res) => {
            const chunks = [];
            res.on('data', (c) => chunks.push(c));
            res.on('end', () => {
                const text = Buffer.concat(chunks).toString('utf8');
                let json;
                try { json = JSON.parse(text); } catch (e) { /* not json */ }
                resolve({ status: res.statusCode, headers: res.headers, text, json });
            });
        });
        req.on('error', reject);
        if (payload !== undefined) req.write(payload);
        req.end();
    });
}

// Starts a plain http server around a request listener; returns {server, close}.
function serve(listener) {
    return new Promise((resolve) => {
        const server = http.createServer(listener);
        server.listen(0, '127.0.0.1', () => resolve({
            server,
            close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(r); }),
        }));
    });
}

// Builds a multipart/form-data body of text fields: {body, headers} for request().
function multipart(fields) {
    const boundary = '----trappsec' + Math.random().toString(16).slice(2);
    let body = '';
    for (const [k, v] of Object.entries(fields)) {
        body += `--${boundary}\r\nContent-Disposition: form-data; name="${k}"\r\n\r\n${v}\r\n`;
    }
    body += `--${boundary}--\r\n`;
    return { body, headers: { 'content-type': `multipart/form-data; boundary=${boundary}` } };
}

module.exports = { makeSentry, request, serve, quietLogger, multipart };
