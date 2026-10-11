'use strict';

// R22 with real CSRF libraries. Each is installed globally, as an app would,
// and rejects a token-less POST. Without the is_trap skip the trap is blocked
// too (and alerts nothing); with it the trap answers its decoy and alerts.

const test = require('node:test');
const assert = require('node:assert/strict');
const Fastify = require('fastify');
const cookieParser = require('cookie-parser');
const { doubleCsrf } = require('csrf-csrf');
const { makeSentry, request } = require('./helpers');

for (const [label, pkg] of [['express4', 'express4'], ['express5', 'express']]) {
    for (const skip of [false, true]) {
        test(`${label}: csrf-csrf ${skip ? 'skips traps via is_trap' : 'blocks traps without the skip'} (R22)`, async (t) => {
            const express = require(pkg);
            const app = express();
            const { sentry, events } = makeSentry(app);
            const { doubleCsrfProtection } = doubleCsrf({
                getSecret: () => 'test-secret',
                getSessionIdentifier: () => 'session',
                cookieOptions: { secure: false },
            });
            app.use(cookieParser());
            app.use((req, res, next) => (skip && sentry.is_trap(req) ? next() : doubleCsrfProtection(req, res, next)));
            sentry.trap('/admin/backup').methods('POST');
            app.post('/real', (req, res) => res.send('ok'));
            const server = await new Promise((r) => { const s = app.listen(0, '127.0.0.1', () => r(s)); });
            t.after(() => server.close());
            assert.equal((await request(server, { method: 'POST', path: '/real' })).status, 403);
            assert.equal((await request(server, { method: 'POST', path: '/admin/backup' })).status, skip ? 401 : 403);
            assert.equal(events.length, skip ? 1 : 0);
        });
    }
}

for (const skip of [false, true]) {
    test(`fastify: @fastify/csrf-protection ${skip ? 'skips traps via is_trap' : 'blocks traps without the skip'} (R22)`, async () => {
        const app = Fastify();
        const { sentry, events } = makeSentry(app);
        await app.register(require('@fastify/cookie'));
        await app.register(require('@fastify/csrf-protection'));
        app.addHook('onRequest', (req, reply, done) => (skip && sentry.is_trap(req) ? done() : app.csrfProtection(req, reply, done)));
        sentry.trap('/admin/backup').methods('POST');
        app.post('/real', async () => 'ok');
        assert.equal((await app.inject({ method: 'POST', url: '/real' })).statusCode, 403);
        assert.equal((await app.inject({ method: 'POST', url: '/admin/backup' })).statusCode, skip ? 401 : 403);
        assert.equal(events.length, skip ? 1 : 0);
        await app.close();
    });
}
