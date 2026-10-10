'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const Fastify = require('fastify');
const { makeSentry, request } = require('./helpers');

test('fastify: ready() then listen() does not throw; traps and watches work over HTTP', async (t) => {
    const app = Fastify();
    const { sentry, events } = makeSentry(app);
    sentry.watch('/items/:id').query('debug').body('is_admin');
    sentry.trap('/admin/export').methods('GET', 'POST', 'HEAD', 'OPTIONS');
    app.get('/items/:id', async (req) => ({ q: req.query }));
    app.post('/items/:id', async (req) => ({ b: req.body }));
    await app.ready();
    await app.listen({ port: 0, host: '127.0.0.1' });
    t.after(() => app.close());
    const server = app.server;

    let r = await request(server, { path: '/items/1?debug=1&k=v' });
    assert.deepEqual(r.json.q, { k: 'v' });
    assert.equal(events[0].found_fields[0].type, 'query');
    r = await request(server, { method: 'POST', path: '/items/1', body: { is_admin: true, n: 1 } });
    assert.deepEqual(r.json.b, { n: 1 });
    assert.equal(events[1].found_fields[0].type, 'body');
    for (const method of ['GET', 'POST', 'HEAD', 'OPTIONS']) {
        assert.equal((await request(server, { method, path: '/admin/export' })).status, 401, method);
    }
});

test('fastify: inject() without listen is protected; bootstrap() idempotent', async () => {
    const app = Fastify();
    const { sentry, events } = makeSentry(app);
    sentry.trap('/secret');
    app.get('/real', async () => 'ok');
    sentry.bootstrap(); sentry.bootstrap();
    const r = await app.inject({ method: 'GET', url: '/secret' });
    assert.equal(r.statusCode, 401);
    assert.equal(events.length, 1);
    assert.equal((await app.inject({ url: '/real' })).payload, 'ok');
    await app.close();
});

test('fastify: schema validation cannot hide honey fields (additionalProperties:false)', async () => {
    const app = Fastify();
    const { sentry, events } = makeSentry(app);
    sentry.watch('/s').body('is_admin');
    app.post('/s', { schema: { body: { type: 'object', additionalProperties: false, properties: { name: { type: 'string' } } } } },
        async (req) => ({ b: req.body }));
    const r = await app.inject({ method: 'POST', url: '/s', payload: { name: 'a', is_admin: true } });
    assert.equal(r.statusCode, 200);
    assert.deepEqual(r.json().b, { name: 'a' });
    assert.equal(events.length, 1);
    await app.close();
});

test('fastify: query mutated in place; prototype keys ignored; raising identify_user is safe', async () => {
    const app = Fastify();
    const { sentry, events } = makeSentry(app);
    sentry.identify_user(() => { throw new Error('boom'); });
    sentry.watch('/q').query('x');
    sentry.trap('/t');
    app.get('/q', async (req) => req.query);
    let r = await app.inject({ url: '/q?constructor=1&toString=2&k=v' });
    assert.deepEqual(r.json(), { constructor: '1', toString: '2', k: 'v' });
    assert.equal(events.length, 0);
    r = await app.inject({ url: '/q?x=1&x=2&k=v' });
    assert.deepEqual(r.json(), { k: 'v' });
    assert.equal(events.length, 1);
    r = await app.inject({ url: '/t' });
    assert.equal(r.statusCode, 401);
    assert.equal(r.headers['content-type'].startsWith('application/json'), true);
    await app.close();
});

test('fastify: trap failure falls back to normal decoy; authenticated trap response', async () => {
    const app = Fastify();
    app.decorateRequest('user', null);
    app.addHook('onRequest', async (req) => { if (req.headers['x-user']) req.user = req.headers['x-user']; });
    const { sentry, events } = makeSentry(app);
    sentry.identify_user((req) => (req.user ? { user: req.user, role: 'r' } : null));
    sentry.trap('/t').if_unauthenticated({ status: 404, body: { e: 1 } }).respond({ status: 200, body: { ok: 1 } });
    assert.equal((await app.inject({ url: '/t' })).statusCode, 404);
    const r = await app.inject({ url: '/t', headers: { 'x-user': 'zed' } });
    assert.equal(r.statusCode, 200);
    assert.equal(events[1].user, 'zed');
    sentry._trigger_trap_event = () => { throw new Error('x'); };
    const f = await app.inject({ url: '/t' });
    assert.equal(f.statusCode, 404);
    assert.deepEqual(f.json(), { e: 1 });
    await app.close();
});

test('fastify: plugin-registered (prefixed) routes are watched by full route path', async () => {
    const app = Fastify();
    const { sentry, events } = makeSentry(app);
    sentry.watch('/api/v1/x').query('dbg');
    app.register(async (inst) => { inst.get('/x', async (req) => req.query); }, { prefix: '/api/v1' });
    const r = await app.inject({ url: '/api/v1/x?dbg=1&a=b' });
    assert.deepEqual(r.json(), { a: 'b' });
    assert.equal(events.length, 1);
    await app.close();
});

test('fastify: a trap duplicating a real route fails loud (R20)', async () => {
    const app = Fastify();
    makeSentry(app).sentry.trap('/real').methods('GET');
    app.get('/real', async () => 'real');
    await assert.rejects(app.ready(), /already declared/);
});
