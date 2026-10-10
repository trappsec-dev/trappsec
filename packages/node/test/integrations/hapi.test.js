'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const Hapi = require('@hapi/hapi');
const { makeSentry } = require('./helpers');

test('hapi: GET+HEAD trap methods do not make start() throw; HEAD is served', async (t) => {
    const server = Hapi.server({ port: 0, host: '127.0.0.1' });
    const { sentry, events } = makeSentry(server);
    sentry.trap('/admin').methods('GET', 'HEAD', 'POST');
    server.route({ method: 'GET', path: '/{p*}', handler: () => 'catchall' });
    await server.start();
    t.after(() => server.stop());
    assert.equal((await server.inject({ url: '/admin' })).statusCode, 401);
    assert.equal((await server.inject({ method: 'HEAD', url: '/admin' })).statusCode, 401);
    assert.equal((await server.inject({ method: 'POST', url: '/admin' })).statusCode, 401);
    assert.equal((await server.inject({ url: '/other' })).payload, 'catchall');
    assert.equal(events.length, 3);
});

test('hapi: inject before start is protected (lazy bootstrap); bootstrap idempotent', async () => {
    const server = Hapi.server();
    const { sentry, events } = makeSentry(server);
    sentry.trap('/secret');
    sentry.watch('/w/{id}').query('dbg').body('adm');
    server.route({ method: ['GET', 'POST'], path: '/w/{id}', handler: (req) => ({ q: req.query, b: req.payload }) });
    sentry.bootstrap(); sentry.bootstrap();
    assert.equal((await server.inject('/secret')).statusCode, 401);
    let r = await server.inject({ url: '/w/9?dbg=1&k=v' });
    assert.deepEqual({ ...r.result.q }, { k: 'v' });
    assert.equal(events[1].found_fields[0].type, 'query');
    r = await server.inject({ method: 'POST', url: '/w/9', payload: { adm: true, n: 1 } });
    assert.deepEqual(r.result.b, { n: 1 });
    assert.equal(events[2].found_fields[0].type, 'body');
});

test('hapi: lazy bootstrap alone (no explicit call) and route-validation cannot hide honey fields', async () => {
    const server = Hapi.server();
    const { sentry, events } = makeSentry(server);
    sentry.trap('/lazy');
    sentry.watch('/v').query('hf');
    server.route({
        method: 'GET', path: '/v',
        options: { validate: { query: (value) => { if ('hf' in value) throw new Error('unknown key'); return value; } } },
        handler: (req) => req.query
    });
    assert.equal((await server.inject('/lazy')).statusCode, 401);
    assert.deepEqual({ ...(await server.inject('/v?hf=1&a=b')).result }, { a: 'b' });
    assert.equal(events.length, 2);
});

test('hapi: raising identify_user is safe; authenticated trap; prototype keys ignored', async () => {
    const server = Hapi.server();
    const { sentry, events } = makeSentry(server);
    let throwing = true;
    sentry.identify_user((req) => { if (throwing) throw new Error('boom'); return { user: 'u', role: 'r' }; });
    sentry.trap('/t').respond({ status: 200, body: { ok: 1 } });
    sentry.watch('/w').query('x');
    server.route({ method: 'GET', path: '/w', handler: (req) => req.query });
    assert.equal((await server.inject('/t')).statusCode, 401);
    assert.deepEqual({ ...(await server.inject('/w?x=1&k=v')).result }, { k: 'v' });
    assert.equal((await server.inject('/w?constructor=1&toString=2')).statusCode, 200);
    const before = events.length;
    throwing = false;
    assert.equal((await server.inject('/t')).statusCode, 200);
    assert.equal(events[before].type, 'alert');
});
