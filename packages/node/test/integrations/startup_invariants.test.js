'use strict';

// R10 and R13 for every Node integration. Watches are declared before traps (the
// order an app may well use) and both must work. After the first request the
// trap and watch lists are made to throw: lookups must go through the indexes
// built at startup, never scan the configuration per request. trappsec catches
// its own errors, so a scan shows up as a logged error and missing events.

require('reflect-metadata');
const test = require('node:test');
const assert = require('node:assert/strict');
const Hapi = require('@hapi/hapi');
const Koa = require('koa');
const Router = require('@koa/router');
const Fastify = require('fastify');
const { NestFactory } = require('@nestjs/core');
const common = require('@nestjs/common');
const { ExpressAdapter } = require('@nestjs/platform-express');
const { FastifyAdapter } = require('@nestjs/platform-fastify');
const { makeSentry, request } = require('./helpers');

function configure(sentry, watchPath) {
    sentry.watch(watchPath).query('debug');
    sentry.trap('/admin/backup').methods('POST');
}

function lock(sentry) {
    for (const key of ['traps', 'watches']) {
        Object.defineProperty(sentry, key, { get() { throw new Error(`per-request scan of ${key}`); } });
    }
}

async function exercise(sentry, events, send) {
    assert.equal(await send('GET', '/users/1'), 200); // boots the app; indexes are built by now
    lock(sentry);
    assert.equal(await send('POST', '/admin/backup'), 401);
    assert.equal(await send('GET', '/users/7?debug=1'), 200);
    assert.equal(await send('GET', '/users/8'), 200);
    assert.deepEqual(sentry.logger.logs.error, []);
    assert.deepEqual(events.map((e) => e.event), ['trappsec.trap_hit', 'trappsec.watch_hit']);
}

function viaServer(server) {
    return async (method, path) => (await request(server, { method, path })).status;
}

for (const [label, pkg] of [['express4', 'express4'], ['express5', 'express']]) {
    test(`${label}: watches before traps; no per-request scans (R10, R13)`, async (t) => {
        const app = require(pkg)();
        const { sentry, events } = makeSentry(app);
        configure(sentry, '/users/:id');
        app.get('/users/:id', (req, res) => res.send('ok'));
        const server = await new Promise((r) => { const s = app.listen(0, '127.0.0.1', () => r(s)); });
        t.after(() => server.close());
        await exercise(sentry, events, viaServer(server));
    });
}

test('fastify: watches before traps; no per-request scans (R10, R13)', async (t) => {
    const app = Fastify();
    const { sentry, events } = makeSentry(app);
    configure(sentry, '/users/:id');
    app.get('/users/:id', async () => 'ok');
    t.after(() => app.close());
    await exercise(sentry, events, async (method, url) => (await app.inject({ method, url })).statusCode);
});

test('hapi: watches before traps; no per-request scans (R10, R13)', async () => {
    const server = Hapi.server();
    const { sentry, events } = makeSentry(server);
    configure(sentry, '/users/{id}');
    server.route({ method: 'GET', path: '/users/{id}', handler: () => 'ok' });
    await exercise(sentry, events, async (method, url) => (await server.inject({ method, url })).statusCode);
});

test('koa: watches before traps; no per-request scans (R10, R13)', async (t) => {
    const app = new Koa();
    const { sentry, events } = makeSentry(app);
    configure(sentry, '/users/:id');
    const router = new Router();
    router.get('/users/:id', (ctx) => { ctx.body = 'ok'; });
    app.use(router.routes());
    const server = await new Promise((r) => { const s = app.listen(0, '127.0.0.1', () => r(s)); });
    t.after(() => server.close());
    await exercise(sentry, events, viaServer(server));
});

for (const [label, makeAdapter] of [['nest-express', () => new ExpressAdapter()], ['nest-fastify', () => new FastifyAdapter()]]) {
    test(`${label}: watches before traps; no per-request scans (R10, R13)`, async (t) => {
        class UsersController { get() { return 'ok'; } }
        common.Controller('users')(UsersController);
        const P = UsersController.prototype;
        common.Get(':id')(P, 'get', Object.getOwnPropertyDescriptor(P, 'get'));
        class M {}
        common.Module({ controllers: [UsersController] })(M);
        const app = await NestFactory.create(M, makeAdapter(), { logger: false });
        const { sentry, events } = makeSentry(app);
        configure(sentry, '/users/:id');
        await app.listen(0, '127.0.0.1');
        t.after(() => app.close());
        await exercise(sentry, events, viaServer(app.getHttpServer()));
    });
}
