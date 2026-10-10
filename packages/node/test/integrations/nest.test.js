'use strict';

require('reflect-metadata');
const test = require('node:test');
const assert = require('node:assert/strict');
const { NestFactory } = require('@nestjs/core');
const common = require('@nestjs/common');
const { ExpressAdapter } = require('@nestjs/platform-express');
const { FastifyAdapter } = require('@nestjs/platform-fastify');
const { makeSentry, request } = require('./helpers');

// Builds controllers/modules without decorator syntax.
function buildModule() {
    class ItemsController {
        get(query, id) { return { q: { ...query }, id }; }
        post(body) { return { b: { ...body } }; }
        any(id) { return { any: id }; }
        boom() { throw new Error('app error'); }
    }
    common.Controller('items')(ItemsController);
    const P = ItemsController.prototype;
    const method = (name, deco, ...params) => {
        const d = Object.getOwnPropertyDescriptor(P, name);
        deco(P, name, d);
        params.forEach((p, i) => p(P, name, i));
    };
    method('get', common.Get(':id'), common.Query(), common.Param('id'));
    method('post', common.Post(':id'), common.Body());
    method('any', common.Get('/other/:id'), common.Param('id'));
    method('boom', common.Get('/boom/x'), );
    class AppModule {}
    common.Module({ controllers: [ItemsController] })(AppModule);
    return AppModule;
}

async function create(adapter) {
    const app = await NestFactory.create(buildModule(), adapter, { logger: false });
    return app;
}

test('nest-express: listen with watches; error middleware keeps arity; traps see middleware-set user', async (t) => {
    const app = await create(new ExpressAdapter());
    app.use((req, res, next) => { if (req.headers['x-user']) req.user = req.headers['x-user']; next(); });
    app.use((err, req, res, next) => res.status(500).json({ handled: err.message })); // 4-arg error middleware
    const { sentry, events } = makeSentry(app);
    sentry.identify_user((req) => (req.user ? { user: req.user, role: 'r' } : null));
    sentry.watch('/items/:id').query('debug').body('is_admin');
    sentry.trap('/items/secret').methods('GET', 'POST');
    await app.listen(0);
    t.after(() => app.close());
    const server = app.getHttpServer();

    let r = await request(server, { path: '/items/5?debug=1&k=v' });
    assert.equal(r.status, 200);
    assert.deepEqual(r.json.q, { k: 'v' });
    assert.equal(events[0].found_fields[0].type, 'query');
    r = await request(server, { method: 'POST', path: '/items/5', body: { is_admin: true, n: 1 } });
    assert.deepEqual(r.json.b, { n: 1 });
    // trap path would be shadowed by GET /items/:id if appended; it must win, and see the user
    r = await request(server, { path: '/items/secret', headers: { 'x-user': 'kim' } });
    assert.equal(r.status, 200); // default authenticated trap response
    assert.deepEqual(r.json, {});
    assert.equal((await request(server, { path: '/items/secret' })).status, 401);
    const hit = events.filter((e) => e.event === 'trappsec.trap_hit')[0];
    assert.equal(hit.user, 'kim');
    assert.equal(hit.type, 'alert');
    r = await request(server, { path: '/items/boom/x' });
    assert.ok(r.status === 404 || r.status === 500);
});

test('nest-express: init() + custom server without listen (lazy bootstrap); raising identify_user', async (t) => {
    const app = await create(new ExpressAdapter());
    const { sentry, events } = makeSentry(app);
    sentry.identify_user(() => { throw new Error('boom'); });
    sentry.trap('/items/secret');
    sentry.watch('/items/:id').query('debug');
    await app.init();
    const http = require('http');
    const server = http.createServer(app.getHttpAdapter().getInstance());
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    t.after(() => { server.close(); return app.close(); });
    assert.equal((await request(server, { path: '/items/secret' })).status, 401);
    const r = await request(server, { path: '/items/1?debug=1&k=v' });
    assert.equal(r.status, 200);
    assert.deepEqual(r.json.q, { k: 'v' });
    assert.ok(events.length >= 2);
    sentry.bootstrap(); sentry.bootstrap();
});

test('nest-express: duplicate trap of a real route fails loud', async () => {
    const app = await create(new ExpressAdapter());
    const { sentry } = makeSentry(app);
    sentry.trap('/items/other/:id').methods('GET');
    await app.init();
    assert.throws(() => sentry.bootstrap(), /duplicates an existing application route/);
    await app.close();
});

test('nest-fastify: init + ready then listen; traps and watches', async (t) => {
    const app = await create(new FastifyAdapter());
    const { sentry, events } = makeSentry(app);
    sentry.watch('/items/:id').query('debug').body('is_admin');
    sentry.trap('/items/secret').methods('GET', 'HEAD');
    await app.init();
    await app.getHttpAdapter().getInstance().ready();
    await app.listen(0, '127.0.0.1');
    t.after(() => app.close());
    const server = app.getHttpServer();

    let r = await request(server, { path: '/items/5?debug=1&k=v' });
    assert.equal(r.status, 200);
    assert.deepEqual(r.json.q, { k: 'v' });
    assert.equal(events[0].found_fields[0].type, 'query');
    r = await request(server, { method: 'POST', path: '/items/5', body: { is_admin: true, n: 1 } });
    assert.deepEqual(r.json.b, { n: 1 });
    assert.equal((await request(server, { path: '/items/secret' })).status, 401);
    assert.equal((await request(server, { method: 'HEAD', path: '/items/secret' })).status, 401);
});

test('nest-fastify: inject without listen', async () => {
    const app = await create(new FastifyAdapter());
    const { sentry, events } = makeSentry(app);
    sentry.trap('/items/secret');
    await app.init();
    await app.getHttpAdapter().getInstance().ready();
    const r = await app.getHttpAdapter().getInstance().inject({ url: '/items/secret' });
    assert.equal(r.statusCode, 401);
    assert.equal(events.length, 1);
    await app.close();
});
