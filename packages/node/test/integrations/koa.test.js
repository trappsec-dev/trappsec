'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const Koa = require('koa');
const Router = require('@koa/router');
const bodyParser = require('koa-bodyparser');
const { makeSentry, request, serve } = require('./helpers');

test('koa: prefixed router, strip happens before the handler, type=query', async (t) => {
    const app = new Koa();
    app.use(bodyParser());
    const { sentry, events } = makeSentry(app);
    sentry.watch('/v1/users/:id').query('debug', { intent: 'd' }).body('is_admin', { intent: 'p' });
    const router = new Router({ prefix: '/v1' });
    router.get('/users/:id', (ctx) => { ctx.body = { q: ctx.query, id: ctx.params.id }; });
    router.post('/users/:id', (ctx) => { ctx.body = { b: ctx.request.body }; });
    app.use(router.routes());
    const { server, close } = await serve(app.callback());
    t.after(close);

    let r = await request(server, { path: '/v1/users/3?debug=1&keep=x' });
    assert.deepEqual(r.json, { q: { keep: 'x' }, id: '3' });
    assert.equal(events[0].found_fields[0].type, 'query');
    r = await request(server, { method: 'POST', path: '/v1/users/3', body: { is_admin: true, n: 1 } });
    assert.deepEqual(r.json.b, { n: 1 });
    assert.equal(events[1].found_fields[0].type, 'body');
});

test('koa: watch fires even when the handler throws', async (t) => {
    const app = new Koa();
    const { sentry, events } = makeSentry(app);
    sentry.watch('/boom').query('x');
    const router = new Router();
    router.get('/boom', (ctx) => { throw new Error('handler failed'); });
    app.use(router.routes());
    app.silent = true;
    const { server, close } = await serve(app.callback());
    t.after(close);
    const r = await request(server, { path: '/boom?x=1' });
    assert.equal(r.status, 500);
    assert.equal(events.length, 1);
});

test('koa: traps are served at the unprefixed path, not shadowed by app routes, for every router', async (t) => {
    const app = new Koa();
    const { sentry, events } = makeSentry(app);
    sentry.trap('/api/internal').methods('get', 'post', 'head', 'options');
    const r1 = new Router({ prefix: '/v1' });
    r1.get('/things', (ctx) => { ctx.body = 'v1'; });
    const r2 = new Router();
    r2.get('/api/:x', (ctx) => { ctx.body = 'param'; });
    const catchall = (ctx) => { ctx.body = 'catchall'; };
    try {
        r2.all('/{*rest}', catchall); // @koa/router >= 14 (path-to-regexp 8)
    } catch (e) {
        r2.all('/(.*)', catchall); // older routers
    }
    app.use(r1.routes());
    app.use(r2.routes());
    const { server, close } = await serve(app.callback());
    t.after(close);

    assert.equal((await request(server, { path: '/api/internal' })).status, 401);
    assert.equal((await request(server, { method: 'POST', path: '/api/internal' })).status, 401);
    assert.equal((await request(server, { method: 'HEAD', path: '/api/internal' })).status, 401);
    assert.equal((await request(server, { path: '/v1/api/internal' })).text, 'catchall');
    assert.equal((await request(server, { path: '/api/zzz' })).text, 'param');
    assert.equal(events.length, 3);
});

test('koa: traps run after auth middleware (identify_user sees ctx.state.user)', async (t) => {
    const app = new Koa();
    app.use(async (ctx, next) => { if (ctx.get('x-user')) ctx.state.user = ctx.get('x-user'); await next(); });
    const { sentry, events } = makeSentry(app);
    sentry.identify_user((ctx) => (ctx.state.user ? { user: ctx.state.user, role: 'r' } : null));
    sentry.trap('/ops').respond({ status: 200, body: { ok: true } });
    const router = new Router();
    router.get('/:x', (ctx) => { ctx.body = 'param'; });
    app.use(router.routes());
    const { server, close } = await serve(app.callback());
    t.after(close);
    assert.equal((await request(server, { path: '/ops' })).status, 401);
    const r = await request(server, { path: '/ops', headers: { 'x-user': 'amy' } });
    assert.equal(r.status, 200);
    assert.equal(events[1].user, 'amy');
});

test('koa: lazy bootstrap via app.callback() without listen; bootstrap is idempotent', async (t) => {
    const app = new Koa();
    const { sentry, events } = makeSentry(app);
    sentry.trap('/secret');
    const router = new Router();
    router.get('/real', (ctx) => { ctx.body = 'ok'; });
    app.use(router.routes());
    const { server, close } = await serve(app.callback());
    t.after(close);
    sentry.bootstrap(); sentry.bootstrap();
    assert.equal((await request(server, { path: '/secret' })).status, 401);
    assert.equal(events.length, 1);
    assert.equal(app.middleware.filter((m) => m.__trappsecTrap).length, 1);
});

test('koa: listen() works with watches and traps', async (t) => {
    const app = new Koa();
    const { sentry, events } = makeSentry(app);
    sentry.watch('/w').query('x');
    sentry.trap('/t');
    const router = new Router();
    router.get('/w', (ctx) => { ctx.body = ctx.query; });
    app.use(router.routes());
    const server = app.listen(0);
    await new Promise((r) => server.once('listening', r));
    t.after(() => server.close());
    assert.deepEqual((await request(server, { path: '/w?x=1&y=2' })).json, { y: '2' });
    assert.equal((await request(server, { path: '/t' })).status, 401);
    assert.equal(events.length, 2);
});

test('koa: nested router.use(child.routes()) with prefix is watched; duplicate trap fails loud', async (t) => {
    const app = new Koa();
    const { sentry, events } = makeSentry(app);
    sentry.watch('/outer/in/:id').query('x');
    const child = new Router();
    child.get('/in/:id', (ctx) => { ctx.body = ctx.query; });
    const parent = new Router();
    parent.use('/outer', child.routes());
    app.use(parent.routes());
    const { server, close } = await serve(app.callback());
    t.after(close);
    assert.deepEqual((await request(server, { path: '/outer/in/1?x=1&k=2' })).json, { k: '2' });
    assert.equal(events.length, 1);

    const app2 = new Koa();
    const s2 = makeSentry(app2).sentry;
    s2.trap('/dup').methods('GET');
    const r = new Router();
    r.get('/dup', (ctx) => { ctx.body = 'x'; });
    app2.use(r.routes());
    assert.throws(() => s2.bootstrap(), /duplicates an existing application route/);
});

test('koa: raising identify_user does not break requests; warns once when body parser is missing', async (t) => {
    const app = new Koa();
    const { sentry, events } = makeSentry(app);
    sentry.identify_user(() => { throw new Error('boom'); });
    sentry.watch('/p').query('x').body('y');
    sentry.trap('/t');
    const router = new Router();
    router.post('/p', (ctx) => { ctx.body = { q: ctx.query }; });
    app.use(router.routes());
    const { server, close } = await serve(app.callback());
    t.after(close);
    let r = await request(server, { method: 'POST', path: '/p?x=1&z=1', body: { y: 1 } });
    assert.equal(r.status, 200);
    assert.deepEqual(r.json.q, { z: '1' });
    await request(server, { method: 'POST', path: '/p', body: { y: 1 } });
    assert.equal(sentry.logger.logs.warn.filter((w) => /body parser/.test(w)).length, 1);
    r = await request(server, { path: '/t' });
    assert.equal(r.status, 401);
    assert.ok(events.length >= 2);
});

test('koa: prototype keys ignored', async (t) => {
    const app = new Koa();
    app.use(bodyParser());
    const { sentry, events } = makeSentry(app);
    sentry.watch('/p').query('x').body('y');
    const router = new Router();
    router.post('/p', (ctx) => { ctx.body = ctx.request.body; });
    app.use(router.routes());
    const { server, close } = await serve(app.callback());
    t.after(close);
    const r = await request(server, { method: 'POST', path: '/p?constructor=1&toString=2', body: '{"constructor":1,"toString":2,"keep":true}' });
    assert.equal(r.status, 200);
    assert.equal(events.length, 0);
});

test('koa: without a router, traps are not shadowed by a catch-all and methods are case-insensitive', async (t) => {
    const app = new Koa();
    const { sentry, events } = makeSentry(app);
    sentry.trap('/t').methods('get');
    app.use((ctx) => { ctx.status = 404; ctx.body = 'app404'; });
    const { server, close } = await serve(app.callback());
    t.after(close);
    const r = await request(server, { path: '/t' });
    assert.equal(r.status, 401);
    assert.equal(events.length, 1);
    assert.equal(events[0].event, 'trappsec.trap_hit');
});

test('koa: route-level body parsers cannot hide honey fields (@koa/multer, koa-bodyparser)', async (t) => {
    const multer = require('@koa/multer');
    const { multipart } = require('./helpers');
    const app = new Koa();
    const { sentry, events } = makeSentry(app);
    sentry.watch('/form').body('is_admin');
    sentry.watch('/json').query('debug').body('is_admin');
    sentry.watch('/admin').query('debug').body('is_admin');
    const router = new Router();
    router.post('/form', multer().none(), (ctx) => { ctx.body = ctx.request.body; });
    router.post('/json', bodyParser(), (ctx) => { ctx.body = { body: ctx.request.body, query: ctx.query }; });
    router.post('/admin', (ctx) => { ctx.status = 403; ctx.body = { error: 'no' }; }, bodyParser(), (ctx) => { ctx.body = 'unreachable'; });
    app.use(router.routes());
    const { server, close } = await serve(app.callback());
    t.after(close);

    const mp = multipart({ is_admin: 'true', name: 'a' });
    let r = await request(server, { method: 'POST', path: '/form', headers: mp.headers, body: mp.body });
    assert.deepEqual(r.json, { name: 'a' });
    assert.equal(events.length, 1);

    r = await request(server, { method: 'POST', path: '/json?debug=1&x=1', body: { is_admin: true, n: 1 } });
    assert.deepEqual(r.json, { body: { n: 1 }, query: { x: '1' } });
    assert.equal(events.length, 2);
    assert.deepEqual(events[1].found_fields.map((f) => f.field).sort(), ['debug', 'is_admin']);

    // a route middleware that answers first: what was seen is still reported once
    r = await request(server, { method: 'POST', path: '/admin?debug=1', body: { is_admin: true } });
    assert.equal(r.status, 403);
    await new Promise((resolve) => setTimeout(resolve, 20));
    assert.equal(events.length, 3);
    assert.deepEqual(events[2].found_fields.map((f) => f.field), ['debug']);
});

test("koa: an app-level bodyparser's empty placeholder does not hide a route-level multipart body", async (t) => {
    const multer = require('@koa/multer');
    const { multipart } = require('./helpers');
    const app = new Koa();
    app.use(bodyParser());
    const { sentry, events } = makeSentry(app);
    sentry.watch('/form').body('is_admin');
    const router = new Router();
    router.post('/form', multer().none(), (ctx) => { ctx.body = ctx.request.body; });
    app.use(router.routes());
    const { server, close } = await serve(app.callback());
    t.after(close);
    const mp = multipart({ is_admin: 'true', name: 'a' });
    const r = await request(server, { method: 'POST', path: '/form', headers: mp.headers, body: mp.body });
    assert.deepEqual(r.json, { name: 'a' });
    assert.equal(events.length, 1);
});

test('koa: a router wrapped in koa-compose is not seen; the warning says so and what to do', async (t) => {
    const compose = require('koa-compose');
    const app = new Koa();
    const { sentry, events } = makeSentry(app);
    sentry.watch('/w').query('debug');
    sentry.trap('/t');
    const router = new Router();
    router.get('/w', (ctx) => { ctx.body = ctx.query; });
    app.use(compose([router.routes()]));
    const { server, close } = await serve(app.callback());
    t.after(close);
    await request(server, { path: '/w?debug=1' });
    assert.equal(events.length, 0);
    const warns = sentry.logger.logs.warn.join('\n');
    assert.match(warns, /koa-compose or koa-mount are not seen/);
    assert.match(warns, /app\.use\(router\.routes\(\)\)|install trappsec on the mounted app/);
    assert.doesNotMatch(warns, /no @koa\/router instance found in app\.middleware;/);
});
