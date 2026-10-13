'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { makeSentry, request } = require('./helpers');

const json = (body) => ({ method: 'POST', body: JSON.stringify(body), headers: { 'content-type': 'application/json' } });

test('hono: watches strip query and JSON body fields before the handler', async () => {
    const app = new Hono();
    const { sentry, events } = makeSentry(app);
    sentry.watch('/users/:id').query('debug', { intent: 'd' }).body('is_admin', { intent: 'p' });
    app.get('/users/:id', (c) => c.json({ q: c.req.query(), id: c.req.param('id'), url: c.req.url }));
    app.post('/users/:id', async (c) => {
        const raw = await c.req.raw.clone().json(); // c.req.raw is the stripped request too
        return c.json({ b: await c.req.json(), raw });
    });

    let r = await (await app.request('/users/3?debug=1&keep=x')).json();
    assert.deepEqual(r.q, { keep: 'x' });
    assert.equal(r.id, '3');
    assert.ok(!r.url.includes('debug'));
    assert.equal(events[0].found_fields[0].type, 'query');

    r = await (await app.request('/users/3', json({ is_admin: true, n: 1 }))).json();
    assert.deepEqual(r.b, { n: 1 });
    assert.deepEqual(r.raw, { n: 1 });
    assert.equal(events[1].found_fields[0].type, 'body');
});

test('hono: form and multipart bodies are stripped for parseBody(), formData() and repeated fields', async () => {
    const app = new Hono();
    const { sentry, events } = makeSentry(app);
    sentry.watch('/form').body('role', { default: 'user' });
    app.post('/form', async (c) => c.json(await c.req.parseBody({ all: true })));

    let res = await app.request('/form', {
        method: 'POST', body: 'name=a&role=admin&tag=1&tag=2',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
    });
    assert.deepEqual(await res.json(), { name: 'a', tag: ['1', '2'] });

    const fd = new FormData();
    fd.append('name', 'b');
    fd.append('role', 'admin');
    fd.append('file', new Blob(['x']), 'a.txt');
    res = await app.request('/form', { method: 'POST', body: fd });
    const out = await res.json();
    assert.equal(out.name, 'b');
    assert.equal(out.role, undefined);
    assert.ok('file' in out);
    assert.equal(events.length, 2);

    // A value equal to the default is still stripped, but raises no alert.
    res = await app.request('/form', {
        method: 'POST', body: 'name=c&role=user', headers: { 'content-type': 'application/x-www-form-urlencoded' },
    });
    assert.deepEqual(await res.json(), { name: 'c' });
    assert.equal(events.length, 2);
});

test('hono: a body read by middleware first is still inspected and stripped', async () => {
    const app = new Hono();
    app.use('*', async (c, next) => { await c.req.json().catch(() => null); await next(); });
    const { sentry, events } = makeSentry(app);
    sentry.watch('/p').body('is_admin');
    app.post('/p', async (c) => c.json(await c.req.json()));
    const res = await app.request('/p', json({ is_admin: true, a: 1 }));
    assert.deepEqual(await res.json(), { a: 1 });
    assert.equal(events.length, 1);
});

test('hono: route-level middleware (validator) sees the stripped body; one event per request', async () => {
    const app = new Hono();
    const { sentry, events } = makeSentry(app);
    sentry.watch('/v').body('is_admin');
    const seen = [];
    app.post('/v', async (c, next) => { seen.push(await c.req.json()); await next(); }, async (c) => c.json(await c.req.json()));
    const res = await app.request('/v', json({ is_admin: true, a: 1 }));
    assert.deepEqual(await res.json(), { a: 1 });
    assert.deepEqual(seen, [{ a: 1 }]);
    assert.equal(events.length, 1);
});

test('hono: traps run after middleware and before routes and catch-alls registered earlier', async () => {
    const app = new Hono();
    app.use('*', async (c, next) => { c.set('user', c.req.header('x-user')); await next(); });
    const { sentry, events } = makeSentry(app);
    sentry.identify_user((c) => (c.get('user') ? { user: c.get('user'), role: 'r' } : null));
    sentry.trap('/api/internal').methods('GET', 'POST').respond({ status: 200, body: { ok: true } });
    app.get('/api/:x', (c) => c.text('param'));
    app.get('*', (c) => c.text('catchall'));

    let res = await app.request('/api/internal');
    assert.equal(res.status, 401);
    res = await app.request('/api/internal', { headers: { 'x-user': 'amy' } });
    assert.equal(res.status, 200);
    assert.equal(res.headers.get('content-type'), 'application/json');
    assert.deepEqual(await res.json(), { ok: true });
    assert.equal((await app.request('/api/internal', { method: 'POST' })).status, 401);
    assert.equal((await app.request('/api/internal', { method: 'HEAD' })).status, 401);
    assert.equal(await (await app.request('/api/other')).text(), 'param');
    assert.equal(await (await app.request('/x')).text(), 'catchall');
    assert.equal(events.length, 4);
    assert.equal(events[1].user, 'amy');
});

test('hono: a trap with an undeclared method answers like an unknown path', async () => {
    const app = new Hono();
    const { sentry, events } = makeSentry(app);
    sentry.trap('/t').methods('GET');
    app.get('/real', (c) => c.text('ok'));
    const trap = await app.request('/t', { method: 'DELETE' });
    const real = await app.request('/real', { method: 'DELETE' });
    assert.equal(trap.status, real.status);
    assert.equal(await trap.text(), await real.text());
    assert.equal(events.length, 0);
});

test('hono: app.route() sub-apps and basePath() are watched by full path; traps ignore basePath', async () => {
    const app = new Hono().basePath('/api');
    const { sentry, events } = makeSentry(app);
    sentry.watch('/api/v2/orders/:id').query('discount');
    sentry.trap('/deployment/config');
    const orders = new Hono();
    orders.get('/:id', (c) => c.json({ id: c.req.param('id'), q: c.req.query() }));
    app.route('/v2/orders', orders);

    const r = await (await app.request('/api/v2/orders/7?discount=X&a=1')).json();
    assert.deepEqual(r, { id: '7', q: { a: '1' } });
    assert.equal((await app.request('/deployment/config')).status, 401);
    assert.equal(events.length, 2);
    assert.deepEqual(sentry.logger.logs.warn, []);
});

test('hono: duplicate trap fails loud on every request; unmatched watch warns', async () => {
    const app = new Hono();
    const { sentry } = makeSentry(app);
    sentry.trap('/users/:id').methods('GET');
    app.get('/users/:id', (c) => c.text('real'));
    assert.throws(() => app.fetch(new Request('http://x/users/1')), /duplicates/);
    assert.throws(() => sentry.bootstrap(), /duplicates/);

    const app2 = new Hono();
    const s2 = makeSentry(app2).sentry;
    s2.watch('/nope').query('x');
    app2.get('/yes', (c) => c.text('ok'));
    await app2.request('/yes');
    assert.match(s2.logger.logs.warn.join('\n'), /watch \/nope matches no registered route/);
});

test('hono: route params and repeated requests stay right with the RegExpRouter cache', async () => {
    const app = new Hono();
    const { sentry, events } = makeSentry(app);
    sentry.watch('/a/:id').query('x');
    sentry.trap('/a/secret');
    app.use('/a/*', async (c, next) => { await next(); c.header('x-mw', '1'); });
    app.get('/a/:id', (c) => c.text(c.req.param('id')));
    for (let i = 0; i < 3; i++) {
        const res = await app.request(`/a/${i}?x=1`);
        assert.equal(await res.text(), String(i));
        assert.equal(res.headers.get('x-mw'), '1');
    }
    assert.equal((await app.request('/a/secret')).status, 401);
    assert.equal(events.length, 4);
});

test('hono: hono/csrf skipped for traps with is_trap; client IP ignores X-Forwarded-For', async (t) => {
    const { csrf } = require('hono/csrf');
    const app = new Hono();
    const { sentry, events } = makeSentry(app);
    sentry.trap('/t').methods('POST');
    const protect = csrf();
    app.use('*', (c, next) => (sentry.is_trap(c) ? next() : protect(c, next)));
    app.post('/real', (c) => c.text('ok'));
    const server = await new Promise((resolve) => {
        const s = serve({ fetch: app.fetch, port: 0, hostname: '127.0.0.1' }, () => resolve(s));
    });
    t.after(() => new Promise((r) => server.close(r)));
    // A cross-site form post: hono/csrf rejects it on a real route...
    const cross = { 'content-type': 'application/x-www-form-urlencoded', origin: 'https://evil.example' };
    assert.equal((await request(server, { method: 'POST', path: '/real', headers: cross, body: 'a=1' })).status, 403);
    // ...but the trap still answers with its decoy (and the spoofed header is not the IP).
    const r = await request(server, { method: 'POST', path: '/t', headers: { ...cross, 'x-forwarded-for': '6.6.6.6' }, body: 'a=1' });
    assert.equal(r.status, 401);
    assert.equal(events.length, 1);

    // Without the skip, hono/csrf blocks the trap too (disabling it and giving it away).
    const plain = new Hono();
    plain.use('*', csrf());
    const p = makeSentry(plain);
    p.sentry.trap('/t').methods('POST');
    const blocked = await plain.request('/t', { method: 'POST', headers: cross, body: 'a=1' });
    assert.equal(blocked.status, 403);
    assert.equal(p.events.length, 0);
    assert.equal(events[0].ip, '127.0.0.1');
});

test('hono: app.all() routes are routes (watched, duplicate-checked, never ahead of traps)', async () => {
    const app = new Hono();
    app.all('*', async (c, next) => { c.header('x-mw', '1'); await next(); }); // middleware: (c, next)
    const { sentry, events } = makeSentry(app);
    sentry.watch('/any').query('x');
    sentry.trap('/ops');
    app.all('/any', (c) => c.json(c.req.query()));
    app.all('*', (c) => c.text('catchall')); // a route: no next
    const res = await app.request('/ops');
    assert.equal(res.status, 401);
    assert.equal(res.headers.get('x-mw'), '1');
    assert.deepEqual(await (await app.request('/any?x=1&y=2')).json(), { y: '2' });
    assert.equal(await (await app.request('/other')).text(), 'catchall');
    assert.equal(events.length, 2);

    const dup = new Hono();
    const d = makeSentry(dup).sentry;
    d.trap('/x').methods('POST');
    dup.all('/x', (c) => c.text('real'));
    assert.throws(() => d.bootstrap(), /duplicates/);
});

test('hono: a throwing identify_user or body default never breaks the request', async () => {
    const app = new Hono();
    const { sentry, events } = makeSentry(app);
    sentry.identify_user(() => { throw new Error('auth down'); });
    sentry.watch('/w').body('plan', { default: () => { throw new Error('lookup down'); } });
    sentry.trap('/t');
    app.post('/w', async (c) => c.json(await c.req.json()));
    assert.equal((await app.request('/t')).status, 401);
    const res = await app.request('/w', json({ plan: 'gold', a: 1 }));
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), { a: 1 });
    assert.equal(events.length, 2);
    assert.equal(events[0].user, null);
});
