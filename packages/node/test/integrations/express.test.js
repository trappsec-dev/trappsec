'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const { makeSentry, request, serve } = require('./helpers');

for (const [label, pkg] of [['express4', 'express4'], ['express5', 'express']]) {
    let express;
    try { express = require(pkg); } catch (e) { test(label, { skip: pkg + ' not installed' }, () => {}); continue; }

    const jsonParser = express.json();

    test(`${label}: listen() with watches and traps does not crash; watch strips and reports type=query`, async (t) => {
        const app = express();
        app.use(jsonParser);
        const { sentry, events } = makeSentry(app);
        sentry.watch('/items/:id').query('debug', { intent: 'dbg' }).body('is_admin', { defaultValue: false, intent: 'priv' });
        sentry.trap('/admin/export').intent('probe');
        app.get('/items/:id', (req, res) => res.json({ query: req.query, id: req.params.id }));
        app.post('/items/:id', (req, res) => res.json({ body: req.body }));

        const server = app.listen(0);
        await new Promise((r) => server.once('listening', r));
        t.after(() => server.close());

        let r = await request(server, { path: '/items/7?debug=1&keep=2' });
        assert.deepEqual(r.json.query, { keep: '2' });
        assert.equal(events.length, 1);
        assert.equal(events[0].event, 'trappsec.watch_hit');
        assert.equal(events[0].found_fields[0].type, 'query');
        assert.equal(events[0].found_fields[0].field, 'debug');

        r = await request(server, { method: 'POST', path: '/items/7', body: { is_admin: true, name: 'x' } });
        assert.deepEqual(r.json.body, { name: 'x' });
        assert.equal(events[1].found_fields[0].type, 'body');

        // is_admin matching its default is stripped but not reported
        r = await request(server, { method: 'POST', path: '/items/7', body: { is_admin: false, name: 'y' } });
        assert.deepEqual(r.json.body, { name: 'y' });
        assert.equal(events.length, 2);

        r = await request(server, { path: '/admin/export' });
        assert.equal(r.status, 401);
        assert.equal(events[2].event, 'trappsec.trap_hit');
    });

    test(`${label}: lazy bootstrap without listen (custom http server)`, async (t) => {
        const app = express();
        const { sentry, events } = makeSentry(app);
        sentry.trap('/secret');
        app.get('/real', (req, res) => res.send('ok'));
        const { server, close } = await serve(app);
        t.after(close);
        assert.equal((await request(server, { path: '/secret' })).status, 401);
        assert.equal((await request(server, { path: '/real' })).text, 'ok');
        assert.equal(events.length, 1);
        sentry.bootstrap(); sentry.bootstrap(); // idempotent
        assert.equal((await request(server, { path: '/secret' })).status, 401);
    });

    test(`${label}: traps are not shadowed by param/catch-all routes and 404 middleware`, async (t) => {
        const app = express();
        const { sentry, events } = makeSentry(app);
        sentry.trap('/api/internal').intent('x').methods('GET', 'POST', 'HEAD', 'OPTIONS');
        app.get('/api/:x', (req, res) => res.send('param'));
        app.post(label === 'express4' ? '/api/*' : '/api/{*rest}', (req, res) => res.send('catchall'));
        app.use((req, res) => res.status(404).send('nf'));
        const { server, close } = await serve(app);
        t.after(close);

        assert.equal((await request(server, { path: '/api/internal' })).status, 401);
        assert.equal((await request(server, { method: 'POST', path: '/api/internal' })).status, 401);
        assert.equal((await request(server, { method: 'HEAD', path: '/api/internal' })).status, 401);
        assert.equal((await request(server, { method: 'OPTIONS', path: '/api/internal' })).status, 401);
        assert.equal((await request(server, { path: '/api/other' })).text, 'param');
        assert.equal(events.length, 4);
    });

    test(`${label}: traps run after middleware so identify_user sees req.user (authenticated response)`, async (t) => {
        const app = express();
        app.use((req, res, next) => { if (req.headers['x-user']) req.user = { name: req.headers['x-user'], role: 'staff' }; next(); });
        const { sentry, events } = makeSentry(app);
        sentry.identify_user((req) => (req.user ? { user: req.user.name, role: req.user.role } : null));
        sentry.trap('/ops').if_unauthenticated({ status: 404, body: { e: 'nope' } }).respond({ status: 200, body: { ok: 1 } });
        app.get('/:x', (req, res) => res.send('param'));
        const { server, close } = await serve(app);
        t.after(close);

        let r = await request(server, { path: '/ops' });
        assert.equal(r.status, 404);
        assert.equal(events[0].type, 'signal');
        r = await request(server, { path: '/ops', headers: { 'x-user': 'bob' } });
        assert.equal(r.status, 200);
        assert.equal(events[1].type, 'alert');
        assert.equal(events[1].user, 'bob');
        assert.equal(events[1].role, 'staff');
    });

    test(`${label}: duplicate of an exact app route fails loud`, async () => {
        const app = express();
        const { sentry } = makeSentry(app);
        sentry.trap('/dup').methods('GET');
        app.get('/dup', (req, res) => res.send('real'));
        assert.throws(() => sentry.bootstrap(), /duplicates an existing application route/);
    });

    test(`${label}: prototype keys are ignored, nested sub-router watch works`, async (t) => {
        const app = express();
        app.use(express.json());
        const { sentry, events } = makeSentry(app);
        sentry.watch('/v1/users/:id').query('debug').body('role');
        const sub = express.Router();
        sub.all('/users/:id', (req, res) => res.json({ q: req.query, b: req.body }));
        app.use('/v1', sub);
        const { server, close } = await serve(app);
        t.after(close);

        let r = await request(server, { method: 'POST', path: '/v1/users/1?constructor=a&toString=b&hasOwnProperty=c', body: { constructor: 'x', toString: 'y', '__proto__': { role: 'admin' }, name: 'n' } });
        assert.equal(r.status, 200);
        assert.equal(events.length, 0);
        assert.equal(r.json.b.name, 'n');

        r = await request(server, { method: 'POST', path: '/v1/users/1?debug=1', body: { role: 'admin' } });
        assert.deepEqual(r.json.q, {});
        assert.deepEqual(r.json.b, {});
        assert.equal(events.length, 1);
        assert.deepEqual(events[0].found_fields.map((f) => f.type).sort(), ['body', 'query']);
    });

    test(`${label}: trap duplicating a route inside a mounted sub-router fails loud`, async () => {
        const app = express();
        const { sentry } = makeSentry(app);
        sentry.trap('/api/secret').methods('GET');
        const api = express.Router();
        api.get('/secret', (req, res) => res.send('real'));
        app.use('/api', api);
        assert.throws(() => sentry.bootstrap(), /GET \/api\/secret duplicates an existing application route/);

        // a different method, or a different mount, is not a duplicate
        const app2 = express();
        const s2 = makeSentry(app2).sentry;
        s2.trap('/api/secret').methods('POST');
        s2.trap('/other/secret').methods('GET');
        const api2 = express.Router();
        api2.get('/secret', (req, res) => res.send('real'));
        app2.use('/api', api2);
        s2.bootstrap();
    });

    test(`${label}: watch on a sub-router mounted under a parameterised path fires`, async (t) => {
        const app = express();
        const { sentry, events } = makeSentry(app);
        sentry.watch('/users/:id/x').query('debug');
        const r = express.Router({ mergeParams: true });
        r.get('/x', (req, res) => res.json({ q: req.query, id: req.params.id }));
        r.get('/y', (req, res) => res.json({ q: req.query }));
        app.use('/users/:id', r);
        const { server, close } = await serve(app);
        t.after(close);

        let res = await request(server, { path: '/users/5/x?debug=1&k=v' });
        assert.deepEqual(res.json, { q: { k: 'v' }, id: '5' });
        assert.equal(events.length, 1);
        assert.equal(events[0].found_fields[0].field, 'debug');
        res = await request(server, { path: '/users/6/y?debug=1' }); // unwatched route
        assert.deepEqual(res.json, { q: { debug: '1' } });
        assert.equal(events.length, 1);
    });

    test(`${label}: a router mounted twice resolves each mount to its own watch`, async (t) => {
        const app = express();
        const { sentry, events } = makeSentry(app);
        sentry.watch('/a/x').query('debug');
        const r = express.Router();
        r.get('/x', (req, res) => res.json(req.query));
        app.use('/a', r);
        app.use('/b', r);
        const { server, close } = await serve(app);
        t.after(close);
        assert.deepEqual((await request(server, { path: '/b/x?debug=1' })).json, { debug: '1' });
        assert.equal(events.length, 0);
        assert.deepEqual((await request(server, { path: '/a/x?debug=1' })).json, {});
        assert.equal(events.length, 1);
    });

    test(`${label}: watch that may be inside a mounted sub-app logs a warning naming the mount`, async (t) => {
        const app = express();
        const { sentry } = makeSentry(app);
        sentry.watch('/sub/things').query('debug');
        sentry.watch('/elsewhere').query('debug');
        const sub = express();
        sub.get('/things', (req, res) => res.json(req.query));
        app.use('/sub', sub);
        app.get('/elsewhere', (req, res) => res.json(req.query));
        const { server, close } = await serve(app);
        t.after(close);
        await request(server, { path: '/elsewhere' });
        const warns = sentry.logger.logs.warn.filter((w) => w.includes('sub-app'));
        assert.equal(warns.length, 1);
        assert.match(warns[0], /\/sub\/things.*mounted at \/sub.*Install trappsec on the sub-app/);
    });

    test(`${label}: plain Express does not enter AsyncLocalStorage for pending body watches`, async (t) => {
        const ExpressIntegration = require('../../src/integrations/express');
        const app = express();
        const { sentry } = makeSentry(app);
        sentry.watch('/p').body('is_admin');
        let store = 'unset';
        app.post('/p', express.json(), (req, res) => { store = ExpressIntegration.pendingRequest.getStore(); res.json(req.body); });
        const { server, close } = await serve(app);
        t.after(close);
        const r = await request(server, { method: 'POST', path: '/p', body: { is_admin: true, n: 1 } });
        assert.deepEqual(r.json, { n: 1 });
        assert.equal(store, undefined);
    });

    test(`${label}: multi-value query watch`, async (t) => {
        const app = express();
        const { sentry, events } = makeSentry(app);
        sentry.watch('/m').query('flag', { defaultValue: '1' });
        app.get('/m', (req, res) => res.json(req.query));
        const { server, close } = await serve(app);
        t.after(close);
        let r = await request(server, { path: '/m?flag=1&flag=1&k=v' });
        assert.deepEqual(r.json, { k: 'v' });
        assert.equal(events.length, 0);
        r = await request(server, { path: '/m?flag=1&flag=2' });
        assert.deepEqual(r.json, {});
        assert.equal(events.length, 1);
    });

    test(`${label}: raising identify_user / override_source_ip never breaks requests or traps`, async (t) => {
        const app = express();
        app.use(express.json());
        const { sentry, events } = makeSentry(app);
        sentry.identify_user(() => { throw new Error('boom'); });
        sentry.override_source_ip(() => { throw new Error('ip boom'); });
        sentry.watch('/w').query('x');
        sentry.trap('/t');
        app.get('/w', (req, res) => res.json({ q: req.query }));
        const { server, close } = await serve(app);
        t.after(close);

        let r = await request(server, { path: '/w?x=1&y=2' });
        assert.equal(r.status, 200);
        assert.deepEqual(r.json.q, { y: '2' });
        r = await request(server, { path: '/t' });
        assert.equal(r.status, 401);
        assert.ok(!/<pre>|Error:/.test(r.text), 'no stack trace in trap response');
        assert.equal(r.headers['content-type'].startsWith('application/json'), true);
        assert.ok(events.length >= 1);
    });

    test(`${label}: failure inside trap machinery returns the normal decoy, not an error`, async (t) => {
        const app = express();
        const { sentry } = makeSentry(app);
        sentry.trap('/t').if_unauthenticated({ status: 403, body: { denied: true } });
        sentry._trigger_trap_event = () => { throw new Error('internal'); };
        const { server, close } = await serve(app);
        t.after(close);
        const r = await request(server, { path: '/t' });
        assert.equal(r.status, 403);
        assert.deepEqual(r.json, { denied: true });
    });

    test(`${label}: body watch without a body parser logs a one-time warning`, async (t) => {
        const app = express();
        const { sentry } = makeSentry(app);
        sentry.watch('/b').body('x');
        app.post('/b', (req, res) => res.json({ got: req.body === undefined ? 'undef' : 'obj' }));
        const { server, close } = await serve(app);
        t.after(close);
        await request(server, { method: 'POST', path: '/b', body: { x: 1 } });
        await request(server, { method: 'POST', path: '/b', body: { x: 1 } });
        assert.equal(sentry.logger.logs.warn.filter((w) => /body parser/.test(w)).length, 1);
    });

    test(`${label}: default IP extractor tolerates a request without socket`, () => {
        const app = express();
        const { sentry } = makeSentry(app);
        assert.equal(sentry.identity.ip({}), '0.0.0.0');
    });

    test(`${label}: trailing-slash watch keys are normalized`, async (t) => {
        const app = express();
        const { sentry, events } = makeSentry(app);
        sentry.watch('/slash/').query('q');
        app.get('/slash', (req, res) => res.json(req.query));
        const { server, close } = await serve(app);
        t.after(close);
        await request(server, { path: '/slash?q=1' });
        assert.equal(events.length, 1);
    });

    test(`${label}: https-style http.createServer(app) and error middleware keep working`, async (t) => {
        const app = express();
        const { sentry } = makeSentry(app);
        sentry.trap('/t');
        app.get('/boom', () => { throw new Error('app error'); });
        app.use((err, req, res, next) => res.status(500).json({ handled: err.message }));
        const server = http.createServer(app);
        await new Promise((r) => server.listen(0, '127.0.0.1', r));
        t.after(() => server.close());
        assert.equal((await request(server, { path: '/boom' })).json.handled, 'app error');
        assert.equal((await request(server, { path: '/t' })).status, 401);
    });
}

for (const [label, pkg] of [['express4', 'express4'], ['express5', 'express']]) {
    let express, multer;
    try { express = require(pkg); multer = require('multer'); } catch (e) { continue; }
    const { multipart } = require('./helpers');

    async function start(t, build) {
        const app = express();
        const { sentry, events } = makeSentry(app);
        build(app, sentry);
        const server = await new Promise((r) => { const s = app.listen(0, '127.0.0.1', () => r(s)); });
        t.after(() => server.close());
        return { server, events };
    }

    test(`${label}: route-level body parsers cannot hide honey fields (multer, express.json)`, async (t) => {
        const { server, events } = await start(t, (app, sentry) => {
            sentry.watch('/form').body('is_admin', { intent: 'priv' });
            sentry.watch('/json').query('debug').body('is_admin');
            app.post('/form', multer().none(), (req, res) => res.json(req.body));
            app.post('/json', express.json(), (req, res) => res.json({ body: req.body, query: req.query }));
        });
        const mp = multipart({ is_admin: 'true', name: 'a' });
        let r = await request(server, { method: 'POST', path: '/form', headers: mp.headers, body: mp.body });
        assert.deepEqual(r.json, { name: 'a' });
        assert.equal(events.length, 1);
        assert.equal(events[0].found_fields[0].field, 'is_admin');

        // query and body honey fields on a route-level parser still make ONE event
        r = await request(server, { method: 'POST', path: '/json?debug=1&x=1', body: { is_admin: true, n: 1 } });
        assert.deepEqual(r.json, { body: { n: 1 }, query: { x: '1' } });
        assert.equal(events.length, 2);
        assert.deepEqual(events[1].found_fields.map((f) => f.field).sort(), ['debug', 'is_admin']);
    });

    test(`${label}: a route middleware that rejects the request still reports what was seen`, async (t) => {
        const { server, events } = await start(t, (app, sentry) => {
            sentry.watch('/admin').query('debug').body('is_admin');
            app.post('/admin', (req, res) => res.status(403).json({ error: 'no' }), express.json(), (req, res) => res.json(req.body));
        });
        const r = await request(server, { method: 'POST', path: '/admin?debug=1', body: { is_admin: true } });
        assert.equal(r.status, 403);
        await new Promise((resolve) => setTimeout(resolve, 20)); // 'close' fires after the response
        assert.equal(events.length, 1);
        assert.deepEqual(events[0].found_fields.map((f) => f.field), ['debug']);
    });

    test(`${label}: per-method final handlers and route-level error handlers`, async (t) => {
        const { server, events } = await start(t, (app, sentry) => {
            sentry.watch('/thing').body('is_admin');
            app.route('/thing')
                .get((req, res) => res.json({ get: true }))
                .post(express.json(), (req, res, next) => (req.body.fail ? next(new Error('boom')) : res.json(req.body)),
                    // eslint-disable-next-line no-unused-vars
                    (err, req, res, next) => res.status(500).json({ error: err.message, body: req.body }));
        });
        let r = await request(server, { method: 'POST', path: '/thing', body: { is_admin: true, n: 1 } });
        assert.deepEqual(r.json, { n: 1 });
        r = await request(server, { method: 'POST', path: '/thing', body: { is_admin: true, fail: 1 } });
        assert.deepEqual(r.json, { error: 'boom', body: { fail: 1 } }); // error handler still runs, field stripped
        assert.equal((await request(server, { path: '/thing' })).json.get, true);
        assert.equal(events.length, 2);
    });
}

test('express: is_trap lets a global CSRF middleware skip traps (R22)', async (t) => {
    const express = require('express');
    const app = express();
    const { sentry, events } = makeSentry(app);
    // stand-in for csurf / csrf-csrf: rejects state-changing requests without a token
    const csrf = (req, res, next) => (req.method === 'POST' && !req.headers['x-csrf-token'] ? res.status(403).end() : next());
    app.use((req, res, next) => (sentry.is_trap(req) ? next() : csrf(req, res, next)));
    sentry.trap('/admin/backup').methods('POST');
    app.post('/real', (req, res) => res.send('ok'));
    const server = await new Promise((r) => { const s = app.listen(0, '127.0.0.1', () => r(s)); });
    t.after(() => server.close());
    assert.equal((await request(server, { method: 'POST', path: '/real' })).status, 403);
    assert.equal((await request(server, { method: 'POST', path: '/admin/backup' })).status, 401);
    assert.equal(events.length, 1);
});
