'use strict';

// Trap response headers, the per-request response hook and the callback
// fallback (R16, R23), served by every framework integration.

require('reflect-metadata');
const test = require('node:test');
const assert = require('node:assert/strict');
const { makeSentry, request } = require('./helpers');

// `header(req, name)` reads a request header in the framework's own way.
function configureMirror(sentry, header) {
    sentry.identify_user((req) => {
        const user = header(req, 'x-user');
        return user ? { user, role: header(req, 'x-role') } : null;
    });
    sentry.default_unauthenticated_response({
        status: 401, body: { detail: 'Not authenticated' }, headers: { 'WWW-Authenticate': 'Bearer' },
    });
    sentry.default_response({ status: 403, body: 'forbidden', mime_type: 'text/plain', headers: { 'X-Default': '1' } });
    sentry.trap('/api/v1/projects/export')
        .respond({ status: 403, body: { detail: 'Forbidden' }, mime_type: 'application/json', headers: { Allow: 'GET, POST', Vary: 'Accept' } })
        .respond_with((req, ctx) => {
            assert.ok(req);
            if (ctx.role === 'owner') return { status: 201, body: { id: 1 } };
            if (ctx.role === 'ghost') return { status: 404, body: { detail: 'Not found.' } };
            return null;
        });
    sentry.trap('/api/v1/broken').respond({ status: 200, body: () => { throw new Error('boom'); }, headers: { 'X-Trap': '1' } });
}

// `get(path, headers)` resolves to { status, headers (lower-cased names), text }.
async function checkMirror(get) {
    const member = { 'x-user': 'bob', 'x-role': 'member' };

    let r = await get('/api/v1/projects/export', {});
    assert.equal(r.status, 401);
    assert.equal(r.headers['www-authenticate'], 'Bearer');
    assert.deepEqual(JSON.parse(r.text), { detail: 'Not authenticated' });

    r = await get('/api/v1/projects/export', member);
    assert.equal(r.status, 403);
    assert.deepEqual(JSON.parse(r.text), { detail: 'Forbidden' });
    assert.equal(r.headers.allow, 'GET, POST');
    assert.equal(r.headers.vary, 'Accept');
    assert.equal(r.headers['www-authenticate'], undefined);

    r = await get('/api/v1/projects/export', { 'x-user': 'bob', 'x-role': 'owner' });
    assert.equal(r.status, 201);
    assert.deepEqual(JSON.parse(r.text), { id: 1 });
    assert.equal(r.headers.allow, 'GET, POST');

    r = await get('/api/v1/projects/export', { 'x-user': 'bob', 'x-role': 'ghost' });
    assert.equal(r.status, 404);
    assert.deepEqual(JSON.parse(r.text), { detail: 'Not found.' });

    // A failing body callback sends the default response, never "{}".
    r = await get('/api/v1/broken', member);
    assert.equal(r.status, 403);
    assert.equal(r.text, 'forbidden');
    assert.match(r.headers['content-type'], /^text\/plain/);
    assert.equal(r.headers['x-default'], '1');
    assert.equal(r.headers['x-trap'], undefined);
}

const viaServer = (server) => async (path, headers) => {
    const r = await request(server, { path, headers });
    return { status: r.status, headers: r.headers, text: r.text };
};

for (const pkg of ['express', 'express4']) {
    test(`${pkg}: trap headers, response hook and fallback`, async (t) => {
        let express;
        try { express = require(pkg); } catch (e) { return t.skip(pkg + ' not installed'); }
        const app = express();
        const { sentry } = makeSentry(app);
        configureMirror(sentry, (req, name) => req.headers[name]);
        app.get('/real', (req, res) => res.send('ok'));
        const server = await new Promise((r) => { const s = app.listen(0, '127.0.0.1', () => r(s)); });
        t.after(() => server.close());
        await checkMirror(viaServer(server));
    });
}

test('fastify: trap headers, response hook and fallback', async (t) => {
    const app = require('fastify')();
    const { sentry } = makeSentry(app);
    configureMirror(sentry, (req, name) => req.headers[name]);
    await app.listen({ port: 0, host: '127.0.0.1' });
    t.after(() => app.close());
    await checkMirror(viaServer(app.server));
});

test('hapi: trap headers, response hook and fallback', async (t) => {
    const server = require('@hapi/hapi').server({ port: 0, host: '127.0.0.1' });
    const { sentry } = makeSentry(server);
    configureMirror(sentry, (req, name) => req.headers[name]);
    await server.start();
    t.after(() => server.stop());
    await checkMirror(async (url, headers) => {
        const r = await server.inject({ url, headers });
        return { status: r.statusCode, headers: r.headers, text: r.payload };
    });
});

test('hono: trap headers, response hook and fallback', async () => {
    const { Hono } = require('hono');
    const app = new Hono();
    const { sentry } = makeSentry(app);
    configureMirror(sentry, (c, name) => c.req.header(name));
    await checkMirror(async (path, headers) => {
        const r = await app.request(path, { headers });
        return { status: r.status, headers: Object.fromEntries(r.headers), text: await r.text() };
    });
});

test('koa: trap headers, response hook and fallback', async (t) => {
    const Koa = require('koa');
    const { serve } = require('./helpers');
    const app = new Koa();
    const { sentry } = makeSentry(app);
    configureMirror(sentry, (ctx, name) => ctx.get(name) || undefined);
    const { server, close } = await serve(app.callback());
    t.after(close);
    await checkMirror(viaServer(server));
});

for (const [label, adapterModule, adapterName] of [
    ['nest-express', '@nestjs/platform-express', 'ExpressAdapter'],
    ['nest-fastify', '@nestjs/platform-fastify', 'FastifyAdapter'],
]) {
    test(`${label}: trap headers, response hook and fallback`, async (t) => {
        const { NestFactory } = require('@nestjs/core');
        const common = require('@nestjs/common');
        class RealController { get() { return 'ok'; } }
        common.Controller('real')(RealController);
        const d = Object.getOwnPropertyDescriptor(RealController.prototype, 'get');
        common.Get()(RealController.prototype, 'get', d);
        class AppModule {}
        common.Module({ controllers: [RealController] })(AppModule);
        const Adapter = require(adapterModule)[adapterName];
        const app = await NestFactory.create(AppModule, new Adapter(), { logger: false });
        const { sentry } = makeSentry(app);
        configureMirror(sentry, (req, name) => req.headers[name]);
        await app.listen(0, '127.0.0.1');
        t.after(() => app.close());
        await checkMirror(viaServer(app.getHttpServer()));
    });
}
