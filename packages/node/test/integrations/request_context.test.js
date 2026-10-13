'use strict';

// R1, R6, R11 for every Node integration. One request goes to a watched
// parameterised route with a honey query field: the watch must match by route
// pattern (R1); the field must be gone from every way a handler (or a proxy)
// can read the query, not just the parsed object (R6); and the event must carry
// the path, method, User-Agent and client address the framework reports (R11).

require('reflect-metadata');
const test = require('node:test');
const assert = require('node:assert/strict');
const Hapi = require('@hapi/hapi');
const Koa = require('koa');
const Router = require('@koa/router');
const Fastify = require('fastify');
const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { NestFactory } = require('@nestjs/core');
const common = require('@nestjs/common');
const { ExpressAdapter } = require('@nestjs/platform-express');
const { FastifyAdapter } = require('@nestjs/platform-fastify');
const { makeSentry, request } = require('./helpers');

const UA = 'trappsec-context-probe/1.0';
const PATH = '/users/7?debug=1&x=1';

function check(events, seen) {
    assert.deepEqual({ ...seen.query }, { x: '1' }, 'parsed query');
    for (const [name, url] of Object.entries(seen.urls)) {
        assert.ok(!String(url).includes('debug'), `${name} still carries the honey field: ${url}`);
        assert.ok(String(url).includes('x=1'), `${name} lost a real parameter: ${url}`);
    }
    assert.equal(events.length, 1, 'the watch must match the parameterised route (R1)');
    const e = events[0];
    assert.equal(e.path, '/users/7');
    assert.equal(e.method, 'GET');
    assert.equal(e.user_agent, UA);
    assert.ok(e.ip && e.ip === seen.ip, `event ip ${e.ip} != framework ip ${seen.ip}`);
    assert.deepEqual(e.found_fields, [{ type: 'query', field: 'debug', value: '1', intent: null }]);
}

async function listen(t, server) {
    await new Promise((r) => server.once('listening', r));
    t.after(() => server.close());
    return server;
}

for (const [label, pkg] of [['express4', 'express4'], ['express5', 'express']]) {
    test(`${label}: request context and raw URL`, async (t) => {
        const express = require(pkg);
        const app = express();
        const { sentry, events } = makeSentry(app);
        sentry.watch('/users/:id').query('debug');
        app.get('/users/:id', (req, res) => res.json({ ip: req.ip, query: req.query, urls: { url: req.url } }));
        const server = await listen(t, app.listen(0, '127.0.0.1'));
        const r = await request(server, { path: PATH, headers: { 'user-agent': UA } });
        check(events, r.json);
    });
}

test('fastify: request context and raw URL', async () => {
    const app = Fastify();
    const { sentry, events } = makeSentry(app);
    sentry.watch('/users/:id').query('debug');
    app.get('/users/:id', async (req) => ({ ip: req.ip, query: req.query, urls: { url: req.url, raw: req.raw.url } }));
    const r = await app.inject({ url: PATH, headers: { 'user-agent': UA } });
    check(events, r.json());
});

test('hapi: request context and raw URL', async () => {
    const server = Hapi.server();
    const { sentry, events } = makeSentry(server);
    sentry.watch('/users/{id}').query('debug');
    server.route({
        method: 'GET', path: '/users/{id}',
        handler: (r) => ({ ip: r.info.remoteAddress, query: r.query, urls: { href: r.url.href, raw: r.raw.req.url } }),
    });
    const r = await server.inject({ url: PATH, headers: { 'user-agent': UA } });
    check(events, r.result);
});

test('koa: request context and raw URL', async (t) => {
    const app = new Koa();
    const { sentry, events } = makeSentry(app);
    sentry.watch('/users/:id').query('debug');
    const router = new Router();
    router.get('/users/:id', (ctx) => {
        ctx.body = { ip: ctx.ip, query: ctx.query, urls: { url: ctx.url, querystring: '?' + ctx.querystring, raw: ctx.req.url } };
    });
    app.use(router.routes());
    const server = await listen(t, app.listen(0, '127.0.0.1'));
    const r = await request(server, { path: PATH, headers: { 'user-agent': UA } });
    check(events, r.json);
});

test('hono: request context and raw URL', async (t) => {
    const app = new Hono();
    const { sentry, events } = makeSentry(app);
    sentry.watch('/users/:id').query('debug');
    app.get('/users/:id', (c) => c.json({
        ip: c.env.incoming.socket.remoteAddress,
        query: c.req.query(),
        urls: { url: c.req.url, raw: c.req.raw.url },
    }));
    const server = await new Promise((r) => { const s = serve({ fetch: app.fetch, port: 0, hostname: '127.0.0.1' }, () => r(s)); });
    t.after(() => new Promise((r) => server.close(r)));
    const r = await request(server, { path: PATH, headers: { 'user-agent': UA } });
    check(events, r.json);
});

for (const [label, makeAdapter] of [['nest-express', () => new ExpressAdapter()], ['nest-fastify', () => new FastifyAdapter()]]) {
    test(`${label}: request context and raw URL`, async (t) => {
        class UsersController {
            get(req, query) {
                return { ip: req.ip, query: { ...query }, urls: { url: req.url, raw: (req.raw || req).url } };
            }
        }
        common.Controller('users')(UsersController);
        const P = UsersController.prototype;
        const d = Object.getOwnPropertyDescriptor(P, 'get');
        common.Get(':id')(P, 'get', d);
        common.Req()(P, 'get', 0);
        common.Query()(P, 'get', 1);
        class M {}
        common.Module({ controllers: [UsersController] })(M);
        const app = await NestFactory.create(M, makeAdapter(), { logger: false });
        const { sentry, events } = makeSentry(app);
        sentry.watch('/users/:id').query('debug');
        await app.listen(0, '127.0.0.1');
        t.after(() => app.close());
        const r = await request(app.getHttpServer(), { path: PATH, headers: { 'user-agent': UA } });
        check(events, r.json);
    });
}
