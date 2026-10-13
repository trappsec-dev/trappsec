'use strict';

// R18: repeating a watched key (first value = the default, second not) must
// still be detected, and every copy stripped, in the query and in form bodies.
const test = require('node:test');
const assert = require('node:assert/strict');
const Hapi = require('@hapi/hapi');
const Koa = require('koa');
const Router = require('@koa/router');
const bodyParser = require('koa-bodyparser');
const Fastify = require('fastify');
const { Hono } = require('hono');
const express = require('express');
const { makeSentry, request } = require('./helpers');

const FORM = { 'content-type': 'application/x-www-form-urlencoded' };
const QS = '/q?role=user&role=admin&x=1';
const BODY = 'role=user&role=admin&name=a';
const watch = (sentry) => sentry.watch('/q').query('role', { defaultValue: 'user' }).body('role', { defaultValue: 'user' });

function check(events, query, body) {
    assert.deepEqual({ ...query }, { x: '1' });
    assert.deepEqual({ ...body }, { name: 'a' });
    assert.equal(events.length, 2);
    assert.deepEqual(events.map((e) => [e.found_fields[0].type, e.found_fields[0].value]),
        [['query', ['user', 'admin']], ['body', ['user', 'admin']]]);
}

test('hapi: duplicate watched keys', async () => {
    const server = Hapi.server();
    const { sentry, events } = makeSentry(server);
    watch(sentry);
    server.route({ method: ['GET', 'POST'], path: '/q', handler: (r) => ({ q: r.query, b: r.payload }) });
    const q = (await server.inject({ url: QS })).result.q;
    const b = (await server.inject({ method: 'POST', url: '/q', headers: FORM, payload: BODY })).result.b;
    check(events, q, b);
});

test('koa: duplicate watched keys', async (t) => {
    const app = new Koa();
    app.use(bodyParser());
    const { sentry, events } = makeSentry(app);
    watch(sentry);
    const router = new Router();
    router.all('/q', (ctx) => { ctx.body = { q: ctx.query, b: ctx.request.body }; });
    app.use(router.routes());
    const server = app.listen(0, '127.0.0.1');
    await new Promise((r) => server.once('listening', r));
    t.after(() => server.close());
    const q = (await request(server, { path: QS })).json.q;
    const b = (await request(server, { method: 'POST', path: '/q', headers: FORM, body: BODY })).json.b;
    check(events, q, b);
});

test('hono: duplicate watched keys', async () => {
    const app = new Hono();
    const { sentry, events } = makeSentry(app);
    watch(sentry);
    app.all('/q', async (c) => c.json({ q: c.req.query(), b: c.req.method === 'POST' ? await c.req.parseBody() : null }));
    const q = (await (await app.request(QS)).json()).q;
    const b = (await (await app.request('/q', { method: 'POST', headers: FORM, body: BODY })).json()).b;
    check(events, q, b);
});

test('fastify: duplicate watched keys', async () => {
    const app = Fastify();
    app.register(require('@fastify/formbody'));
    const { sentry, events } = makeSentry(app);
    watch(sentry);
    app.all('/q', async (req) => ({ q: req.query, b: req.body }));
    const q = (await app.inject({ url: QS })).json().q;
    const b = (await app.inject({ method: 'POST', url: '/q', headers: FORM, payload: BODY })).json().b;
    check(events, q, b);
});

test('express: duplicate watched keys', async (t) => {
    const app = express();
    app.use(express.urlencoded({ extended: false }));
    const { sentry, events } = makeSentry(app);
    watch(sentry);
    app.all('/q', (req, res) => res.json({ q: req.query, b: req.body }));
    const server = app.listen(0, '127.0.0.1');
    await new Promise((r) => server.once('listening', r));
    t.after(() => server.close());
    const q = (await request(server, { path: QS })).json.q;
    const b = (await request(server, { method: 'POST', path: '/q', headers: FORM, body: BODY })).json.b;
    check(events, q, b);
});
