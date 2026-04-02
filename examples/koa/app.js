const { parseArgs } = require('node:util');

const options = {
    otel: { type: 'boolean' },
    webhook: { type: 'string' },
};

const { values } = parseArgs({ options, strict: false });

if (values.otel) {
    require('./otel').setupOpentelemetry();
}

const Koa = require('koa');
const Router = require('@koa/router');
const bodyParser = require('koa-bodyparser');
const serve = require('koa-static');
const path = require('path');
const trappsec = require('../../packages/node/src/index');

const app = new Koa();
const router = new Router();

async function bootstrap() {
    app.use(bodyParser());

    const ts = new trappsec.Sentry(app, 'KoaApp', 'Development');

    ts.default_responses.unauthenticated = {
        status_code: 401,
        response_body: { error: 'authentication required' },
        mime_type: 'application/json',
    };

    ts.identify_user((ctx) => {
        if (ctx.headers['x-user-id']) {
            return {
                user: ctx.headers['x-user-id'],
                role: ctx.headers['x-user-role'] || 'user',
            };
        }
        return null;
    });

    ts.override_source_ip((ctx) => ctx.headers['x-real-ip'] || ctx.ip || ctx.req?.socket?.remoteAddress || '0.0.0.0');

    // Legitimate routes
    router.post('/auth/register', (ctx) => {
        const email = ctx.request.body?.email || null;
        ctx.body = { status: 'registered', email };
    });

    router.get('/api/v2/profile', (ctx) => {
        const name = ctx.headers['x-user-id'];
        ctx.body = { name, is_admin: false };
    });

    router.post('/api/v2/profile', (ctx) => {
        const name = ctx.headers['x-user-id'];
        ctx.body = { name, status: 'updated' };
    });

    router.get('/api/v2/orders', (ctx) => {
        ctx.body = {
            orders: [
                { id: 'ord-123', item: 'Laptop', amount: 1200 },
                { id: 'ord-124', item: 'Mouse', amount: 45 },
            ],
        };
    });

    router.get('/api/v2/orders/:id', (ctx) => {
        ctx.body = { id: ctx.params.id, item: 'Laptop', amount: 1200, status: 'shipped' };
    });

    router.get('/api/v2/echo/query', (ctx) => { ctx.body = ctx.query; });
    router.post('/api/v2/echo/body', (ctx) => { ctx.body = ctx.request.body || {}; });
    router.post('/api/v2/echo/form', (ctx) => { ctx.body = ctx.request.body || {}; });
    router.post('/api/v2/echo/multipart', (ctx) => { ctx.body = { supported: false }; });

    app.use(router.routes());
    app.use(router.allowedMethods());

    // Serve lure frontend from root
    app.use(serve(path.join(__dirname, '../lure-frontend')));

    // Traps
    ts.trap('/deployment/config')
        .methods('GET')
        .intent('Reconnaissance')
        .respond({ status: 200, body: { region: 'us-east-1', deployment_type: 'production' } });

    ts.trap('/deployment/metrics')
        .methods('GET')
        .intent('Reconnaissance')
        .respond({
            status: 200,
            body: () => ({
                cpu: `${Math.floor(Math.random() * 91) + 5}%`,
                memory: `${Math.floor(Math.random() * 71) + 20}%`,
            }),
        });

    ts.template('fake_deprecated_api_response', 410, {
        error: 'Gone',
        message: 'API v1 has been deprecated',
    });

    ts.trap('/api/v1/orders')
        .methods('GET', 'POST')
        .intent('Legacy API Probing')
        .respond({ template: 'fake_deprecated_api_response' });

    ts.trap('/api/v1/profile')
        .methods('GET', 'POST')
        .intent('Legacy API Probing')
        .respond({ template: 'fake_deprecated_api_response' });

    // Watches
    ts.watch('/auth/register')
        .body('role', { defaultValue: 'user', intent: 'Privilege Escalation (role)' })
        .body('credits', { defaultValue: 0, intent: 'Credit Manipulation' });

    ts.watch('/api/v2/profile')
        .body('is_admin', { intent: 'Privilege Escalation' });

    ts.watch('/api/v2/orders/:id')
        .query('discount_code', { defaultValue: 'NONE', intent: 'Coupon Tampering' });

    ts.watch('/api/v2/echo/query')
        .query('honey_q', { intent: 'Query Field Test' })
        .query('role_q', { defaultValue: 'user', intent: 'Query Default Test' });

    ts.watch('/api/v2/echo/body')
        .body('honey_b', { intent: 'Body Field Test' })
        .body('role_b', { defaultValue: 'user', intent: 'Body Default Test' });

    ts.watch('/api/v2/echo/form')
        .body('honey_f', { intent: 'Form Field Test' });

    ts.watch('/api/v2/echo/multipart')
        .body('honey_m', { intent: 'Multipart Field Test' });

    if (values.otel) {
        ts.add_otel();
    }

    if (values.webhook) {
        ts.add_webhook(values.webhook, { alerts_only: false });
    }

    app.listen(8000, '0.0.0.0', () => {
        console.log('KoaApp listening on http://127.0.0.1:8000');
    });
}

bootstrap();

