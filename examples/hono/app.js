const { parseArgs } = require('node:util');

const options = {
    otel: { type: 'boolean' },
    webhook: { type: 'string' },
};

const { values } = parseArgs({ options, strict: false });

if (values.otel) {
    require('./otel').setupOpentelemetry();
}

const { Hono } = require('hono');
const { serve } = require('@hono/node-server');
const { serveStatic } = require('@hono/node-server/serve-static');
const path = require('path');
const trappsec = require('../../packages/node/src/index');

const app = new Hono();

// Install trappsec before serve(): it hooks app.fetch.
const ts = new trappsec.Sentry(app, 'HonoApp', 'Development');

ts.default_unauthenticated_response({ status: 401, body: { error: 'authentication required' } });

ts.identify_user((c) => {
    const user = c.req.header('x-user-id');
    return user ? { user, role: c.req.header('x-user-role') || 'user' } : null;
});

ts.override_source_ip((c) => c.req.header('x-real-ip') || c.env?.incoming?.socket?.remoteAddress || '0.0.0.0');

// Legitimate routes
app.post('/auth/register', async (c) => {
    const isJson = c.req.header('content-type')?.includes('json');
    const body = await (isJson ? c.req.json() : c.req.parseBody()).catch(() => ({}));
    return c.json({ status: 'registered', email: body.email || null });
});

const v2 = new Hono();
v2.get('/profile', (c) => c.json({ name: c.req.header('x-user-id'), is_admin: false }));
v2.post('/profile', (c) => c.json({ name: c.req.header('x-user-id'), status: 'updated' }));
v2.get('/orders', (c) => c.json({
    orders: [
        { id: 'ord-123', item: 'Laptop', amount: 1200 },
        { id: 'ord-124', item: 'Mouse', amount: 45 },
    ],
}));
v2.get('/orders/:id', (c) => c.json({ id: c.req.param('id'), item: 'Laptop', amount: 1200, status: 'shipped' }));
v2.get('/echo/query', (c) => c.json(c.req.query()));
v2.post('/echo/body', async (c) => c.json(await c.req.json().catch(() => ({}))));
v2.post('/echo/form', async (c) => c.json(await c.req.parseBody()));
v2.post('/echo/multipart', async (c) => {
    const fields = {};
    for (const [k, v] of Object.entries(await c.req.parseBody())) {
        if (typeof v === 'string') fields[k] = v;
    }
    return c.json(fields);
});
// Sub-app routes are watched by their full path (/api/v2/...).
app.route('/api/v2', v2);

// Lure frontend. Traps are matched before this catch-all.
const frontend = path.relative(process.cwd(), path.join(__dirname, '../lure-frontend'));
app.get('*', serveStatic({ root: frontend }));

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
    .body('role', { default: 'user', intent: 'Privilege Escalation (role)' })
    .body('credits', { default: 0, intent: 'Credit Manipulation' });

ts.watch('/api/v2/profile')
    .body('is_admin', { intent: 'Privilege Escalation' });

ts.watch('/api/v2/orders/:id')
    .query('discount_code', { default: 'NONE', intent: 'Coupon Tampering' });

ts.watch('/api/v2/echo/query')
    .query('honey_q', { intent: 'Query Field Test' })
    .query('role_q', { default: 'user', intent: 'Query Default Test' });

ts.watch('/api/v2/echo/body')
    .body('honey_b', { intent: 'Body Field Test' })
    .body('role_b', { default: 'user', intent: 'Body Default Test' });

ts.watch('/api/v2/echo/form')
    .body('honey_f', { intent: 'Form Field Test' });

ts.watch('/api/v2/echo/multipart')
    .body('honey_m', { intent: 'Multipart Field Test' });

if (values.otel) {
    ts.add_otel();
}

if (values.webhook) {
    ts.add_webhook(values.webhook, { secret: process.env.TRAPPSEC_WEBHOOK_SECRET || null, alerts_only: false });
}
if (process.env.TRAPPSEC_ALERTS_WEBHOOK) {  // second receiver with the default alerts_only: true
    ts.add_webhook(process.env.TRAPPSEC_ALERTS_WEBHOOK, { secret: process.env.TRAPPSEC_WEBHOOK_SECRET || null });
}

// Flush queued webhook/Slack deliveries before exiting.
for (const sig of ['SIGINT', 'SIGTERM']) {
    process.once(sig, async () => { await ts.close(); process.exit(0); });
}

const port = Number(process.env.PORT || 8000);
serve({ fetch: app.fetch, port, hostname: '0.0.0.0' }, () => {
    console.log('HonoApp listening on http://127.0.0.1:' + port);
});
