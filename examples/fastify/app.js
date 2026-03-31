const path = require('path');
const { parseArgs } = require('node:util');
const fastify = require('fastify')({ logger: false });
const trappsec = require('../../packages/node/src/index');

async function bootstrap() {
    const options = {
        otel: { type: 'boolean' },
        webhook: { type: 'string' },
    };

    const { values } = parseArgs({ options, strict: false });

    await fastify.register(require('@fastify/formbody'));
    await fastify.register(require('@fastify/static'), {
        root: path.join(__dirname, '../lure-frontend'),
        prefix: '/',
    });

    const ts = new trappsec.Sentry(fastify, 'FastifyApp', 'Development');

    ts.default_responses.unauthenticated = {
        status_code: 401,
        response_body: { error: 'authentication required' },
        mime_type: 'application/json',
    };

    ts.identify_user((req) => {
        if (req.headers['x-user-id']) {
            return {
                user: req.headers['x-user-id'],
                role: req.headers['x-user-role'] || 'user',
            };
        }
        return null;
    });

    ts.override_source_ip((req) => req.headers['x-real-ip'] || req.ip || req.socket?.remoteAddress || '0.0.0.0');

    // Legitimate routes
    fastify.post('/auth/register', async (req) => {
        const email = req.body?.email || null;
        return { status: 'registered', email };
    });

    fastify.get('/api/v2/profile', async (req) => {
        const name = req.headers['x-user-id'];
        return { name, is_admin: false };
    });

    fastify.post('/api/v2/profile', async (req) => {
        const name = req.headers['x-user-id'];
        return { name, status: 'updated' };
    });

    fastify.get('/api/v2/orders', async () => ({
        orders: [
            { id: 'ord-123', item: 'Laptop', amount: 1200 },
            { id: 'ord-124', item: 'Mouse', amount: 45 },
        ]
    }));

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

    if (values.otel) {
        ts.add_otel();
    }

    if (values.webhook) {
        ts.add_webhook(values.webhook);
    }

    await fastify.listen({ port: 8000, host: '0.0.0.0' });
    console.log('FastifyApp listening on http://127.0.0.1:8000');
}

bootstrap();
