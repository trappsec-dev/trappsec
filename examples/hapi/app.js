const Hapi = require('@hapi/hapi');
const Path = require('path');
const Inert = require('@hapi/inert');
const { parseArgs } = require('node:util');
const trappsec = require('../../packages/node/src/index');

async function bootstrap() {
    const options = {
        otel: { type: 'boolean' },
        webhook: { type: 'string' },
    };

    const { values } = parseArgs({ options, strict: false });

    const server = Hapi.server({
        port: 8000,
        host: '0.0.0.0',
        routes: {
            payload: {
                parse: true,
                output: 'data',
                allow: ['application/json', 'application/x-www-form-urlencoded', 'multipart/form-data']
            }
        }
    });

    await server.register(Inert);

    const ts = new trappsec.Sentry(server, 'HapiApp', 'Development');

    ts.default_responses.unauthenticated = {
        status_code: 401,
        response_body: { error: 'authentication required' },
        mime_type: 'application/json',
    };

    ts.identify_user((request) => {
        if (request.headers['x-user-id']) {
            return {
                user: request.headers['x-user-id'],
                role: request.headers['x-user-role'] || 'user',
            };
        }
        return null;
    });

    ts.override_source_ip((request) => request.headers['x-real-ip'] || request.info.remoteAddress || '0.0.0.0');

    // Legitimate routes
    server.route({
        method: 'POST',
        path: '/auth/register',
        handler: (request) => {
            const email = request.payload?.email || null;
            return { status: 'registered', email };
        }
    });

    server.route({
        method: 'GET',
        path: '/api/v2/profile',
        handler: (request) => {
            const name = request.headers['x-user-id'];
            return { name, is_admin: false };
        }
    });

    server.route({
        method: 'POST',
        path: '/api/v2/profile',
        handler: (request) => {
            const name = request.headers['x-user-id'];
            return { name, status: 'updated' };
        }
    });

    server.route({
        method: 'GET',
        path: '/api/v2/orders',
        handler: () => ({
            orders: [
                { id: 'ord-123', item: 'Laptop', amount: 1200 },
                { id: 'ord-124', item: 'Mouse', amount: 45 },
            ],
        })
    });

    // Static lure frontend
    server.route({
        method: 'GET',
        path: '/{path*}',
        handler: {
            directory: {
                path: Path.join(__dirname, '../lure-frontend'),
                index: ['index.html']
            }
        }
    });

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

    await server.start();
    console.log('HapiApp listening on http://127.0.0.1:8000');
}

bootstrap();
