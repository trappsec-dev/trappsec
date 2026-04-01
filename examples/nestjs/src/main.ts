import { NestFactory } from '@nestjs/core';
import { FastifyAdapter, NestFastifyApplication } from '@nestjs/platform-fastify';
import { NestExpressApplication } from '@nestjs/platform-express';
import { AppModule } from './app.module';
import trappsec from '../../../packages/node/src/index';
import { parseArgs } from 'node:util';

async function bootstrap() {
    const options = {
        otel: { type: 'boolean' },
        webhook: { type: 'string' },
        fastify: { type: 'boolean' },
    } as const;

    const { values } = parseArgs({ options, strict: false });

    let app;
    if (values.fastify) {
        app = await NestFactory.create<NestFastifyApplication>(
            AppModule,
            new FastifyAdapter({ trustProxy: false })
        );
        await app.register(require('@fastify/multipart'), {
            attachFieldsToBody: 'keyValues',
        });
    } else {
        app = await NestFactory.create<NestExpressApplication>(AppModule);
    }

    // trappsec initialization
    const ts = new trappsec.Sentry(app, "NestJSApp", "Development");

    if (values.otel) {
        ts.add_otel();
    }

    if (values.webhook) {
        ts.add_webhook(values.webhook as string, { alerts_only: false });
    }

    ts.identify_user((req) => {
        const headers = req.headers;
        if (headers['x-user-id']) {
            return {
                user: headers['x-user-id'],
                role: headers['x-user-role'] || 'user'
            };
        }
        return null;
    });

    ts.override_source_ip((req) => {
        const headers = req.headers;
        return headers['x-real-ip'] || req.ip || req.socket.remoteAddress;
    });

    // Explicitly setting default unauthenticated response via direct object access 
    ts.default_responses.unauthenticated.response_body = { "error": "authentication required" };


    // 4. Decoy Routes (Traps)

    // 4.1 Static
    ts.trap("/deployment/config")
        .methods("GET")
        .intent("Reconnaissance")
        .respond({ status: 200, body: { "region": "us-east-1", "deployment_type": "production" } });

    // 4.2 Dynamic
    ts.trap("/deployment/metrics")
        .methods("GET")
        .intent("Reconnaissance")
        .respond({
            status: 200,
            body: (req) => {
                const cpu = Math.floor(Math.random() * (95 - 5 + 1) + 5) + "%";
                const memory = Math.floor(Math.random() * (90 - 20 + 1) + 20) + "%";
                return { cpu, memory };
            }
        });

    // 4.3 Templates
    ts.template("fake_deprecated_api_response", 410, { "error": "Gone", "message": "API v1 has been deprecated" });

    // 4.4 Templated Routes methods
    ts.trap("/api/v1/orders")
        .methods("GET", "POST")
        .intent("Legacy API Probing")
        .respond({ template: "fake_deprecated_api_response" });

    ts.trap("/api/v1/profile")
        .methods("GET", "POST")
        .intent("Legacy API Probing")
        .respond({ template: "fake_deprecated_api_response" });

    // 5. Watch Rules

    // 5.1 /auth/register
    ts.watch("/auth/register")
        .body("role", { defaultValue: "user", intent: "Privilege Escalation (role)" })
        .body("credits", { defaultValue: 0, intent: "Credit Manipulation" });

    // 5.2 /api/v2/profile
    ts.watch("/api/v2/profile")
        .body("is_admin", { intent: "Privilege Escalation" });

    // 5.3 /api/v2/orders/:id
    ts.watch("/api/v2/orders/:id")
        .query("discount_code", { defaultValue: "NONE", intent: "Coupon Tampering" });

    // 5.4 Echo routes for field stripping verification
    ts.watch("/api/v2/echo/query")
        .query("honey_q", { intent: "Query Field Test" })
        .query("role_q", { defaultValue: "user", intent: "Query Default Test" });

    ts.watch("/api/v2/echo/body")
        .body("honey_b", { intent: "Body Field Test" })
        .body("role_b", { defaultValue: "user", intent: "Body Default Test" });

    ts.watch("/api/v2/echo/form")
        .body("honey_f", { intent: "Form Field Test" });

    ts.watch("/api/v2/echo/multipart")
        .body("honey_m", { intent: "Multipart Field Test" });

    await app.listen(8000, '0.0.0.0');
    console.log(`NestJSApp listening on port 8000 (Driver: ${values.fastify ? 'Fastify' : 'Express'})`);
}
bootstrap();

