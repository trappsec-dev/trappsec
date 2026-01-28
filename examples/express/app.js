const express = require('express');
const trappsec = require('../../packages/node/src/index'); // Importing local package

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const ts = new trappsec.Sentry(app, "ExpressApp", "Development");

// Configuration
ts.default_responses["unauthenticated"] = {
    "status_code": 401,
    "response_body": { "error": "authentication required" },
    "mime_type": "application/json"
};

ts.identify_user((req) => ({
    "user": req.headers["x-user-id"],
    "role": req.headers["x-user-role"]
}));

ts.override_source_ip((req) => req.headers["x-real-ip"] || req.ip);

// Application Routes
app.post("/auth/register", (req, res) => {
    let email = req.body.email;
    res.json({ "status": "registered", "email": email });
});

app.get("/api/v2/profile", (req, res) => {
    const name = req.headers["x-user-id"];
    res.json({ "name": name, "is_admin": false });
});

app.post("/api/v2/profile", (req, res) => {
    const name = req.headers["x-user-id"];
    res.json({ "name": name, "status": "updated" });
});

app.get("/api/v2/users", (req, res) => {
    res.json({
        "users": [
            { "id": 1, "username": "alice", "role": "admin" },
            { "id": 2, "username": "bob", "role": "user" }
        ]
    });
});

// Traps
ts.trap("/deployment/config")
    .methods("GET")
    .intent("Reconnaissance")
    .respond({ status: 200, body: { "region": "us-east-1", "deployment_type": "production" } });

ts.trap("/deployment/metrics")
    .methods("GET")
    .intent("Reconnaissance")
    .respond({
        status: 200,
        body: (req) => ({
            "cpu": `${Math.floor(Math.random() * 90) + 5}%`,
            "memory": `${Math.floor(Math.random() * 70) + 20}%`
        })
    });

ts.template("fake_deprecated_api_response", 410, { "error": "Gone", "message": "API v1 has been deprecated" });

ts.trap("/api/v1/users")
    .methods("GET", "POST")
    .intent("Legacy API Probing")
    .respond({ template: "fake_deprecated_api_response" });

ts.trap("/api/v1/profile")
    .methods("GET", "POST")
    .intent("Legacy API Probing")
    .respond({ template: "fake_deprecated_api_response" });

// Watches
ts.watch("/auth/register")
    .body("is_admin", { defaultValue: false, intent: "Privilege Escalation (is_admin)" })
    .body("role", { defaultValue: "user", intent: "Privilege Escalation (role)" })
    .body("credits", { defaultValue: 0, intent: "Credit Manipulation" });

ts.watch("/api/v2/profile")
    .body("is_admin", { intent: "Privilege Escalation" });

function setupOpentelemetry() {
    const { NodeSDK } = require('@opentelemetry/sdk-node');
    const { ConsoleSpanExporter } = require('@opentelemetry/sdk-node');
    const { ExpressInstrumentation } = require('@opentelemetry/instrumentation-express');
    const { HttpInstrumentation } = require('@opentelemetry/instrumentation-http');

    const sdk = new NodeSDK({
        traceExporter: new ConsoleSpanExporter(),
        instrumentations: [
            new HttpInstrumentation(),
            new ExpressInstrumentation(),
        ],
    });

    sdk.start();
}

const { parseArgs } = require('node:util');

const options = {
    otel: { type: 'boolean' },
    webhook: { type: 'string' },
};

const { values } = parseArgs({ options, tokens: false, strict: false });

if (values.otel) {
    setupOpentelemetry();
    ts.add_otel();
}

if (values.webhook) {
    ts.add_webhook(values.webhook);
}

const port = 8000;
app.listen(port, () => {
    console.log(`Starting server on http://127.0.0.1:${port}`);
});
