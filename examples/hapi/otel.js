function setupOpentelemetry() {
    const { NodeSDK } = require('@opentelemetry/sdk-node');
    const { ConsoleSpanExporter } = require('@opentelemetry/sdk-trace-node');
    const { HttpInstrumentation } = require('@opentelemetry/instrumentation-http');
    const { HapiInstrumentation } = require('@opentelemetry/instrumentation-hapi');

    const sdk = new NodeSDK({
        traceExporter: new ConsoleSpanExporter(),
        instrumentations: [
            new HttpInstrumentation(),
            new HapiInstrumentation(),
        ],
    });

    sdk.start();
}

module.exports = { setupOpentelemetry };
