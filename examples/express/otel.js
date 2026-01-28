function setupOpentelemetry() {
    const { NodeSDK } = require('@opentelemetry/sdk-node');
    const { ConsoleSpanExporter } = require('@opentelemetry/sdk-trace-node');
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

module.exports = { setupOpentelemetry };