function setupOpentelemetry() {
    const { NodeSDK } = require('@opentelemetry/sdk-node');
    const { ConsoleSpanExporter } = require('@opentelemetry/sdk-trace-node');
    const { HttpInstrumentation } = require('@opentelemetry/instrumentation-http');
    const { KoaInstrumentation } = require('@opentelemetry/instrumentation-koa');

    const sdk = new NodeSDK({
        traceExporter: new ConsoleSpanExporter(),
        instrumentations: [
            new HttpInstrumentation(),
            new KoaInstrumentation(),
        ],
    });

    sdk.start();
}

module.exports = { setupOpentelemetry };
