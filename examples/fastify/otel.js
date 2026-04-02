function setupOpentelemetry() {
    const { NodeSDK } = require('@opentelemetry/sdk-node');
    const { ConsoleSpanExporter } = require('@opentelemetry/sdk-trace-node');
    const { HttpInstrumentation } = require('@opentelemetry/instrumentation-http');
    const { FastifyInstrumentation } = require('@opentelemetry/instrumentation-fastify');

    const sdk = new NodeSDK({
        traceExporter: new ConsoleSpanExporter(),
        instrumentations: [
            new HttpInstrumentation(),
            new FastifyInstrumentation(),
        ],
    });

    sdk.start();
}

module.exports = { setupOpentelemetry };
