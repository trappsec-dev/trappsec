function setupOpentelemetry() {
    const { NodeSDK } = require('@opentelemetry/sdk-node');
    const { ExportResultCode, hrTimeToMicroseconds } = require('@opentelemetry/core');
    const { HttpInstrumentation } = require('@opentelemetry/instrumentation-http');
    const { KoaInstrumentation } = require('@opentelemetry/instrumentation-koa');

    class CompactConsoleSpanExporter {
        export(spans, resultCallback) {
            for (const span of spans) {
                const payload = {
                    resource: { attributes: span.resource.attributes },
                    instrumentationScope: span.instrumentationLibrary,
                    traceId: span.spanContext().traceId,
                    parentId: span.parentSpanId,
                    traceState: span.spanContext().traceState?.serialize(),
                    name: span.name,
                    id: span.spanContext().spanId,
                    kind: span.kind,
                    timestamp: hrTimeToMicroseconds(span.startTime),
                    duration: hrTimeToMicroseconds(span.duration),
                    attributes: span.attributes,
                    status: span.status,
                    events: span.events,
                    links: span.links,
                };
                process.stdout.write(`${JSON.stringify(payload)}\n`);
            }
            resultCallback({ code: ExportResultCode.SUCCESS });
        }

        shutdown() {
            return this.forceFlush();
        }

        forceFlush() {
            return Promise.resolve();
        }
    }

    const sdk = new NodeSDK({
        traceExporter: new CompactConsoleSpanExporter(),
        instrumentations: [
            new HttpInstrumentation(),
            new KoaInstrumentation(),
        ],
    });

    sdk.start();
}

module.exports = { setupOpentelemetry };
