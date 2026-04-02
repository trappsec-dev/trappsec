import { NodeSDK } from '@opentelemetry/sdk-node';
import { ExportResultCode, hrTimeToMicroseconds } from '@opentelemetry/core';
import { HttpInstrumentation } from '@opentelemetry/instrumentation-http';
import { ExpressInstrumentation } from '@opentelemetry/instrumentation-express';
import { FastifyInstrumentation } from '@opentelemetry/instrumentation-fastify';
import { NestInstrumentation } from '@opentelemetry/instrumentation-nestjs-core';

class CompactConsoleSpanExporter {
    export(spans: any[], resultCallback: (result: { code: number }) => void): void {
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

    shutdown(): Promise<void> {
        return this.forceFlush();
    }

    forceFlush(): Promise<void> {
        return Promise.resolve();
    }
}

export function setupOpentelemetry(useFastify: boolean): void {
    const sdk = new NodeSDK({
        traceExporter: new CompactConsoleSpanExporter(),
        instrumentations: [
            new HttpInstrumentation(),
            new NestInstrumentation(),
            useFastify ? new FastifyInstrumentation() : new ExpressInstrumentation(),
        ],
    });

    sdk.start();
}
