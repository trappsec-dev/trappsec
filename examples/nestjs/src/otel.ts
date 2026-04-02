import { NodeSDK } from '@opentelemetry/sdk-node';
import { ConsoleSpanExporter } from '@opentelemetry/sdk-trace-node';
import { HttpInstrumentation } from '@opentelemetry/instrumentation-http';
import { ExpressInstrumentation } from '@opentelemetry/instrumentation-express';
import { FastifyInstrumentation } from '@opentelemetry/instrumentation-fastify';
import { NestInstrumentation } from '@opentelemetry/instrumentation-nestjs-core';

export function setupOpentelemetry(useFastify: boolean): void {
    const sdk = new NodeSDK({
        traceExporter: new ConsoleSpanExporter(),
        instrumentations: [
            new HttpInstrumentation(),
            new NestInstrumentation(),
            useFastify ? new FastifyInstrumentation() : new ExpressInstrumentation(),
        ],
    });

    sdk.start();
}
