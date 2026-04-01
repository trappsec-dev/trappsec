export const NO_DEFAULT: unique symbol;

export interface ResponseConfig {
    status?: number;
    body?: any;
    mime_type?: string;
    template?: string;
}

export class TrapBuilder {
    methods(...args: string[]): this;
    intent(intent: string): this;
    respond(config: ResponseConfig): this;
    if_unauthenticated(config: ResponseConfig): this;
    build(): any;
}

export class WatchBuilder {
    query(name: string, config?: { defaultValue?: any; intent?: string }): this;
    body(name: string, config?: { defaultValue?: any; intent?: string }): this;
    build(): any;
}

export interface RequestContext {
    path: (req: any) => string | null;
    userAgent: (req: any) => string | null;
    method: (req: any) => string | null;
}

export interface IdentityContext {
    ip: ((req: any) => string | null) | null;
    auth: ((req: any) => { user: string; role?: string } | null) | null;
}

export class Sentry {
    constructor(app: any, service: string, environment: string);

    default_responses: {
        authenticated: any;
        unauthenticated: any;
    };

    identity: IdentityContext;
    requestContext: RequestContext;

    template(name: string, statusCode: number, responseBody: any, mimeType?: string): this;
    trap(path: string): TrapBuilder;
    watch(path: string): WatchBuilder;
    add_webhook(url: string, options?: { secret?: string; headers?: any; heartbeat_interval?: number; template?: any; alerts_only?: boolean }): this;
    add_otel(): this;
    identify_user(callback: (req: any) => { user: string; role?: string } | null): this;
    override_source_ip(callback: (req: any) => string | null): this;
}
