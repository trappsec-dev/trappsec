export const NO_DEFAULT: unique symbol;

export interface ResponseConfig {
    status?: number;
    body?: any | ((req: any) => any);
    mime_type?: string;
    template?: string;
}

export interface ResolvedResponse {
    status_code: number;
    response_body: any;
    mime_type: string;
}

export interface TrapConfig {
    path: string;
    methods: string[];
    intent: string | null;
    "response.authenticated": ResolvedResponse;
    "response.unauthenticated": ResolvedResponse;
}

export interface FieldRule {
    default: any;
    intent: string | null;
}

export interface WatchConfig {
    path: string;
    query_fields: Record<string, FieldRule>;
    body_fields: Record<string, FieldRule>;
}

export interface FieldOptions {
    /** Expected value; omit to alert on any presence of the field. */
    default?: any | ((req: any) => any);
    /** @deprecated Use `default`. */
    defaultValue?: any | ((req: any) => any);
    intent?: string | null;
}

export class TrapBuilder {
    constructor(ts: any, path: string);
    methods(...args: string[]): this;
    intent(intent: string): this;
    respond(config?: ResponseConfig): this;
    if_unauthenticated(config?: ResponseConfig): this;
    build(): TrapConfig;
}

export class WatchBuilder {
    constructor(path: string);
    query(name: string, config?: FieldOptions): this;
    body(name: string, config?: FieldOptions): this;
    build(): WatchConfig;
}

export interface FoundField {
    type: "query" | "body";
    field: string;
    value: any;
    intent: string | null;
}

export interface TrappsecEvent {
    timestamp: number;
    event: "trappsec.watch_hit" | "trappsec.trap_hit" | "trappsec.rule_hit";
    type: "alert" | "signal";
    path: string | null;
    method: string | null;
    user_agent: string | null;
    ip: string | null;
    user: string | null;
    role: string | null;
    intent?: string | null;
    reason?: string | null;
    metadata?: Record<string, any> | null;
    found_fields?: FoundField[];
    app: { service: string; environment: string; hostname: string };
}

export interface WebhookOptions {
    /** HMAC-SHA256 secret. Signs `<timestamp>.<body>`; see x-trappsec-timestamp / x-trappsec-signature. */
    secret?: string | null;
    headers?: Record<string, string> | null;
    /** Seconds between heartbeats. */
    heartbeat_interval?: number | null;
    /** Transform an event into the payload. Throwing drops the event. */
    template?: ((event: TrappsecEvent) => object | null) | null;
    alerts_only?: boolean;
}

export interface RequestContext {
    path: (req: any) => string | null;
    user_agent: (req: any) => string | null;
    /** @deprecated Use `user_agent`. */
    userAgent?: (req: any) => string | null;
    method: (req: any) => string | null;
}

export interface TriggerOptions {
    intent?: string | null;
    metadata?: Record<string, any> | null;
}

export interface IdentityResult {
    user: string | null;
    role?: string | null;
}

export interface IdentityContext {
    ip: ((req: any) => string | null) | null;
    auth: ((req: any) => IdentityResult | null) | null;
}

export class Sentry {
    constructor(app: any, service: string, environment: string);

    default_responses: {
        authenticated: ResolvedResponse;
        unauthenticated: ResolvedResponse;
    };

    identity: IdentityContext;
    request: RequestContext;
    /** @deprecated Use `request`. */
    requestContext: RequestContext;
    integration?: any;

    readonly traps: TrapConfig[];
    readonly watches: WatchConfig[];

    /** Default response for authenticated requests to traps without `respond`. Same options as `respond`. */
    default_response(config?: ResponseConfig): this;
    /** Default response for unauthenticated requests to traps without `if_unauthenticated`. */
    default_unauthenticated_response(config?: ResponseConfig): this;
    template(name: string, statusCode: number, responseBody: any, mimeType?: string): this;
    trap(path: string): TrapBuilder;
    watch(path: string): WatchBuilder;
    add_webhook(url: string, options?: WebhookOptions): this;
    add_otel(): this;
    add_slack(url: string, options?: { alerts_only?: boolean }): this;
    identify_user(callback: (req: any) => IdentityResult | null): this;
    override_source_ip(callback: (req: any) => string | null): this;
    /** Emit a trappsec.rule_hit event. Never throws. */
    trigger(req: any, reason: string, options?: TriggerOptions): void;
    /** @deprecated Use `trigger(req, reason, { intent, metadata })`. */
    trigger(req: any, reason: string, intent?: string | null, metadata?: Record<string, any> | null): void;
    /** True when the request targets a trap; use to skip CSRF or similar middleware for traps. */
    is_trap(req: any): boolean;
    /** Idempotent: install traps and watches. */
    bootstrap(): void;
    /** Stop heartbeats and flush in-flight webhook/Slack deliveries. `timeout` in seconds (default 5). */
    close(timeout?: number): Promise<void>;
}
