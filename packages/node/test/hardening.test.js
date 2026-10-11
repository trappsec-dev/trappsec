// Depth limits, synchronous-callback guard, serializer and webhook option checks.
const test = require("node:test");
const assert = require("node:assert/strict");

const { Sentry, values_match, safe_value } = require("../src/core");
const { WatchBuilder, NO_DEFAULT } = require("../src/builders");
const { WebhookHandler, safeStringify } = require("../src/handlers");

function logged() {
  const logs = { error: [], warn: [] };
  return { logs, logger: { error: (...a) => logs.error.push(a), warn: (...a) => logs.warn.push(a), info() {}, log() {} } };
}

function harness(over = {}) {
  const ts = Object.create(Sentry.prototype);
  const { logs, logger } = logged();
  ts.logger = logger;
  ts.logs = logs;
  ts.identity = over.identity || { ip: null, auth: null };
  ts.request = { path: () => "/p", user_agent: () => "ua", method: () => "GET" };
  return ts;
}

const nest = (n, leaf) => { let v = leaf; for (let i = 0; i < n; i++) v = [v]; return v; };
const tick = () => new Promise((r) => setImmediate(r));

test("deep values neither match nor overflow the stack", () => {
  assert.equal(values_match(nest(32, 1), nest(32, 1)), true);
  assert.equal(values_match(nest(33, 1), nest(33, 1)), false);
  assert.equal(values_match(nest(5000, 1), nest(5000, 1)), false);
  assert.equal(safe_value(nest(5000, 1)).flat(Infinity).length, 1);
  let o = { leaf: 1 };
  for (let i = 0; i < 5000; i++) o = { o };
  assert.match(safe_value(o), /<nested>/);
  assert.match(safe_value([o])[0], /<nested>/);
});

test("safeStringify: shared references are not circular; cycles are", () => {
  const x = { n: 1 };
  assert.equal(safeStringify({ a: x, b: x, c: [x, x] }), '{"a":{"n":1},"b":{"n":1},"c":[{"n":1},{"n":1}]}');
  const c = { name: "c" };
  c.self = c;
  assert.equal(safeStringify(c), '{"name":"c","self":"[Circular]"}');
  assert.equal(safeStringify({ a: undefined, b: () => 1, n: NaN, big: 10n, d: new Date(0) }), '{"n":null,"big":"10","d":"1970-01-01T00:00:00.000Z"}');
});

test("safeStringify sortKeys: code point order, integer-like keys included", () => {
  assert.equal(
    safeStringify({ 9: 2, 10: 1, a: 3, "～": 4, "\u{1F600}": 5 }, { sortKeys: true }),
    '{"10":1,"9":2,"a":3,"～":4,"\u{1F600}":5}',
  );
});

test("async callbacks are not awaited, never crash, and use the fallback", async () => {
  const ts = harness({ identity: { ip: async () => { throw new Error("ip"); }, auth: async () => ({ user: "bob", role: "admin" }) } });
  ts._default_ip = () => "9.9.9.9";
  const ctx = ts._get_identity_context({});
  assert.equal(ctx.user, null);
  assert.equal(ctx.ip, "9.9.9.9");
  ts._get_identity_context({});
  assert.equal(ts.logs.error.filter((a) => /must be synchronous/.test(a[0])).length, 2); // once per kind
  await tick(); // rejections were handled: no unhandledRejection
  assert.ok(ts.logs.error.some((a) => /rejected/.test(a[0])));

  const wb = new WatchBuilder("/x").body("f", { default: async () => "v" }).build();
  const out = ts._detect_honey_fields({ f: "v" }, wb.body_fields, {}, "body");
  assert.equal(out.found_fields.length, 1); // callable default ignored: no default
  assert.notEqual(wb.body_fields.f.default, NO_DEFAULT);

  const trap = {
    intent: null,
    "response.authenticated": { response_body: {}, mime_type: "application/json" },
    "response.unauthenticated": { response_body: async () => ({ a: 1 }), mime_type: "application/json" },
  };
  ts._trigger = () => {};
  ts._base_event = () => ({ type: "signal" });
  assert.equal(ts._trigger_trap_event({}, trap).response_body, "{}");
});

test("async webhook template drops the event", async () => {
  const { logs, logger } = logged();
  const h = new WebhookHandler("http://127.0.0.1:1/x", { alerts_only: false, template: async () => ({ a: 1 }) });
  h.logger = logger;
  let sent = 0;
  h._send = () => { sent++; };
  h.emit({ type: "alert" });
  h.emit({ type: "alert" });
  assert.equal(sent, 0);
  assert.equal(logs.error.filter((a) => /must be synchronous/.test(a[0])).length, 1);
  await h.close();
});

test("webhook heartbeat_interval: only finite positive numbers start a timer", async () => {
  for (const bad of [-1, 0, NaN, Infinity, "5"]) {
    const h = new WebhookHandler("http://127.0.0.1:1/x", { heartbeat_interval: bad });
    assert.equal(h._timer, null, String(bad));
    await h.close();
  }
  const ok = new WebhookHandler("http://127.0.0.1:1/x", { heartbeat_interval: 3e9 }); // clamped, not 1 ms
  assert.ok(ok._timer);
  assert.equal(ok._timer._idleTimeout, 2 ** 31 - 1);
  await ok.close();
});

test("webhook with an invalid URL is rejected once, not retried per event", async () => {
  const h = new WebhookHandler("not a url", { alerts_only: false });
  const { logs, logger } = logged();
  let calls = 0;
  h._deliver = async () => { calls++; };
  h.logger = logger;
  h.emit({ type: "alert" });
  assert.equal(calls, 0);
  await h.close();
});

test("is_trap index follows added traps and changed methods", () => {
  const ts = harness();
  ts._traps = [];
  ts._templates = Object.create(null);
  ts.default_responses = { authenticated: {}, unauthenticated: {} };
  const req = (method, path) => ({ method, path });
  ts.request = { path: (r) => r.path, method: (r) => r.method, user_agent: () => null };
  assert.equal(ts.is_trap(req("GET", "/a")), false);
  const b = ts.trap("/a").methods("GET");
  assert.equal(ts.is_trap(req("GET", "/a")), true);
  b.methods("POST");
  assert.equal(ts.is_trap(req("GET", "/a")), false);
  assert.equal(ts.is_trap(req("POST", "/a")), true);
});
