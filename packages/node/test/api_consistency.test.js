// The Node API mirrors Python's names, units and option shapes; the pre-0.3
// spellings keep working.
const test = require("node:test");
const assert = require("node:assert/strict");

const { Sentry } = require("../src/core");
const { WatchBuilder, NO_DEFAULT } = require("../src/builders");

const quiet = { error() {}, warn() {}, info() {}, log() {} };

function harness() {
  const ts = Object.create(Sentry.prototype);
  ts.logger = quiet;
  ts.identity = { ip: () => "1.1.1.1", auth: null };
  ts.request = { path: () => "/p", user_agent: () => "ua", method: () => "GET" };
  ts.captured = [];
  ts._trigger = (e) => ts.captured.push(e);
  ts._traps = [];
  ts._handlers = [];
  ts._templates = Object.create(null);
  ts.default_responses = {
    authenticated: { status_code: 200, response_body: {}, mime_type: "application/json" },
    unauthenticated: { status_code: 401, response_body: {}, mime_type: "application/json" },
  };
  return ts;
}

test("watch fields take `default`, and `defaultValue` still works", () => {
  const w = new WatchBuilder("/x")
    .body("a", { default: false, intent: "PrivEsc" })
    .body("b", { defaultValue: "x" })
    .body("c", { default: null })
    .query("d")
    .query("e", { intent: "Recon" })
    .build();
  assert.deepEqual(w.body_fields.a, { default: false, intent: "PrivEsc" });
  assert.deepEqual(w.body_fields.b, { default: "x", intent: null });
  assert.deepEqual(w.body_fields.c, { default: null, intent: null });
  assert.equal(w.query_fields.d.default, NO_DEFAULT);
  assert.deepEqual(w.query_fields.e, { default: NO_DEFAULT, intent: "Recon" });
});

test("request is the extractor object; requestContext and userAgent are aliases", () => {
  const ts = harness();
  assert.equal(ts.requestContext, ts.request);
  ts.requestContext = { path: () => "/legacy", userAgent: () => "old-ua", method: () => "POST" };
  assert.equal(ts.request.path(), "/legacy");
  ts.trigger({}, "r");
  assert.equal(ts.captured[0].path, "/legacy");
  assert.equal(ts.captured[0].user_agent, "old-ua");
});

test("trigger takes { intent, metadata }, and the positional form still works", () => {
  const ts = harness();
  ts.trigger({}, "opts", { intent: "fraud", metadata: { amount: 5 } });
  ts.trigger({}, "positional", "fraud", { amount: 6 });
  ts.trigger({}, "bare");
  assert.deepEqual(ts.captured.map((e) => [e.reason, e.intent, e.metadata]), [
    ["opts", "fraud", { amount: 5 }],
    ["positional", "fraud", { amount: 6 }],
    ["bare", null, null],
  ]);
});

test("default_response and default_unauthenticated_response work like respond", () => {
  const ts = harness();
  const trap = ts.trap("/t");
  ts.default_response({ body: { ok: true } });
  ts.default_unauthenticated_response({ status: 403, body: "no", mime_type: "text/plain" });
  const cfg = trap.build();
  assert.deepEqual(cfg["response.authenticated"], { status_code: 200, response_body: { ok: true }, mime_type: "application/json" });
  assert.deepEqual(cfg["response.unauthenticated"], { status_code: 403, response_body: "no", mime_type: "text/plain" });

  ts.template("gone", 410, { error: "gone" });
  ts.default_unauthenticated_response({ template: "gone" });
  assert.equal(ts.trap("/u").build()["response.unauthenticated"].status_code, 410);
  assert.throws(() => ts.default_response({ template: "missing" }), /not found/);
  assert.throws(() => ts.default_response({ template: "gone", status: 200 }), /cannot be used together/);
});

test("close(timeout) is in seconds; large values are read as milliseconds", async () => {
  const seen = [];
  const ts = harness();
  ts._handlers = [{ close: async (ms) => { seen.push(ms); } }];
  await ts.close();
  await ts.close(2);
  await ts.close(0.5);
  await ts.close(3000);
  assert.deepEqual(seen, [5000, 2000, 500, 3000]);
});
