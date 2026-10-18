// Trap response headers, the per-request response hook and callback fallback (R16, R23).
const test = require("node:test");
const assert = require("node:assert/strict");

const { Sentry } = require("../src/core");
const { decoyFallback } = require("../src/integrations/_common");

class BareSentry extends Sentry {
  _register() {}
}

function make(identity = null) {
  const ts = new BareSentry({}, "svc", "test");
  const errors = [];
  ts.logger = { error: (...a) => errors.push(a.map(String).join(" ")), warn() {}, info() {}, log() {} };
  ts.errors = errors;
  ts._handlers = [];
  ts.request = { path: () => "/t", user_agent: () => null, method: () => "GET" };
  ts.identify_user(() => identity);
  return ts;
}

test("the hook gets the request and the identity", () => {
  const seen = [];
  let ts = make({ user: "bob", role: "owner" });
  const req = {};
  let trap = ts.trap("/t").respond_with((r, ctx) => { seen.push([r, ctx]); return ctx.role === "owner" ? { status: 201 } : null; }).build();
  const out = ts._trigger_trap_event(req, trap);
  assert.equal(out.response_config.status_code, 201);
  assert.equal(out.response_body, "{}");
  assert.equal(seen[0][0], req);
  assert.deepEqual(seen[0][1], { authenticated: true, user: "bob", role: "owner" });

  ts = make();
  trap = ts.trap("/t").respond_with((r, ctx) => { seen.push([r, ctx]); }).build();
  assert.equal(ts._trigger_trap_event({}, trap).response_config.status_code, 401);
  assert.deepEqual(seen[1][1], { authenticated: false, user: null, role: null });
});

for (const result of ["not an object", [1], { status: 99 }, { status: "404" }, { status: 200.5 }, { body: () => "x" },
  { mime_type: 1 }, { headers: { X: 1 } }, { headers: "X" }]) {
  test(`an invalid hook result sends the static response: ${JSON.stringify(result) ?? String(result)}`, () => {
    const ts = make();
    const trap = ts.trap("/t").if_unauthenticated({ status: 403, body: "static" }).respond_with(() => result).build();
    const out = ts._trigger_trap_event({}, trap);
    assert.equal(out.response_config.status_code, 403);
    assert.equal(out.response_body, "static");
    assert.ok(ts.errors.some((e) => /trap response hook failed/.test(e)));
  });
}

test("an async hook is ignored and the static response sent", async () => {
  const ts = make();
  const trap = ts.trap("/t").if_unauthenticated({ status: 403, body: "static" }).respond_with(async () => ({ status: 404 })).build();
  assert.equal(ts._trigger_trap_event({}, trap).response_config.status_code, 403);
  assert.ok(ts.errors.some((e) => /must be synchronous/.test(e)));
});

test("a hook body that cannot be encoded sends the default response", () => {
  const ts = make();
  ts.default_unauthenticated_response({ body: "default" });
  const trap = ts.trap("/t").respond_with(() => ({ status: 404, body: { n: 1n } })).build();
  const out = ts._trigger_trap_event({}, trap);
  assert.equal(out.response_body, "default");
  assert.equal(out.response_config.status_code, 401);
});

test("respond_with rejects non-functions", () => {
  assert.throws(() => make().trap("/t").respond_with("nope"), TypeError);
});

for (const headers of [["X"], "X", { X: 1 }, { X: "a\r\nb" }, { "X\n": "a" }, { "": "a" }, { "X:Y": "a" }, JSON.parse('{"__proto__": "a"}')]) {
  test(`invalid headers fail at configuration time: ${JSON.stringify(headers)}`, () => {
    const ts = make();
    assert.throws(() => ts.trap("/t").respond({ headers }), TypeError);
    assert.throws(() => ts.trap("/t").if_unauthenticated({ headers }), TypeError);
    assert.throws(() => ts.default_response({ headers }), TypeError);
    assert.throws(() => ts.default_unauthenticated_response({ headers }), TypeError);
    assert.throws(() => ts.template("t", 401, {}, "application/json", headers), TypeError);
  });
}

test("templates carry headers and exclude the other options", () => {
  const ts = make();
  ts.template("bearer", 401, { detail: "Not authenticated" }, "application/json", { "WWW-Authenticate": "Bearer" });
  const trap = ts.trap("/t").if_unauthenticated({ template: "bearer" }).build();
  const out = ts._trigger_trap_event({}, trap);
  assert.deepEqual(out.response_config.headers, { "WWW-Authenticate": "Bearer" });
  assert.throws(() => ts.trap("/u").respond({ template: "bearer", headers: { X: "1" } }), /template/);
  assert.throws(() => ts.default_response({ template: "bearer", headers: { X: "1" } }), /template/);
});

test("headers are copied from configuration", () => {
  const ts = make();
  const headers = { Vary: "Accept" };
  const builder = ts.trap("/t").if_unauthenticated({ headers });
  headers.Vary = "changed";
  assert.deepEqual(ts._trigger_trap_event({}, builder.build()).response_config.headers, { Vary: "Accept" });
});

test("decoyFallback keeps headers and never sends an empty object for a function body", () => {
  const ts = make();
  ts.default_unauthenticated_response({ body: "real", headers: { "WWW-Authenticate": "Bearer" } });
  const trap = ts.trap("/t").if_unauthenticated({ body: () => "x", headers: { X: "1" } }).build();
  let out = decoyFallback(ts, trap, {});
  assert.equal(out.response_body, "real");
  assert.deepEqual(out.response_config.headers, { "WWW-Authenticate": "Bearer" });
  out = decoyFallback(ts, null, {});
  assert.equal(out.response_body, "real");
  assert.equal(out.response_config.status_code, 401);
});
