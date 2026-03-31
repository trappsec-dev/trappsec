const test = require("node:test");
const assert = require("node:assert/strict");

const { Sentry } = require("../src/core");
const { TrapBuilder, WatchBuilder } = require("../src/builders");

function makeCoreHarness({ identity, requestContext }) {
  const ts = Object.create(Sentry.prototype);
  ts.identity = identity;
  ts.requestContext = requestContext;
  ts.captured = [];
  ts._trigger = (event) => ts.captured.push(event);
  return ts;
}

test("trigger watch event emits signal payload", () => {
  const ts = makeCoreHarness({
    identity: { ip: () => "1.2.3.4", auth: null },
    requestContext: { path: () => "/a", userAgent: () => "ua", method: () => "GET" },
  });

  ts._trigger_watch_event({}, [{ field: "x" }]);

  assert.equal(ts.captured.length, 1);
  assert.equal(ts.captured[0].event, "trappsec.watch_hit");
  assert.equal(ts.captured[0].type, "signal");
  assert.equal(ts.captured[0].path, "/a");
});

test("trigger trap event uses authenticated response when user exists", () => {
  const ts = makeCoreHarness({
    identity: { ip: () => "1.2.3.4", auth: () => ({ user: "u1", role: "admin" }) },
    requestContext: { path: () => "/trap", userAgent: () => "ua", method: () => "POST" },
  });

  const trap = {
    intent: "Recon",
    "response.authenticated": { status_code: 201, response_body: { ok: true }, mime_type: "application/json" },
    "response.unauthenticated": { status_code: 401, response_body: { ok: false }, mime_type: "application/json" },
  };

  const { response_body, response_config } = ts._trigger_trap_event({}, trap);

  assert.equal(response_config.status_code, 201);
  assert.match(response_body, /"ok":true/);
  assert.equal(ts.captured[0].type, "alert");
  assert.equal(ts.captured[0].event, "trappsec.trap_hit");
});

test("trap builder applies explicit and template responses", () => {
  const ts = {
    default_responses: {
      authenticated: { status_code: 200, response_body: {}, mime_type: "application/json" },
      unauthenticated: { status_code: 401, response_body: {}, mime_type: "application/json" },
    },
    _templates: {
      gone: { status_code: 410, response_body: { error: "gone" }, mime_type: "application/json" },
    },
  };

  const cfg = new TrapBuilder(ts, "/trap")
    .methods("PUT")
    .intent("Recon")
    .respond({ status: 418, body: { x: 1 }, mime_type: "application/json" })
    .if_unauthenticated({ template: "gone" })
    .build();

  assert.deepEqual(cfg.methods, ["PUT"]);
  assert.equal(cfg.intent, "Recon");
  assert.equal(cfg["response.authenticated"].status_code, 418);
  assert.equal(cfg["response.unauthenticated"].status_code, 410);
});

test("watch builder emits expected shape", () => {
  const cfg = new WatchBuilder("/login")
    .query("role", { defaultValue: "user", intent: "x" })
    .body("token", { intent: "y" })
    .build();

  assert.equal(cfg.path, "/login");
  assert.equal(cfg.query_fields.role.default, "user");
  assert.equal(cfg.body_fields.token.intent, "y");
});
