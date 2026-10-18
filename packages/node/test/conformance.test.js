// Shared cross-language cases from tests/conformance (R17, R18).
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const { Sentry, values_match } = require("../src/core");
const { WatchBuilder } = require("../src/builders");

const CONFORMANCE = path.join(__dirname, "..", "..", "..", "tests", "conformance");
function load(name) {
  const file = path.join(CONFORMANCE, name);
  if (!fs.existsSync(file) && !process.env.CI) {
    test(`${name} not found (outside the trappsec repository)`, { skip: true }, () => {});
    return [];
  }
  return JSON.parse(fs.readFileSync(file, "utf8")).cases;
}

// Placeholders: {"$repeat": s, "count": n, "prefix", "suffix"} and
// {"$nest": n, "leaf": x} (x in n one-element lists, built iteratively so a
// 5000-deep fixture cannot overflow the loader's own stack).
function expand(v) {
  if (Array.isArray(v)) return v.map(expand);
  if (v !== null && typeof v === "object") {
    if ("$repeat" in v) return (v.prefix || "") + v.$repeat.repeat(v.count) + (v.suffix || "");
    if ("$nest" in v) {
      let out = expand(v.leaf);
      for (let i = 0; i < v.$nest; i++) out = [out];
      return out;
    }
    return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, expand(x)]));
  }
  return v;
}

const quiet = { error() {}, warn() {}, info() {}, log() {} };
const byField = (a, b) => (a.field < b.field ? -1 : a.field > b.field ? 1 : 0);

for (const c of load("values_match.json")) {
  test(`values_match(${JSON.stringify(c.actual).slice(0, 80)}, ${JSON.stringify(c.expected).slice(0, 80)}) is ${c.match}`, () => {
    assert.equal(values_match(expand(c.actual), expand(c.expected)), c.match);
  });
}

for (const raw of load("detect_honey_fields.json")) {
  const c = expand(raw);
  test(`detect_honey_fields: ${c.name}`, () => {
    const source = c.source || "body";
    const wb = new WatchBuilder("/x");
    for (const [field, rule] of Object.entries(c.rules)) {
      const opts = { intent: rule.intent };
      if (Object.prototype.hasOwnProperty.call(rule, "default")) opts.defaultValue = rule.default;
      wb[source](field, opts);
    }
    const built = wb.build();
    const rules = source === "query" ? built.query_fields : built.body_fields;

    const ts = Object.create(Sentry.prototype);
    ts.logger = quiet;
    const { data, found_fields, touched } = ts._detect_honey_fields(c.data, rules, null, source);

    const expected = c.found.map((f) => ({ type: source, field: f.field, value: f.value, intent: f.intent }));
    assert.deepEqual([...found_fields].sort(byField), expected.sort(byField));
    assert.deepEqual(data, c.result);
    assert.equal(touched, c.touched);
  });
}

test("event keys match tests/conformance/event_keys.json", (t) => {
  const file = path.join(CONFORMANCE, "event_keys.json");
  if (!fs.existsSync(file) && !process.env.CI) return t.skip("event_keys.json not found");
  const fx = JSON.parse(fs.readFileSync(file, "utf8"));

  const ts = Object.create(Sentry.prototype);
  ts.logger = quiet;
  ts.service = "svc"; ts.environment = "test"; ts.hostname = "h";
  ts.identity = { ip: null, auth: null };
  ts.requestContext = { path: () => "/p", userAgent: () => null, method: () => "GET" };
  const events = [];
  ts._handlers = [{ emit: (e) => events.push(e) }];
  const resp = { status_code: 401, response_body: {}, mime_type: "application/json" };
  ts._trigger_trap_event({}, { intent: null, "response.authenticated": resp, "response.unauthenticated": resp });
  ts._trigger_watch_event({}, [{ type: "body", field: "f", value: 1, intent: null }]);
  ts.trigger({}, "reason");

  assert.deepEqual(events.map((e) => e.event), Object.keys(fx.events));
  const sorted = (a) => [...a].sort();
  for (const e of events) {
    assert.deepEqual(sorted(Object.keys(e)), sorted([...fx.common, ...fx.events[e.event]]), e.event);
    assert.deepEqual(sorted(Object.keys(e.app)), sorted(fx.app));
  }
  assert.deepEqual(sorted(Object.keys(events[1].found_fields[0])), sorted(fx.found_field));
});

const { safe_value } = require("../src/core");
for (const c of load("safe_value.json")) {
  test(`safe_value: ${c.name}`, () => {
    assert.deepEqual(safe_value(expand(c.input)), expand(c.output));
  });
}

test("event path and user_agent truncation", (t) => {
  const file = path.join(CONFORMANCE, "safe_value.json");
  if (!fs.existsSync(file) && !process.env.CI) return t.skip("safe_value.json not found");
  const fx = expand(JSON.parse(fs.readFileSync(file, "utf8")).events);
  const ts = Object.create(Sentry.prototype);
  ts.logger = quiet;
  ts.identity = { ip: null, auth: null };
  ts.requestContext = { path: () => fx.path, userAgent: () => fx.user_agent, method: () => "GET" };
  const events = [];
  ts._handlers = [{ emit: (e) => events.push(e) }];
  ts.trigger({}, "reason");
  assert.equal(events[0].path, fx.path_out);
  assert.equal(events[0].user_agent, fx.user_agent_out);
});

const isTrapFx = (() => {
  const file = path.join(CONFORMANCE, "is_trap.json");
  if (!fs.existsSync(file) && !process.env.CI) return null;
  return JSON.parse(fs.readFileSync(file, "utf8"));
})();

if (isTrapFx) {
  const ts = Object.create(Sentry.prototype);
  ts.logger = quiet;
  ts._traps = [];
  ts._trap_index = null;
  for (const t of isTrapFx.traps) ts.trap(t.path).methods(...t.methods);
  let cur = {};
  ts.request = { path: () => cur.path, method: () => cur.method, user_agent: () => null };
  for (const c of isTrapFx.cases) {
    test(`is_trap: ${c.method} ${c.path} is ${c.is_trap}`, () => {
      cur = c;
      assert.equal(ts.is_trap(c), c.is_trap);
    });
  }
}

// Trap response resolution: headers, response hook and fallback (R16, R23).
class BareSentry extends Sentry {
  _register() {}
}

function fixtureBody(v) {
  if (v !== null && typeof v === "object" && "$callable" in v) {
    if (v.$callable === "throws") return () => { throw new Error("boom"); };
    return () => v.value;
  }
  return v;
}

function fixtureResponse(spec) {
  return Object.fromEntries(Object.entries(spec || {}).map(([k, v]) => [k, k === "body" ? fixtureBody(v) : v]));
}

for (const c of load("trap_response.json")) {
  test(`trap_response: ${c.name}`, () => {
    const ts = new BareSentry({}, "svc", "test");
    ts.logger = quiet;
    ts._handlers = [];
    ts.request = { path: () => "/t", user_agent: () => null, method: () => "GET" };
    ts.identify_user(() => (c.authenticated ? { user: "u1", role: "member" } : null));

    let builder;
    if (c.authenticated) {
      ts.default_response(fixtureResponse(c.default));
      builder = ts.trap("/t").respond(fixtureResponse(c.trap));
    } else {
      ts.default_unauthenticated_response(fixtureResponse(c.default));
      builder = ts.trap("/t").if_unauthenticated(fixtureResponse(c.trap));
    }
    if (c.hook === "throws") builder.respond_with(() => { throw new Error("hook"); });
    else if (c.hook !== undefined) builder.respond_with(() => c.hook.returns);

    const { response_body, response_config } = ts._trigger_trap_event({}, builder.build());
    assert.deepEqual(
      { status: response_config.status_code, body: String(response_body), mime_type: response_config.mime_type, headers: response_config.headers },
      c.expect,
    );
  });
}
