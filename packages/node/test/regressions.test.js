const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const crypto = require("node:crypto");

const { Sentry } = require("../src/core");
const { TrapBuilder, WatchBuilder, NO_DEFAULT } = require("../src/builders");
const { WebhookHandler, SlackHandler, OTELHandler, otelValue } = require("../src/handlers");
const pkg = require("../src/index");

const quiet = { error() {}, warn() {}, info() {}, log() {} };

function harness(over = {}) {
  const ts = Object.create(Sentry.prototype);
  ts.logger = quiet;
  ts.identity = over.identity || { ip: () => "1.1.1.1", auth: null };
  ts.requestContext = over.requestContext || { path: () => "/p", userAgent: () => "ua", method: () => "GET" };
  ts.captured = [];
  ts._trigger = (e) => ts.captured.push(e);
  ts.default_responses = {
    authenticated: { status_code: 200, response_body: {}, mime_type: "application/json" },
    unauthenticated: { status_code: 401, response_body: {}, mime_type: "application/json" },
  };
  ts._templates = Object.create(null);
  return ts;
}

const rules = (o) => { const r = new WatchBuilder("/x"); for (const [k, v] of Object.entries(o)) r.body(k, v); return r.build().body_fields; };

test("exports", () => {
  assert.ok(pkg.Sentry && pkg.TrapBuilder && pkg.WatchBuilder && pkg.NO_DEFAULT);
});

test("prototype keys never match", () => {
  const ts = harness();
  const r = rules({ role: {} });
  const data = JSON.parse('{"constructor":1,"toString":2,"__proto__":3,"hasOwnProperty":4}');
  const out = ts._detect_honey_fields(data, r, {}, "query");
  assert.equal(out.found_fields.length, 0);
  assert.equal(out.touched, false);
  assert.equal(Object.keys(out.data).length, 4);
  // plain-object rules too
  const out2 = ts._detect_honey_fields({ constructor: 1 }, {}, {}, "body");
  assert.equal(out2.touched, false);
});

test("a rule named constructor works when configured", () => {
  const ts = harness();
  const out = ts._detect_honey_fields({ constructor: 1 }, rules({ constructor: {} }), {}, "body");
  assert.equal(out.found_fields.length, 1);
  assert.equal(Object.hasOwn(out.data, "constructor"), false);
});

test("source param sets type and callable throwing is a violation but still strips", () => {
  const ts = harness();
  const r = rules({ a: { defaultValue: () => { throw new Error("boom"); } } });
  const out = ts._detect_honey_fields({ a: "1", b: 2 }, r, {}, "query");
  assert.equal(out.found_fields.length, 1);
  assert.equal(out.found_fields[0].type, "query");
  assert.deepEqual(out.data, { b: 2 });
  assert.equal(ts._detect_honey_fields({ a: 1 }, r, {}).found_fields[0].type, "body");
});

test("loose value matching", () => {
  const ts = harness();
  const d = (val, def) => ts._detect_honey_fields({ k: val }, rules({ k: { defaultValue: def } }), {}, "query").found_fields.length;
  assert.equal(d("5", 5), 0);
  assert.equal(d(5, "5"), 0);
  assert.equal(d(5.0, 5), 0);
  assert.equal(d("true", true), 0);
  assert.equal(d(true, "true"), 0);
  assert.equal(d("1", true), 1);
  assert.equal(d("6", 5), 1);
  assert.equal(d("abc", "abd"), 1);
  assert.equal(d(["5"], 5), 0);
  assert.equal(d(["5", "5"], 5), 0);
  assert.equal(d(["5", "6"], 5), 1);
  assert.equal(d(["5", "6"], NO_DEFAULT), 1);
});

test("multi-valued strip and top-level arrays", () => {
  const ts = harness();
  const r = rules({ w: { defaultValue: "x" } });
  const out = ts._detect_honey_fields({ w: ["x", "y"], keep: ["a", "b"] }, r, {}, "query");
  assert.equal(out.found_fields.length, 1);
  assert.deepEqual(out.data, { keep: ["a", "b"] });
  const arr = [{ w: "z" }, 5, null, { w: "x" }];
  const o2 = ts._detect_honey_fields(arr, r, {}, "body");
  assert.equal(o2.found_fields.length, 1);
  assert.equal(o2.touched, true);
  assert.deepEqual(arr[0], {});
  for (const odd of ["str", 5, null, undefined]) {
    assert.equal(ts._detect_honey_fields(odd, r, {}, "body").touched, false);
  }
});

test("safe_value sanitizes recorded value", () => {
  const ts = harness();
  const r = rules({ w: {} });
  const big = "a".repeat(5000);
  const f = (v) => ts._detect_honey_fields({ w: v }, r, {}, "body").found_fields[0].value;
  assert.equal(f(big).length, 1027);
  assert.ok(f(big).endsWith("..."));
  assert.equal(f(Array.from({ length: 50 }, (_, i) => i)).length, 20);
  assert.equal(typeof f({ a: { b: 1 } }), "string");
  assert.equal(f(Buffer.from("x")), "<Buffer>");
  assert.equal(f(true), true);
});

test("identity callbacks that throw never propagate", () => {
  const ts = harness({
    identity: { ip: () => { throw new Error("ip"); }, auth: () => { throw new Error("auth"); } },
    requestContext: { path: () => { throw new Error("p"); }, userAgent: () => "u", method: () => "GET" },
  });
  ts._default_ip = () => "9.9.9.9";
  ts._trigger_watch_event({}, []);
  assert.equal(ts.captured[0].type, "signal");
  assert.equal(ts.captured[0].user, null);
  assert.equal(ts.captured[0].ip, "9.9.9.9");
  assert.equal(ts.captured[0].path, null);
  assert.ok("role" in ts.captured[0] && "found_fields" in ts.captured[0]);
});

test("trap: throwing dynamic body falls back to {} and string bodies are raw", () => {
  const ts = harness();
  const mk = (body, mime = "application/json") => ({ intent: null, "response.authenticated": {}, "response.unauthenticated": { status_code: 401, response_body: body, mime_type: mime } });
  assert.equal(ts._trigger_trap_event({}, mk(() => { throw new Error("x"); })).response_body, "{}");
  assert.equal(ts._trigger_trap_event({}, mk("<b>hi</b>")).response_body, "<b>hi</b>");
  assert.equal(ts._trigger_trap_event({}, mk('raw"', "application/json")).response_body, 'raw"');
  assert.equal(ts.captured[0].intent, null);
  assert.ok("user" in ts.captured[0]);
});

test("trigger() emits rule_hit with null keys", () => {
  const ts = harness();
  ts.trigger({}, "too many", undefined, { n: 1 });
  const e = ts.captured[0];
  assert.equal(e.event, "trappsec.rule_hit");
  assert.equal(e.reason, "too many");
  assert.equal(e.intent, null);
  assert.deepEqual(e.metadata, { n: 1 });
  ts.trigger({}, "r");
  assert.equal(ts.captured[1].metadata, null);
});

test("builders: falsy values honored, template keeps functions, defaults resolved at build", () => {
  const ts = harness();
  const fn = () => "dyn";
  ts._templates.t = { status_code: 410, response_body: fn, mime_type: "text/plain" };
  const b = new TrapBuilder(ts, "/t").respond({ status: 0, body: "" }).if_unauthenticated({ template: "t" });
  ts.default_responses.authenticated.mime_type = "text/html"; // changed after .trap()
  const cfg = b.build();
  assert.equal(cfg["response.authenticated"].status_code, 0);
  assert.equal(cfg["response.authenticated"].response_body, "");
  assert.equal(cfg["response.authenticated"].mime_type, "text/html");
  assert.equal(cfg["response.unauthenticated"].response_body, fn);
  assert.equal(new TrapBuilder(ts, "/z").respond({ body: {} }).build()["response.authenticated"].response_body.constructor, Object);
  assert.throws(() => new TrapBuilder(ts, "/z").respond({ template: "constructor" }), /not found/);
});

test("watch builder maps have no prototype", () => {
  const b = new WatchBuilder("/p").query("a", {}).build();
  assert.equal(Object.getPrototypeOf(b.query_fields), null);
  assert.equal("constructor" in b.body_fields, false);
});

test("Sentry.bootstrap delegates and close exists", async () => {
  const ts = harness();
  ts._handlers = [];
  let n = 0;
  ts.integration = { bootstrap() { n++; } };
  ts.bootstrap();
  assert.equal(n, 1);
  ts.integration = {};
  ts.bootstrap();
  await ts.close();
});

// ---- webhook ----
function server(handler) {
  return new Promise((resolve) => {
    const reqs = [];
    const s = http.createServer((req, res) => {
      const chunks = [];
      req.on("data", (c) => chunks.push(c));
      req.on("end", () => {
        const rec = { headers: req.headers, body: Buffer.concat(chunks).toString() };
        reqs.push(rec);
        handler ? handler(rec, res, reqs) : res.end("ok");
      });
    });
    s.listen(0, "127.0.0.1", () => resolve({ s, reqs, url: `http://127.0.0.1:${s.address().port}/h` }));
  });
}

test("webhook: signature format, non-blocking, close flushes", async () => {
  const { s, reqs, url } = await server();
  const h = new WebhookHandler(url, { secret: "sek", alerts_only: false });
  h.logger = quiet;
  const t0 = Date.now();
  h.emit({ type: "alert", event: "x" });
  assert.ok(Date.now() - t0 < 50);
  assert.equal(reqs.length, 0);
  await h.close();
  assert.equal(reqs.length, 1);
  const { headers, body } = reqs[0];
  const ts = headers["x-trappsec-timestamp"];
  assert.match(ts, /^\d+$/);
  const expect = crypto.createHmac("sha256", "sek").update(`${ts}.${body}`).digest("hex");
  assert.equal(headers["x-trappsec-signature"], `sha256=${expect}`);
  s.close();
});

test("webhook: no signature headers without secret", async () => {
  const { s, reqs, url } = await server();
  const h = new WebhookHandler(url, { alerts_only: false });
  h.emit({ type: "alert" });
  await h.close();
  assert.equal(reqs[0].headers["x-trappsec-signature"], undefined);
  s.close();
});

test("webhook: template throw drops event", async () => {
  const { s, reqs, url } = await server();
  const h = new WebhookHandler(url, { alerts_only: false, template: () => { throw new Error("t"); } });
  h.logger = quiet;
  h.emit({ type: "alert", secret: "raw" });
  await h.close();
  assert.equal(reqs.length, 0);
  s.close();
});

test("webhook: in-flight cap drops excess", async () => {
  const held = [];
  const { s, reqs, url } = await server((rec, res) => held.push(res));
  const h = new WebhookHandler(url, { alerts_only: false });
  let warns = 0;
  h.logger = { error() {}, warn() { warns++; } };
  for (let i = 0; i < 150; i++) h.emit({ type: "alert", i });
  assert.equal(h._inFlight, 100);
  assert.equal(warns, 1);
  await h.close(50);
  held.forEach((r) => r.end());
  s.closeAllConnections();
  s.close();
});

test("webhook: non-2xx logged and 5xx retried at most twice", async () => {
  const { s, reqs, url } = await server((rec, res) => { res.statusCode = 500; res.end(); });
  const h = new WebhookHandler(url, { alerts_only: false });
  const errs = [];
  h.logger = { error: (m) => errs.push(m), warn() {} };
  h.emit({ type: "alert" });
  await h.close(5000);
  assert.equal(reqs.length, 3);
  assert.ok(errs.some((m) => /500/.test(m)));
  s.close();
});

test("webhook: 4xx not retried", async () => {
  const { s, reqs, url } = await server((rec, res) => { res.statusCode = 400; res.end(); });
  const h = new WebhookHandler(url, { alerts_only: false });
  h.logger = quiet;
  h.emit({ type: "alert" });
  await h.close();
  assert.equal(reqs.length, 1);
  s.close();
});

test("webhook: heartbeat is stoppable and unref'd", async () => {
  const { s, reqs, url } = await server();
  const h = new WebhookHandler(url, { heartbeat_interval: 0.05, secret: "k" });
  assert.equal(h._timer.hasRef(), false);
  await new Promise((r) => setTimeout(r, 180));
  await h.close();
  const n = reqs.length;
  assert.ok(n >= 1);
  assert.equal(h._timer, null);
  await new Promise((r) => setTimeout(r, 150));
  assert.equal(reqs.length, n);
  assert.ok(reqs[0].headers["x-trappsec-signature"].startsWith("sha256="));
  s.close();
});

// ---- slack ----
test("slack escapes mrkdwn and sets text", () => {
  const h = new SlackHandler("http://x.test/", { alerts_only: false, service: "s", environment: "e" });
  const sent = [];
  h.webhook._send = (p) => sent.push(p);
  h.emit({
    event: "trappsec.watch_hit", type: "alert", timestamp: 1712011200,
    path: "/<!channel>", method: "GET", user: "<!here>", role: "a&b", ip: "<x>", user_agent: "<!everyone>",
    intent: "<!channel>", found_fields: [{ field: "<@U1>", type: "body", intent: "<!channel>" }],
  });
  const p = JSON.parse(sent[0]);
  const all = JSON.stringify(p);
  assert.ok(!all.includes("<!channel>") && !all.includes("<!here>") && !all.includes("<@U1>") && !all.includes("<!everyone>"));
  assert.ok(all.includes("&lt;!channel&gt;"));
  assert.ok(all.includes("a&amp;b"));
  assert.ok(p.text.length > 0);
  assert.match(p.attachments[0].blocks[0].text.text, /<!date\^1712011200\^/);
});

// ---- otel ----
test("otel attributes are valid types", () => {
  assert.equal(otelValue(null), undefined);
  assert.equal(otelValue({ a: 1 }), '{"a":1}');
  assert.deepEqual(otelValue(["a", null, "b"]), ["a", "b"]);
  assert.deepEqual(otelValue([1, "a", { x: 1 }]), ["1", "a", '{"x":1}']);
  const events = [], attrs = {};
  const span = { isRecording: () => true, setAttribute: (k, v) => { attrs[k] = v; }, addEvent: (n, a) => events.push(a) };
  const h = Object.create(OTELHandler.prototype);
  h.otel = { trace: { getSpan: () => span }, context: { active: () => ({}) } };
  h.emit({ event: "trappsec.watch_hit", type: "alert", user: null, role: null, ip: null, metadata: { m: { x: 1 }, n: null },
    found_fields: [{ type: "body", field: "f", value: { a: 1 }, intent: null }] });
  for (const v of Object.values(events[0])) assert.ok(["string", "number", "boolean"].includes(typeof v) || Array.isArray(v));
  assert.equal("intent" in events[0], false);
  assert.equal(attrs["metadata.m"], '{"x":1}');
  assert.equal("metadata.n" in attrs, false);
  assert.equal("trappsec.user" in attrs, false);
});
