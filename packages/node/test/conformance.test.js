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

const quiet = { error() {}, warn() {}, info() {}, log() {} };
const byField = (a, b) => (a.field < b.field ? -1 : a.field > b.field ? 1 : 0);

for (const c of load("values_match.json")) {
  test(`values_match(${JSON.stringify(c.actual)}, ${JSON.stringify(c.expected)}) is ${c.match}`, () => {
    assert.equal(values_match(c.actual, c.expected), c.match);
  });
}

for (const c of load("detect_honey_fields.json")) {
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
