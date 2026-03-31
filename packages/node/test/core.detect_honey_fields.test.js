const test = require("node:test");
const assert = require("node:assert/strict");

const { Sentry, NO_DEFAULT } = require("../src/core");

function detect(data, rules, requestObj = null) {
  const dummy = { logger: console };
  return Sentry.prototype._detect_honey_fields.call(dummy, data, rules, requestObj);
}

test("touched with default value strips without violation", () => {
  const data = { role: "user", safe: "x" };
  const rules = { role: { default: "user", intent: "Privilege Escalation" } };

  const { data: sanitized, found_fields, touched } = detect(data, rules);

  assert.equal(touched, true);
  assert.deepEqual(found_fields, []);
  assert.deepEqual(sanitized, { safe: "x" });
});

test("touched with mismatch strips and reports violation", () => {
  const data = { role: "admin", safe: "x" };
  const rules = { role: { default: "user", intent: "Privilege Escalation" } };

  const { data: sanitized, found_fields, touched } = detect(data, rules);

  assert.equal(touched, true);
  assert.equal(found_fields.length, 1);
  assert.equal(found_fields[0].field, "role");
  assert.deepEqual(sanitized, { safe: "x" });
});

test("untouched when no watched keys are present", () => {
  const data = { safe: "x" };
  const rules = { role: { default: "user", intent: "Privilege Escalation" } };

  const { data: sanitized, found_fields, touched } = detect(data, rules);

  assert.equal(touched, false);
  assert.deepEqual(found_fields, []);
  assert.deepEqual(sanitized, { safe: "x" });
});

test("NO_DEFAULT always triggers and strips", () => {
  const data = { token: "abc" };
  const rules = { token: { default: NO_DEFAULT, intent: "Credential Stuffing" } };

  const { data: sanitized, found_fields, touched } = detect(data, rules);

  assert.equal(touched, true);
  assert.equal(found_fields.length, 1);
  assert.deepEqual(sanitized, {});
});
