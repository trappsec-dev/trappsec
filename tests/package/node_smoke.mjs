// ESM entry point of the installed package: named and default exports.
import assert from "node:assert/strict";
import trappsec, { Sentry, NO_DEFAULT, TrapBuilder, WatchBuilder } from "trappsec";

for (const [name, value] of Object.entries({ Sentry, NO_DEFAULT, TrapBuilder, WatchBuilder })) {
  assert.ok(value !== undefined, `${name} not exported (ESM)`);
  assert.equal(trappsec[name], value, `default export disagrees on ${name}`);
}
console.error("node package smoke ok (ESM)");
