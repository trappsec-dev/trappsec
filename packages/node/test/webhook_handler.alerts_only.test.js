const test = require("node:test");
const assert = require("node:assert/strict");

const { WebhookHandler } = require("../src/handlers");

test("webhook handler skips signal events by default", () => {
  const handler = new WebhookHandler("http://example.test/webhook");
  const sent = [];
  handler._send = (payload) => sent.push(payload);

  handler.emit({ event: "trappsec.watch_hit", type: "signal" });

  assert.equal(sent.length, 0);
});

test("webhook handler sends signal events when alerts_only is false", () => {
  const handler = new WebhookHandler("http://example.test/webhook", { alerts_only: false });
  const sent = [];
  handler._send = (payload) => sent.push(payload);

  handler.emit({ event: "trappsec.watch_hit", type: "signal" });

  assert.equal(sent.length, 1);
});
