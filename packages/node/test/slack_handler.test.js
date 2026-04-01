const test = require("node:test");
const assert = require("node:assert/strict");

const { SlackHandler } = require("../src/handlers");

test("slack handler skips signal events by default", () => {
  const handler = new SlackHandler("http://example.test/webhook");
  const sent = [];
  handler.webhook._send = (payload) => sent.push(payload);

  handler.emit({ event: "trappsec.watch_hit", type: "signal", path: "/x", method: "GET" });

  assert.equal(sent.length, 0);
});

test("slack handler formats payload with blocks", () => {
  const handler = new SlackHandler("http://example.test/webhook", { alerts_only: false, service: "svc", environment: "dev" });
  const sent = [];
  handler.webhook._send = (payload) => sent.push(payload);

  handler.emit({
    event: "trappsec.trap_hit",
    type: "alert",
    path: "/deployment/config",
    method: "GET",
    intent: "Recon",
  });

  assert.equal(sent.length, 1);
  const payload = JSON.parse(sent[0]);
  assert.ok(Array.isArray(payload.blocks));
  assert.match(payload.text, /\[ALERT\]/);
});
