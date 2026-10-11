// Smoke-test an installed trappsec tarball (npm pack), not the repo source.
// Run from a scratch project with trappsec and express installed.
const assert = require("node:assert/strict");
const path = require("node:path");

const entry = require.resolve("trappsec");
assert.ok(entry.includes(`${path.sep}node_modules${path.sep}trappsec${path.sep}`), `resolved ${entry}, not the installed package`);

const trappsec = require("trappsec");
for (const name of ["Sentry", "NO_DEFAULT", "TrapBuilder", "WatchBuilder"]) {
  assert.ok(trappsec[name] !== undefined, `trappsec.${name} not exported (CJS)`);
}
for (const mod of ["express", "fastify", "koa", "hapi", "nestjs", "_common"]) {
  require.resolve(`./node_modules/trappsec/src/integrations/${mod}.js`, { paths: [process.cwd()] });
}

const express = require("express");
const app = express();
app.use(express.json());
app.post("/profile", (req, res) => res.json(req.body));
const ts = new trappsec.Sentry(app, "smoke", "ci");
const events = [];
ts._handlers = [{ emit: (e) => events.push(e) }];
ts.trap("/admin/backup").methods("GET").intent("Recon").respond({ status: 200, body: { ok: true } });
ts.watch("/profile").body("is_admin", { intent: "Privilege Escalation" });

const server = app.listen(0, async () => {
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    assert.equal((await fetch(`${base}/admin/backup`)).status, 401);
    const r = await fetch(`${base}/profile`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ is_admin: true, name: "a" }),
    });
    assert.deepEqual(await r.json(), { name: "a" });
    assert.deepEqual(events.map((e) => e.event), ["trappsec.trap_hit", "trappsec.watch_hit"]);
    console.error(`node package smoke ok (CJS): ${entry}`);
  } finally {
    server.close();
  }
});
