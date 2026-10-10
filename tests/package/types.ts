// Type-checks against the shipped index.d.ts (tsc --noEmit).
import express from "express";
import { Sentry, NO_DEFAULT } from "trappsec";

const app = express();
const ts = new Sentry(app, "smoke", "ci");
ts.identify_user((req: any) => ({ user: req.headers["x-user-id"], role: null }));
ts.trap("/admin/backup").methods("GET").intent("Recon").respond({ status: 200, body: { ok: true } });
ts.watch("/profile").body("is_admin", { intent: "Privilege Escalation" }).query("debug", { defaultValue: NO_DEFAULT });
ts.add_webhook("https://example.com/hook", { secret: "s", alerts_only: true });
void ts.close();
