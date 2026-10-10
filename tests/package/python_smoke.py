"""Smoke-test an installed trappsec distribution (wheel or sdist), not the repo source.

Run from outside the repository in a fresh environment with trappsec and flask installed.
"""
import importlib.util
import json
import logging
import pathlib
import sys

import trappsec

src = pathlib.Path(trappsec.__file__).resolve()
assert "site-packages" in src.parts, f"imported trappsec from {src}, not an installed distribution"
assert (src.parent / "py.typed").exists(), "py.typed missing: type information is not shipped"

for mod in ("core", "builders", "handlers", "integrations._jsonbody", "integrations._version", "integrations.flask", "integrations.fastapi",
            "integrations.starlette", "integrations.litestar", "integrations.django", "integrations.sanic",
            "integrations.tornado"):
    assert importlib.util.find_spec(f"trappsec.{mod}") is not None, f"trappsec.{mod} missing from the distribution"

for name in ("Sentry", "NO_DEFAULT", "TrapBuilder", "WatchBuilder"):
    assert hasattr(trappsec, name), f"trappsec.{name} not exported"

from flask import Flask, jsonify, request  # noqa: E402

app = Flask(__name__)


@app.post("/profile")
def profile():
    return jsonify(request.get_json(silent=True) or {})


ts = trappsec.Sentry(app, service="smoke", environment="ci")
events = []
ts._handlers.append(type("Capture", (), {"emit": lambda self, e: events.append(e)})())
logging.getLogger("trappsec").setLevel(logging.CRITICAL)
ts.trap("/admin/backup").methods("GET").intent("Recon").respond(200, {"ok": True})
ts.watch("/profile").body("is_admin", intent="Privilege Escalation")

client = app.test_client()
assert client.get("/admin/backup").status_code == 401
assert client.post("/profile", json={"is_admin": True, "name": "a"}).get_json() == {"name": "a"}
assert [e["event"] for e in events] == ["trappsec.trap_hit", "trappsec.watch_hit"], events
json.dumps(events, default=str)
print(f"python package smoke ok: trappsec from {src.parent}", file=sys.stderr)
