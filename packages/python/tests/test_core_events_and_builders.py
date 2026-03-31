import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from trappsec.builders import TrapBuilder, WatchBuilder
from trappsec.core import Sentry


class _Ctx:
    def __init__(self, identity_ctx, request_ctx):
        self.identity = type("Identity", (), {"get_context": lambda _self, _req: identity_ctx})()
        self.request = type("Request", (), {"get_context": lambda _self, _req: request_ctx})()
        self.events = []

    def _trigger(self, event):
        self.events.append(event)


class _TS:
    def __init__(self):
        self.default_responses = {
            "authenticated": {"status_code": 200, "response_body": {}, "mime_type": "application/json"},
            "unauthenticated": {"status_code": 401, "response_body": {}, "mime_type": "application/json"},
        }
        self._templates = {
            "gone": {"status_code": 410, "response_body": {"error": "gone"}, "mime_type": "application/json"}
        }


class CoreEventsAndBuildersTests(unittest.TestCase):
    def test_trigger_watch_event_signal_payload(self):
        ctx = _Ctx(
            identity_ctx={"user": None, "role": None, "ip": "1.2.3.4"},
            request_ctx={"path": "/a", "method": "GET", "user_agent": "ua"},
        )
        Sentry._trigger_watch_event(ctx, object(), [{"field": "x"}])

        self.assertEqual(len(ctx.events), 1)
        event = ctx.events[0]
        self.assertEqual(event["event"], "trappsec.watch_hit")
        self.assertEqual(event["type"], "signal")
        self.assertEqual(event["path"], "/a")
        self.assertEqual(event["ip"], "1.2.3.4")

    def test_trigger_trap_event_auth_uses_authenticated_response(self):
        ctx = _Ctx(
            identity_ctx={"user": "u1", "role": "admin", "ip": "1.2.3.4"},
            request_ctx={"path": "/trap", "method": "POST", "user_agent": "ua"},
        )
        trap = {
            "intent": "Recon",
            "response.authenticated": {
                "status_code": 201,
                "response_body": {"ok": True},
                "mime_type": "application/json",
            },
            "response.unauthenticated": {
                "status_code": 401,
                "response_body": {"ok": False},
                "mime_type": "application/json",
            },
        }

        body, response_cfg = Sentry._trigger_trap_event(ctx, object(), trap)

        self.assertEqual(response_cfg["status_code"], 201)
        self.assertIn('"ok": true', body)
        self.assertEqual(ctx.events[0]["type"], "alert")
        self.assertEqual(ctx.events[0]["event"], "trappsec.trap_hit")

    def test_trap_builder_template_and_method_overrides(self):
        ts = _TS()
        cfg = (
            TrapBuilder(ts, "/trap")
            .methods("PUT")
            .intent("Recon")
            .respond(status=418, body={"x": 1}, mime_type="application/json")
            .if_unauthenticated(template="gone")
            .build()
        )

        self.assertEqual(cfg["methods"], ["PUT"])
        self.assertEqual(cfg["intent"], "Recon")
        self.assertEqual(cfg["response.authenticated"]["status_code"], 418)
        self.assertEqual(cfg["response.unauthenticated"]["status_code"], 410)

    def test_watch_builder_build_shape(self):
        cfg = WatchBuilder("/login").query("role", default="user", intent="x").body("token", intent="y").build()

        self.assertEqual(cfg["path"], "/login")
        self.assertIn("role", cfg["query_fields"])
        self.assertIn("token", cfg["body_fields"])


if __name__ == "__main__":
    unittest.main()
