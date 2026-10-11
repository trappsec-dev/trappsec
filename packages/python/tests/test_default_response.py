import pathlib
import sys
import unittest

try:
    import trappsec  # noqa: F401  (prefer the installed package)
except ImportError:
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from flask import Flask

from trappsec import Sentry


class DefaultResponseTests(unittest.TestCase):
    def setUp(self):
        self.ts = Sentry(Flask(__name__), "svc", "dev")

    def test_only_given_arguments_change_the_default(self):
        trap = self.ts.trap("/t")
        self.ts.default_response(body={"ok": True})
        self.ts.default_unauthenticated_response(status=403, body="no", mime_type="text/plain")
        cfg = trap.build()
        self.assertEqual(cfg["response.authenticated"], {"status_code": 200, "response_body": {"ok": True}, "mime_type": "application/json"})
        self.assertEqual(cfg["response.unauthenticated"], {"status_code": 403, "response_body": "no", "mime_type": "text/plain"})

    def test_template_replaces_the_default(self):
        self.ts.template("gone", 410, {"error": "gone"})
        self.ts.default_unauthenticated_response(template="gone")
        cfg = self.ts.trap("/t").build()
        self.assertEqual(cfg["response.unauthenticated"]["status_code"], 410)
        with self.assertRaises(ValueError):
            self.ts.default_response(template="missing")
        with self.assertRaises(TypeError):
            self.ts.default_response(template="gone", status=200)

    def test_trap_overrides_win_and_calls_chain(self):
        self.assertIs(self.ts.default_response(status=202), self.ts)
        cfg = self.ts.trap("/t").respond(status=200).build()
        self.assertEqual(cfg["response.authenticated"]["status_code"], 200)


if __name__ == "__main__":
    unittest.main()
