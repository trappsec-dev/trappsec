import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from trappsec import handlers
from trappsec.handlers import SlackHandler


@unittest.skipIf(handlers.requests is None, "requests dependency is not installed")
class SlackHandlerTests(unittest.TestCase):
    def test_emit_skips_signal_by_default(self):
        handler = SlackHandler("http://example.test/webhook")
        sent = []
        handler._webhook._send = lambda payload: sent.append(payload)

        handler.emit({"event": "trappsec.watch_hit", "type": "signal", "path": "/x", "method": "GET"})

        self.assertEqual(sent, [])

    def test_emit_formats_slack_payload(self):
        handler = SlackHandler("http://example.test/webhook", alerts_only=False)
        sent = []
        handler._webhook._send = lambda payload: sent.append(payload)

        handler.emit(
            {
                "event": "trappsec.trap_hit",
                "type": "alert",
                "path": "/deployment/config",
                "method": "GET",
                "intent": "Reconnaissance",
                "app": {"service": "svc", "environment": "dev", "hostname": "h1"},
            }
        )

        self.assertEqual(len(sent), 1)
        self.assertIn('"blocks"', sent[0])
        self.assertIn("Trappsec ALERT", sent[0])


if __name__ == "__main__":
    unittest.main()
