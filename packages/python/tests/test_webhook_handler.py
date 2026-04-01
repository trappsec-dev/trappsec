import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from trappsec import handlers
from trappsec.handlers import WebhookHandler


@unittest.skipIf(handlers.requests is None, "requests dependency is not installed")
class WebhookHandlerAlertsOnlyTests(unittest.TestCase):
    def test_emit_skips_signal_by_default(self):
        handler = WebhookHandler("http://example.test/webhook")
        sent = []
        handler._send = lambda payload: sent.append(payload)

        handler.emit({"event": "trappsec.watch_hit", "type": "signal"})

        self.assertEqual(sent, [])

    def test_emit_allows_signal_when_alerts_only_disabled(self):
        handler = WebhookHandler("http://example.test/webhook", alerts_only=False)
        sent = []
        handler._send = lambda payload: sent.append(payload)

        handler.emit({"event": "trappsec.watch_hit", "type": "signal"})

        self.assertEqual(len(sent), 1)


if __name__ == "__main__":
    unittest.main()
