import hashlib
import hmac
import json
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

EVENT_KEYS = json.loads((Path(__file__).resolve().parent.parent / "conformance" / "event_keys.json").read_text())

# Wait after the expected alerts arrive, so a duplicate or late extra event is
# still counted instead of slipping in after the assertion.
SETTLE = 0.3
SIGNATURE_MAX_SKEW = 300


class AlertHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length') or 0)
        body = self.rfile.read(content_length)
        self.server.record(self.path, body, {k.lower(): v for k, v in self.headers.items()})
        self.send_response(200)
        self.send_header("content-length", "0")
        self.end_headers()

    def log_message(self, format, *args):
        pass


class AlertServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, server_address, RequestHandlerClass, secret=None):
        super().__init__(server_address, RequestHandlerClass)
        self.secret = secret
        self.alerts = []
        self.alerts_only = []  # deliveries to /alerts: a second handler registered with alerts_only=True
        self.problems = []  # bad signatures or unparseable bodies, across the session
        self._lock = threading.Lock()

    def record(self, path, body, headers):
        problem = self._check_signature(body, headers)
        try:
            data = json.loads(body)
        except (ValueError, UnicodeDecodeError):
            problem = problem or "body is not JSON"
            data = None
        with self._lock:
            if problem:
                self.problems.append((problem, body[:200]))
            if isinstance(data, dict):
                (self.alerts_only if path.startswith("/alerts") else self.alerts).append(data)

    def _check_signature(self, body, headers):
        if not self.secret:
            return None
        ts, sig = headers.get("x-trappsec-timestamp"), headers.get("x-trappsec-signature")
        if not ts or not sig:
            return "missing signature headers"
        try:
            if abs(time.time() - int(ts)) > SIGNATURE_MAX_SKEW:
                return "stale signature timestamp"
        except ValueError:
            return "non-numeric signature timestamp"
        expected = "sha256=" + hmac.new(self.secret.encode(), ts.encode() + b"." + body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, sig):
            return "signature mismatch"
        return None

    def clear(self):
        with self._lock:
            self.alerts = []
            self.alerts_only = []

    def get_alerts_for_agent(self, user_agent, alerts_only=False):
        with self._lock:
            pool = self.alerts_only if alerts_only else self.alerts
            return [a for a in pool if a.get("user_agent") == user_agent]


def unique_ua():
    return f"trappsec-e2e-{uuid.uuid4()}"


class Alerts:
    """Assertion helpers around the alert server, bound to one app under test."""

    def __init__(self, server, api, base_url, check_alerts_only=False):
        self.server = server
        self.api = api
        self.base_url = base_url
        self.check_alerts_only = check_alerts_only

    def expect(self, user_agent, count=1, timeout=5):
        """Wait for `count` events from `user_agent`, then settle and require exactly that many."""
        deadline = time.time() + timeout
        while time.time() < deadline and len(self.server.get_alerts_for_agent(user_agent)) < count:
            time.sleep(0.05)
        time.sleep(SETTLE)
        alerts = self.server.get_alerts_for_agent(user_agent)
        assert len(alerts) == count, f"expected {count} event(s) for {user_agent}, got {len(alerts)}: {alerts}"
        for a in alerts:
            check_event_shape(a, user_agent)
        if self.check_alerts_only:
            # The alerts_only=True receiver gets exactly the alerts, never a signal.
            filtered = self.server.get_alerts_for_agent(user_agent, alerts_only=True)
            assert [a["event"] for a in filtered] == [a["event"] for a in alerts if a["type"] == "alert"], filtered
        return alerts

    def expect_none(self, user_agent):
        """Require that `user_agent` produced no event.

        Delivery is asynchronous, so waiting a fixed time proves little. Instead
        hit a trap with a fresh user agent and wait for that event: once it has
        been delivered, anything queued before it has been delivered too.
        """
        sentinel = unique_ua()
        r = self.api.get(f"{self.base_url}/deployment/config", headers={"User-Agent": sentinel})
        assert r.status_code == 401
        self.expect(sentinel)
        assert self.server.get_alerts_for_agent(user_agent) == []
        assert self.server.get_alerts_for_agent(user_agent, alerts_only=True) == []


def check_event_shape(event, user_agent):
    """Every delivered event must carry exactly the documented keys with sane values."""
    name = event.get("event")
    assert name in EVENT_KEYS["events"], f"unknown event {name!r}"
    expected = set(EVENT_KEYS["common"]) | set(EVENT_KEYS["events"][name])
    assert set(event) == expected, f"{name} keys: extra {set(event) - expected}, missing {expected - set(event)}"
    assert set(event["app"]) == set(EVENT_KEYS["app"])
    assert all(isinstance(event["app"][k], str) and event["app"][k] for k in EVENT_KEYS["app"]), event["app"]
    assert event["type"] in ("alert", "signal")
    assert (event["type"] == "alert") == (event["user"] is not None)
    assert isinstance(event["timestamp"], (int, float)) and abs(time.time() - event["timestamp"]) < 120
    assert event["user_agent"] == user_agent
    assert isinstance(event["ip"], str) and event["ip"]
    assert isinstance(event["method"], str) and event["method"].isupper()
    assert isinstance(event["path"], str) and event["path"].startswith("/")
    for f in event.get("found_fields") or []:
        assert set(f) == set(EVENT_KEYS["found_field"]), f
        assert f["type"] in ("query", "body")
