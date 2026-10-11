import hashlib
import hmac
import http.server
import json
import logging
import os
import pathlib
import sys
import threading
import time

import pytest

try:
    import trappsec  # noqa: F401
except ImportError:
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from trappsec import handlers
from trappsec.handlers import (
    OTELHandler, SlackHandler, WebhookHandler, _build_slack_payload, _otel_value,
)

requests_missing = handlers.requests is None
needs_requests = pytest.mark.skipif(requests_missing, reason="requests not installed")


class Server:
    def __init__(self, delay=0.0, statuses=None):
        self.delay = delay
        self.statuses = list(statuses or [])
        self.received = []
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("content-length", 0)))
                outer.received.append((dict((k.lower(), v) for k, v in self.headers.items()), body))
                if outer.delay:
                    time.sleep(outer.delay)
                status = outer.statuses.pop(0) if outer.statuses else 200
                self.send_response(status)
                self.send_header("content-length", "0")
                self.end_headers()

            def log_message(self, *a):
                pass

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = "http://127.0.0.1:%d/hook" % self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def wait(self, n, timeout=5):
        end = time.time() + timeout
        while len(self.received) < n and time.time() < end:
            time.sleep(0.01)
        return len(self.received) >= n

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def server():
    s = Server()
    yield s
    s.stop()


ALERT = {"event": "trappsec.trap_hit", "type": "alert", "path": "/x"}


@needs_requests
def test_signature_format(server):
    h = WebhookHandler(server.url, secret="s3cret")
    h.emit(ALERT)
    assert server.wait(1)
    headers, body = server.received[0]
    ts = headers["x-trappsec-timestamp"]
    assert ts.isdigit() and abs(int(ts) - time.time()) < 10
    expected = hmac.new(b"s3cret", ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    assert headers["x-trappsec-signature"] == "sha256=" + expected
    assert json.loads(body)["event"] == "trappsec.trap_hit"
    h.close()


@needs_requests
def test_no_signature_headers_without_secret(server):
    h = WebhookHandler(server.url)
    h.emit(ALERT)
    assert server.wait(1)
    assert "x-trappsec-signature" not in server.received[0][0]
    assert "x-trappsec-timestamp" not in server.received[0][0]
    h.close()


@needs_requests
def test_emit_is_non_blocking_against_slow_server():
    s = Server(delay=1.0)
    try:
        h = WebhookHandler(s.url, timeout=5)
        t0 = time.perf_counter()
        for _ in range(5):
            h.emit(ALERT)
        assert time.perf_counter() - t0 < 0.05 * 5
        h.close(timeout=0.1)
    finally:
        s.stop()


@needs_requests
def test_unreachable_host_does_not_block():
    h = WebhookHandler("http://127.0.0.1:1/hook")
    h.retry_backoff = 0.01
    t0 = time.perf_counter()
    h.emit(ALERT)
    assert time.perf_counter() - t0 < 0.05
    h.close(timeout=2)


@needs_requests
def test_queue_full_drops_and_warns_rate_limited(caplog):
    s = Server(delay=0.5)
    try:
        h = WebhookHandler(s.url, queue_size=2)
        with caplog.at_level(logging.WARNING, logger="trappsec"):
            t0 = time.perf_counter()
            for _ in range(50):
                h.emit(ALERT)
            assert time.perf_counter() - t0 < 0.5
        drops = [r for r in caplog.records if "queue is full" in r.getMessage()]
        assert len(drops) == 1
        h.close(timeout=0.1)
    finally:
        s.stop()


@needs_requests
def test_close_flushes_queue_and_stops_threads(server):
    h = WebhookHandler(server.url, heartbeat_interval=3600)
    for _ in range(5):
        h.emit(ALERT)
    h.close(timeout=5)
    assert len(server.received) == 5
    assert not h._worker.is_alive()
    assert not h._heartbeat.is_alive()
    h.emit(ALERT)  # after close: silently ignored
    time.sleep(0.1)
    assert len(server.received) == 5
    h.close()  # idempotent


@needs_requests
def test_heartbeat_is_sent_signed_and_stoppable(server):
    h = WebhookHandler(server.url, secret="k", heartbeat_interval=1, service="svc")
    assert server.wait(1, timeout=4)
    headers, body = server.received[0]
    assert json.loads(body)["event"] == "trappsec.heartbeat"
    assert headers["x-trappsec-signature"].startswith("sha256=")
    h.close()
    assert not h._heartbeat.is_alive()


@needs_requests
def test_non_2xx_logged_and_5xx_retried(caplog):
    s = Server(statuses=[500, 500, 200])
    try:
        h = WebhookHandler(s.url)
        h.retry_backoff = 0.01
        with caplog.at_level(logging.ERROR, logger="trappsec"):
            h.emit(ALERT)
            h.close(timeout=5)
        assert len(s.received) == 3
        assert sum("HTTP 500" in r.getMessage() for r in caplog.records) == 2
    finally:
        s.stop()


@needs_requests
def test_4xx_logged_not_retried(caplog):
    s = Server(statuses=[404])
    try:
        h = WebhookHandler(s.url)
        with caplog.at_level(logging.ERROR, logger="trappsec"):
            h.emit(ALERT)
            h.close(timeout=5)
        assert len(s.received) == 1
        assert any("HTTP 404" in r.getMessage() for r in caplog.records)
    finally:
        s.stop()


@needs_requests
def test_retries_capped_at_two(server):
    server.statuses = [503] * 10
    h = WebhookHandler(server.url)
    h.retry_backoff = 0.01
    h.emit(ALERT)
    h.close(timeout=5)
    assert len(server.received) == 3


@needs_requests
def test_unserializable_event_still_delivered(server):
    import datetime
    h = WebhookHandler(server.url)
    h.emit(dict(ALERT, when=datetime.datetime(2026, 1, 1), obj=object()))
    h.close()
    assert len(server.received) == 1


@needs_requests
def test_template_failure_drops_event_without_sending_raw(server):
    h = WebhookHandler(server.url, template=lambda e: 1 / 0)
    h.emit(ALERT)
    h.close()
    assert server.received == []


@needs_requests
def test_slack_uses_async_path_and_close(server):
    h = SlackHandler(server.url)
    h.emit(ALERT)
    h.close()
    assert len(server.received) == 1
    assert "attachments" in json.loads(server.received[0][1])


# ---- Slack escaping (C7) -------------------------------------------------

def test_slack_escapes_request_derived_values():
    evil = "<!channel> & <https://evil|click>"
    p = _build_slack_payload({
        "event": "trappsec.watch_hit", "type": "alert", "timestamp": 1712011200,
        "path": evil, "method": "GET", "user_agent": evil, "user": evil, "role": evil,
        "ip": evil, "intent": evil, "reason": evil,
        "found_fields": [{"field": evil, "type": "body", "intent": evil}],
        "app": {"service": evil, "environment": evil, "hostname": evil},
    })
    dumped = json.dumps(p)
    assert "<!channel>" not in dumped and "<https" not in dumped
    assert "&lt;!channel&gt;" in dumped and "&amp;" in dumped
    assert "<!date^1712011200^" in dumped  # generated date token stays intact
    assert p["text"].strip() and "<" not in p["text"]


def test_slack_text_fallback_nonempty_for_all_events():
    for name in ("trappsec.watch_hit", "trappsec.trap_hit", "trappsec.rule_hit", "other"):
        assert _build_slack_payload({"event": name, "type": "signal"})["text"].strip()


# ---- OTel (C8) -----------------------------------------------------------

def test_otel_value_coercion():
    assert _otel_value(None) is None
    assert _otel_value({"a": 1}) == '{"a": 1}'
    assert _otel_value([1, 2]) == [1, 2]
    assert _otel_value([1, "a", None]) == ["1", "a"]
    assert _otel_value([True, False]) == [True, False]
    assert _otel_value(object()).startswith("<object")
    assert _otel_value(2 ** 70) == str(2 ** 70)


def test_otel_handler_emits_valid_attributes():
    pytest.importorskip("opentelemetry.sdk.trace")
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = provider.get_tracer("t")
    with tracer.start_as_current_span("req"):
        OTELHandler().emit({
            "event": "trappsec.watch_hit", "type": "alert", "user": "bob", "role": None, "ip": None,
            "found_fields": [{"type": "body", "field": "f", "value": {"a": 1}, "intent": None},
                             {"type": "body", "field": "g", "value": [1, "x"], "intent": "i"}],
        })
        OTELHandler().emit({
            "event": "trappsec.rule_hit", "type": "signal", "reason": "r", "intent": None,
            "metadata": {"n": None, "d": {"k": 1}, "l": [1, 2], "s": "x"},
        })
    span = exporter.get_finished_spans()[0]
    assert span.attributes["trappsec.user"] == "bob"
    assert span.attributes["metadata.d"] == '{"k": 1}'
    assert "metadata.n" not in span.attributes
    assert len(span.events) == 2
    assert "intent" not in span.events[0].attributes
    assert span.events[0].attributes["value"] == '{"a": 1}'


@needs_requests
@pytest.mark.skipif(not hasattr(os, "fork"), reason="needs os.fork")
@pytest.mark.filterwarnings("ignore::DeprecationWarning")  # fork() with threads running
def test_delivery_and_heartbeat_resume_in_forked_child(server):
    """gunicorn --preload: a handler created before fork() keeps working in the worker."""
    h = WebhookHandler(server.url, heartbeat_interval=1)
    h.emit(ALERT)
    assert server.wait(1)
    pid = os.fork()
    if pid == 0:  # child: worker and heartbeat threads did not survive fork()
        code = 1
        try:
            h.emit(dict(ALERT, path="/child"))
            h.close(timeout=5)
            code = 0
        finally:
            os._exit(code)
    _, status = os.waitpid(pid, 0)
    assert os.waitstatus_to_exitcode(status) == 0
    assert server.wait(2)
    paths = [json.loads(b).get("path") for _, b in server.received]
    assert "/child" in paths
    h.close()


@needs_requests
@pytest.mark.skipif(not hasattr(os, "fork"), reason="needs os.fork")
@pytest.mark.filterwarnings("ignore::DeprecationWarning")
def test_forked_child_does_not_resend_parent_backlog():
    srv = Server(delay=0.3)
    try:
        h = WebhookHandler(srv.url)
        for i in range(3):
            h.emit(dict(ALERT, path="/parent-%d" % i))
        pid = os.fork()  # parent still has queued, undelivered events
        if pid == 0:
            try:
                h.emit(dict(ALERT, path="/child"))
                h.close(timeout=5)
            finally:
                os._exit(0)
        os.waitpid(pid, 0)
        h.close(timeout=5)
        paths = sorted(json.loads(b)["path"] for _, b in srv.received)
        assert paths == ["/child", "/parent-0", "/parent-1", "/parent-2"]
    finally:
        srv.stop()
