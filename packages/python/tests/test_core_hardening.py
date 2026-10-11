"""Async callbacks, same-path watches, is_trap index, heartbeat validation, trap fallback."""
import logging
import warnings
from unittest import mock

import pytest

from trappsec import Sentry
from trappsec import handlers as handlers_mod
from trappsec.core import safe_value, values_match


@pytest.fixture
def ts():
    handlers_mod._async_warned.clear()
    with mock.patch.object(Sentry, "_register", lambda self, app: None):
        s = Sentry(object(), "svc", "test")
    s.request.method = lambda r: r[0]
    s.request.path = lambda r: r[1]
    return s


def test_async_callbacks_use_fallbacks_and_log_once(ts, caplog):
    async def user(r):
        return {"user": "u", "role": "admin"}

    async def ip(r):
        return "9.9.9.9"

    ts.identify_user(user).override_source_ip(ip)
    with warnings.catch_warnings():
        warnings.simplefilter("error")  # "coroutine was never awaited" would raise
        with caplog.at_level(logging.ERROR, logger="trappsec"):
            for _ in range(3):
                ctx = ts.identity.get_context(("GET", "/x"))
                assert ctx == {"user": None, "role": None, "ip": None}
    assert sum("identify_user" in r.getMessage() for r in caplog.records) == 1
    assert sum("override_source_ip" in r.getMessage() for r in caplog.records) == 1


def test_async_default_and_body_fall_back(ts, caplog):
    async def dflt(r):
        return 1

    async def body(r):
        return {"a": 1}

    ts.watch("/p").body("f", default=dflt, intent="i")
    rules = ts.watches[0]["body_fields"]
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        _, found, _ = ts._detect_honey_fields({"f": 1}, rules, None, "body")
        assert [f["field"] for f in found] == ["f"]  # no default: any presence is a violation
        ts._handlers = []
        ts.trap("/t").respond(body=body)
        out, _ = ts._trigger_trap_event(("GET", "/t"), ts.traps[0])
    assert out == "{}"


def test_async_webhook_template_drops_event(caplog):
    pytest.importorskip("requests")
    handlers_mod._async_warned.clear()

    async def tmpl(e):
        return {}

    h = handlers_mod.WebhookHandler("http://127.0.0.1:1/", template=tmpl, alerts_only=False)
    h._send = mock.Mock()
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        h.emit({"type": "alert"})
    h._send.assert_not_called()
    h.close(0.1)


def test_same_path_watches_merge(ts):
    ts.watch("/p").query("a", default=1, intent="one").body("b", intent="b1")
    ts.watch("/q").query("z", intent="z")
    ts.watch("/p").query("a", default=2, intent="two").query("c", intent="c")
    by_path = {w["path"]: w for w in ts.watches}
    assert set(by_path) == {"/p", "/q"}
    assert by_path["/p"]["query_fields"]["a"]["intent"] == "two"
    assert set(by_path["/p"]["query_fields"]) == {"a", "c"}
    assert set(by_path["/p"]["body_fields"]) == {"b"}


def test_watch_build_returns_copies(ts):
    wb = ts.watch("/p")
    wb.query("a", intent="x")
    built = wb.build()
    built["query_fields"]["a"]["intent"] = "changed"
    built["query_fields"]["new"] = {}
    assert wb.build()["query_fields"] == {"a": {"default": wb.build()["query_fields"]["a"]["default"], "intent": "x"}}


@pytest.mark.parametrize("bad", [0, -1, float("inf"), float("nan")])
def test_invalid_heartbeat_interval_runs_no_heartbeat(bad, caplog):
    pytest.importorskip("requests")
    with caplog.at_level(logging.WARNING, logger="trappsec"):
        h = handlers_mod.WebhookHandler("http://127.0.0.1:1/", heartbeat_interval=bad)
    assert h.heartbeat_interval is None and h._heartbeat is None
    assert any("heartbeat" in r.getMessage() for r in caplog.records)
    h.close(0.1)


def test_is_trap_index_is_cached_and_invalidated(ts):
    b = ts.trap("/a").methods("GET")
    assert ts.is_trap(("GET", "/a"))
    index = ts._trap_index
    assert index is not None
    with mock.patch.object(type(b), "build", side_effect=AssertionError("is_trap must not build traps")):
        assert ts.is_trap(("GET", "/a")) and not ts.is_trap(("POST", "/a"))
    assert ts._trap_index is index
    b.methods("POST")
    assert ts.is_trap(("POST", "/a")) and not ts.is_trap(("GET", "/a"))
    ts.trap("/b/:id")
    assert ts.is_trap(("GET", "/b/1"))


def test_trap_fallback(ts):
    ts.trap("/c").if_unauthenticated(body=lambda r: "x")
    ts.trap("/d").if_unauthenticated(body={"k": object})
    ts.trap("/e").if_unauthenticated(body="raw")
    traps = ts.traps
    assert ts._trap_fallback(traps[0])[0] == "{}"
    assert ts._trap_fallback(traps[1])[0].startswith('{"k"')
    body, cfg = ts._trap_fallback(traps[2])
    assert body == "raw" and cfg["status_code"] == 401
    assert ts._trap_fallback(None)[0] == "{}"


def test_depth_limit_without_recursion_error():
    deep = []
    for _ in range(5000):
        deep = [deep]
    assert values_match(deep, "x") is False
    assert safe_value({"k": deep}).count("<nested>") == 1


@pytest.mark.parametrize("override", [lambda r: 1 / 0, lambda r: _coro()])
def test_failing_ip_override_falls_back_to_the_integrations_extractor(override, caplog):
    from flask import Flask
    app = Flask(__name__)
    s = Sentry(app, "svc", "test")
    events = []
    s._handlers.append(type("H", (), {"emit": lambda self, e: events.append(e)})())
    s.override_source_ip(override)
    s.trap("/t")
    with warnings.catch_warnings():
        warnings.simplefilter("error", RuntimeWarning)
        app.test_client().get("/t", environ_base={"REMOTE_ADDR": "9.9.9.9"})
    assert events[0]["ip"] == "9.9.9.9"


async def _coro():
    return "1.2.3.4"
