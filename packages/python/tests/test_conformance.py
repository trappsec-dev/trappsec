"""Shared cross-language cases from tests/conformance (R17, R18)."""
import json
import logging
import os
import pathlib
import sys

from unittest import mock

import pytest

try:
    import trappsec  # noqa: F401
except ImportError:
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from trappsec import Sentry, WatchBuilder
from trappsec.core import values_match

CONFORMANCE = pathlib.Path(__file__).resolve().parents[3] / "tests" / "conformance"


def _load(name):
    path = CONFORMANCE / name
    if not path.exists() and not os.environ.get("CI"):
        return [pytest.param(None, marks=pytest.mark.skip(reason=f"{name} not found (outside the trappsec repository)"))]
    return json.loads(path.read_text(encoding="utf-8"))["cases"]


def _bare_sentry():
    ts = Sentry.__new__(Sentry)  # skip framework registration
    ts.logger = logging.getLogger("trappsec-test")
    return ts


@pytest.mark.parametrize("case", _load("values_match.json"), ids=lambda c: c.get("note") or f"{c['actual']!r}~{c['expected']!r}" if c else "missing")
def test_values_match(case):
    assert values_match(_expand(case["actual"]), _expand(case["expected"])) is case["match"]


@pytest.mark.parametrize("case", _load("detect_honey_fields.json"), ids=lambda c: c["name"] if c else "missing")
def test_detect_honey_fields(case):
    source = case.get("source", "body")
    wb = WatchBuilder("/x")
    add = wb.query if source == "query" else wb.body
    for field, rule in case["rules"].items():
        if "default" in rule:
            add(field, default=_expand(rule["default"]), intent=rule["intent"])
        else:
            add(field, intent=rule["intent"])
    built = wb.build()
    rules = built["query_fields"] if source == "query" else built["body_fields"]

    data, found, touched = _bare_sentry()._detect_honey_fields(_expand(case["data"]), rules, None, source)

    expected = [dict(f, type=source) for f in _expand(case["found"])]
    key = lambda f: f["field"]  # noqa: E731
    assert sorted(found, key=key) == sorted(expected, key=key)
    assert data == _expand(case["result"])
    assert touched is case["touched"]


def _event_keys_fixture():
    path = CONFORMANCE / "event_keys.json"
    if not path.exists() and not os.environ.get("CI"):
        pytest.skip("event_keys.json not found (outside the trappsec repository)")
    return json.loads(path.read_text(encoding="utf-8"))


def test_event_keys():
    fx = _event_keys_fixture()
    with mock.patch.object(Sentry, "_register", lambda self, app: None):
        ts = Sentry(object(), "svc", "test")
    events = []
    ts._handlers = [type("Cap", (), {"emit": lambda self, e: events.append(e)})()]
    ts._trigger_trap_event(None, ts.trap("/t").build())
    ts._trigger_watch_event(None, [{"type": "body", "field": "f", "value": 1, "intent": None}])
    ts.trigger(None, "reason")

    assert [e["event"] for e in events] == list(fx["events"])
    for e in events:
        assert sorted(e) == sorted(fx["common"] + fx["events"][e["event"]]), e["event"]
        assert sorted(e["app"]) == sorted(fx["app"])
    assert sorted(events[1]["found_fields"][0]) == sorted(fx["found_field"])


def _expand(v):
    """Expand {"$repeat": s, "count": n, "prefix": p, "suffix": x} and
    {"$nest": n, "leaf": x} (x in n single-element lists, built iteratively) placeholders."""
    if isinstance(v, dict):
        if "$repeat" in v:
            return v.get("prefix", "") + v["$repeat"] * v["count"] + v.get("suffix", "")
        if "$nest" in v:
            out = _expand(v["leaf"])
            for _ in range(v["$nest"]):
                out = [out]
            return out
        return {k: _expand(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_expand(x) for x in v]
    return v


@pytest.mark.parametrize("case", _load("safe_value.json"), ids=lambda c: c["name"] if c else "missing")
def test_safe_value(case):
    from trappsec.core import safe_value

    assert safe_value(_expand(case["input"])) == _expand(case["output"])


def test_event_path_and_user_agent_truncation():
    path = CONFORMANCE / "safe_value.json"
    if not path.exists() and not os.environ.get("CI"):
        pytest.skip("safe_value.json not found (outside the trappsec repository)")
    fx = _expand(json.loads(path.read_text(encoding="utf-8"))["events"])
    with mock.patch.object(Sentry, "_register", lambda self, app: None):
        ts = Sentry(object(), "svc", "test")
    ts.request.path = lambda r: fx["path"]
    ts.request.user_agent = lambda r: fx["user_agent"]
    ts.request.method = lambda r: "GET"
    events = []
    ts._handlers = [type("Cap", (), {"emit": lambda self, e: events.append(e)})()]
    ts.trigger(None, "reason")
    assert events[0]["path"] == fx["path_out"]
    assert events[0]["user_agent"] == fx["user_agent_out"]


def _is_trap_fixture():
    path = CONFORMANCE / "is_trap.json"
    if not path.exists() and not os.environ.get("CI"):
        return [pytest.param(None, marks=pytest.mark.skip(reason="is_trap.json not found (outside the trappsec repository)"))]
    return [json.loads(path.read_text(encoding="utf-8"))]


@pytest.mark.parametrize("fx", _is_trap_fixture())
def test_is_trap(fx):
    with mock.patch.object(Sentry, "_register", lambda self, app: None):
        ts = Sentry(object(), "svc", "test")
    for t in fx["traps"]:
        ts.trap(t["path"]).methods(*t["methods"])
    ts.request.method = lambda r: r[0]
    ts.request.path = lambda r: r[1]
    for case in fx["cases"]:
        assert ts.is_trap((case["method"], case["path"])) is case["is_trap"], case
