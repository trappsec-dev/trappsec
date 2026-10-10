import datetime
import json
import logging
import pathlib
import sys
from unittest import mock

import pytest

try:
    import trappsec  # noqa: F401
except ImportError:
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

import trappsec
from trappsec import NO_DEFAULT, Sentry
from trappsec.core import safe_value, values_match


def make_sentry():
    with mock.patch.object(Sentry, "_register", lambda self, app: None):
        ts = Sentry(object(), "svc", "test")
    ts.request.path = lambda r: "/p"
    ts.request.method = lambda r: "GET"
    ts.request.user_agent = lambda r: "ua"
    return ts


class Capture:
    def __init__(self):
        self.events = []

    def emit(self, event):
        self.events.append(event)


# ---- exports / logging ---------------------------------------------------

def test_exports():
    for name in ("Sentry", "NO_DEFAULT", "TrapBuilder", "WatchBuilder"):
        assert name in trappsec.__all__ and hasattr(trappsec, name)


def test_no_basicconfig_and_no_logging_error(capsys):
    root = logging.getLogger()
    before = list(root.handlers)
    with mock.patch("logging.basicConfig") as bc:
        ts = make_sentry()
    assert not bc.called
    assert root.handlers == before

    ts.identify_user(lambda r: 1 / 0)
    cap = Capture()
    ts._handlers = [mock.Mock(emit=mock.Mock(side_effect=RuntimeError("boom")))]
    ts.trigger(object(), "r")  # handler error is logged with %s, not raised
    assert "Logging error" not in capsys.readouterr().err


def test_bootstrap_delegates_and_tolerates_missing():
    ts = make_sentry()
    assert ts.bootstrap() is None
    ts.integration = mock.Mock()
    ts.bootstrap()
    ts.integration.bootstrap.assert_called_once()


# ---- callbacks (C1) ------------------------------------------------------

def test_identity_callbacks_never_raise():
    ts = make_sentry()
    ts.identify_user(lambda r: 1 / 0)
    ts.override_source_ip(lambda r: 1 / 0)
    assert ts.identity.get_context(object()) == {"user": None, "role": None, "ip": None}


def test_callable_default_that_raises_is_violation_and_still_strips():
    ts = make_sentry()
    rules = {"role": {"default": lambda r: 1 / 0, "intent": "x"}}
    data, found, touched = ts._detect_honey_fields({"role": "user", "a": 1}, rules, None)
    assert data == {"a": 1} and touched and len(found) == 1


def test_dynamic_body_raising_falls_back_to_empty_object():
    ts = make_sentry()
    trap = ts.trap("/t").respond(body=lambda r: 1 / 0).if_unauthenticated(body=lambda r: 1 / 0).build()
    body, cfg = ts._trigger_trap_event(object(), trap)
    assert body == "{}"


# ---- events (C3/C4) ------------------------------------------------------

def test_events_always_have_user_role_keys_and_truncate():
    ts = make_sentry()
    ts.request.path = lambda r: "x" * 5000
    ts.request.user_agent = lambda r: "u" * 5000
    cap = Capture()
    ts._handlers = [cap]
    ts.trigger(object(), "why", metadata={"when": datetime.datetime(2026, 1, 1)})
    ts._trigger_watch_event(object(), [])
    ev = cap.events[0]
    assert ev["user"] is None and ev["role"] is None and ev["type"] == "signal"
    assert len(ev["path"]) == 1027 and ev["path"].endswith("...")
    assert len(ev["user_agent"]) == 1027
    for e in cap.events:
        assert {"user", "role", "ip", "user_agent", "path", "method"} <= set(e)
        json.dumps(e, default=str)


def test_log_handler_survives_datetime_metadata(caplog):
    ts = make_sentry()
    with caplog.at_level(logging.WARNING, logger="trappsec"):
        ts.trigger(object(), "r", metadata={"when": datetime.datetime(2026, 1, 1)})
    assert any("2026-01-01" in r.getMessage() for r in caplog.records)


def test_authenticated_event_is_alert():
    ts = make_sentry()
    ts.identify_user(lambda r: {"user": "bob", "role": "admin"})
    cap = Capture()
    ts._handlers = [cap]
    ts.trigger(object(), "r")
    assert cap.events[0]["type"] == "alert" and cap.events[0]["user"] == "bob"


# ---- trap bodies & builders ---------------------------------------------

def test_string_body_is_sent_raw_for_json():
    ts = make_sentry()
    trap = ts.trap("/t").if_unauthenticated(body="plain text").build()
    body, _ = ts._trigger_trap_event(object(), trap)
    assert body == "plain text"


def test_dict_body_json_encoded_and_default_str():
    ts = make_sentry()
    trap = ts.trap("/t").if_unauthenticated(body={"d": datetime.date(2026, 1, 2)}).build()
    body, _ = ts._trigger_trap_event(object(), trap)
    assert json.loads(body) == {"d": "2026-01-02"}


def test_falsy_builder_values_honored():
    ts = make_sentry()
    cfg = ts.trap("/t").respond(status=0, body={}, mime_type="").if_unauthenticated(body="").build()
    assert cfg["response.authenticated"]["status_code"] == 0
    assert cfg["response.authenticated"]["response_body"] == {}
    assert cfg["response.unauthenticated"]["response_body"] == ""


def test_defaults_resolved_at_build_time_not_trap_time():
    ts = make_sentry()
    builder = ts.trap("/t")  # registered before defaults change
    ts.default_responses["unauthenticated"]["status_code"] = 403
    ts.default_responses["authenticated"]["status_code"] = 202
    cfg = ts.traps[0]
    assert cfg["response.unauthenticated"]["status_code"] == 403
    assert cfg["response.authenticated"]["status_code"] == 202
    builder.if_unauthenticated(status=418)
    assert ts.traps[0]["response.unauthenticated"]["status_code"] == 418
    assert ts.traps[0]["response.unauthenticated"]["mime_type"] == "application/json"


def test_template_preserves_callable_body():
    ts = make_sentry()
    fn = lambda r: {"x": 1}
    ts.template("t", 200, fn)
    cfg = ts.trap("/t").respond(template="t").build()
    assert cfg["response.authenticated"]["response_body"] is fn


# ---- values_match / safe_value ------------------------------------------

@pytest.mark.parametrize("a,e,ok", [
    (5, 5.0, True), ("5", 5, True), (5, "5", True), ("5.0", 5, False),
    ("true", True, True), (True, "true", True), ("True", True, False),
    (1, True, False), ("1", True, False), ("admin", "admin", True),
    ("a", "b", False), (1.5, "1.5", True), (None, None, True), ("x", None, False),
])
def test_values_match(a, e, ok):
    assert values_match(a, e) is ok


def test_safe_value():
    class UploadFile:
        pass
    assert safe_value(None) is None and safe_value(True) is True and safe_value(3) == 3
    assert safe_value("a" * 2000) == "a" * 1024 + "..."
    assert safe_value(UploadFile()) == "<UploadFile>"
    assert safe_value(b"xx") == "<bytes>"
    assert len(safe_value(list(range(50)))) == 20
    assert safe_value({"d": datetime.date(2026, 1, 1)}) == '{"d":"2026-01-01"}'
    assert len(safe_value({"k": "v" * 3000})) == 1027


# ---- _detect_honey_fields (C3) ------------------------------------------

def test_source_param_sets_type():
    ts = make_sentry()
    _, found, _ = ts._detect_honey_fields({"t": "x"}, {"t": {"default": NO_DEFAULT}}, None, source="query")
    assert found[0]["type"] == "query"
    _, found, _ = ts._detect_honey_fields({"t": "x"}, {"t": {"default": NO_DEFAULT}})
    assert found[0]["type"] == "body"


def test_duplicate_key_evasion_is_violation_and_stripped():
    ts = make_sentry()
    rules = {"is_admin": {"default": "0", "intent": "pe"}}
    data, found, touched = ts._detect_honey_fields({"is_admin": ["1", "0"], "k": ["a", "b"]}, rules, None, "query")
    assert len(found) == 1 and found[0]["value"] == ["1", "0"]
    assert data == {"k": ["a", "b"]} and touched


def test_multi_values_all_matching_is_clean_single_element_scalar():
    ts = make_sentry()
    rules = {"f": {"default": "0"}}
    _, found, _ = ts._detect_honey_fields({"f": ["0", "0"]}, rules)
    assert found == []
    _, found, _ = ts._detect_honey_fields({"f": ["0"]}, rules)
    assert found == []
    _, found, _ = ts._detect_honey_fields({"f": ["1"]}, rules)
    assert found[0]["value"] == "1"


def test_loose_numeric_matching_in_detection():
    ts = make_sentry()
    rules = {"qty": {"default": 5}, "on": {"default": True}}
    _, found, _ = ts._detect_honey_fields({"qty": "5", "on": "true"}, rules)
    assert found == []


def test_upload_value_is_sanitized_and_serializable():
    class UploadFile:
        filename = "x"
    ts = make_sentry()
    _, found, _ = ts._detect_honey_fields({"f": UploadFile()}, {"f": {"default": NO_DEFAULT}})
    assert found[0]["value"] == "<UploadFile>"
    json.dumps(found)


def test_non_dict_data_returned_unchanged():
    ts = make_sentry()
    rules = {"a": {"default": NO_DEFAULT}}
    for d in ("str", 5, None, 1.5, True):
        assert ts._detect_honey_fields(d, rules) == (d, [], False)


def test_top_level_array_inspects_object_elements():
    ts = make_sentry()
    rules = {"a": {"default": NO_DEFAULT}}
    data = [{"a": 1, "b": 2}, 7, "s", {"c": 3}, {"a": 2}]
    out, found, touched = ts._detect_honey_fields(data, rules)
    assert touched and len(found) == 2
    assert out == [{"b": 2}, 7, "s", {"c": 3}, {}]


def test_watched_key_lookup_does_not_match_object_attributes():
    ts = make_sentry()
    data, found, touched = ts._detect_honey_fields({"constructor": 1}, {"a": {}})
    assert not touched and data == {"constructor": 1}
