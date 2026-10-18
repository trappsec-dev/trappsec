"""Trap response headers, the per-request response hook and callback fallback (R16, R23)."""
import logging
from unittest import mock

import pytest

from trappsec import Sentry


def make_sentry(identity=None):
    with mock.patch.object(Sentry, "_register", lambda self, app: None):
        ts = Sentry(object(), "svc", "test")
    ts._handlers = []
    if identity is not None:
        ts.identify_user(lambda r: identity)
    return ts


def test_hook_gets_the_request_and_the_identity():
    ts = make_sentry({"user": "bob", "role": "owner"})
    seen = []

    def hook(request, ctx):
        seen.append((request, ctx))
        return {"status": 201} if ctx["role"] == "owner" else None

    trap = ts.trap("/t").respond_with(hook).build()
    req = object()
    body, cfg = ts._trigger_trap_event(req, trap)
    assert cfg["status_code"] == 201 and body == "{}"
    assert seen == [(req, {"authenticated": True, "user": "bob", "role": "owner"})]

    ts = make_sentry()
    trap = ts.trap("/t").respond_with(lambda r, ctx: seen.append(ctx)).build()
    assert ts._trigger_trap_event(None, trap)[1]["status_code"] == 401
    assert seen[-1] == {"authenticated": False, "user": None, "role": None}


@pytest.mark.parametrize("result", [
    "not a dict", {"status": True}, {"status": "404"}, {"status": 600},
    {"body": lambda r: "x"}, {"mime_type": 1}, {"headers": {"X": 1}}, {"headers": ["X"]},
])
def test_invalid_hook_result_sends_the_static_response(result, caplog):
    ts = make_sentry()
    trap = ts.trap("/t").if_unauthenticated(status=403, body="static").respond_with(lambda r, c: result).build()
    with caplog.at_level(logging.ERROR, logger="trappsec"):
        body, cfg = ts._trigger_trap_event(None, trap)
    assert (body, cfg["status_code"]) == ("static", 403)
    assert "trap response hook failed" in caplog.text


def test_async_hook_is_rejected_and_the_static_response_sent():
    ts = make_sentry()

    async def hook(request, ctx):
        return {"status": 404}

    trap = ts.trap("/t").if_unauthenticated(status=403, body="static").respond_with(hook).build()
    assert ts._trigger_trap_event(None, trap)[1]["status_code"] == 403


def test_hook_body_that_cannot_be_encoded_sends_the_default_response():
    ts = make_sentry()
    ts.default_unauthenticated_response(body="default")
    circular = []
    circular.append(circular)
    trap = ts.trap("/t").respond_with(lambda r, c: {"status": 404, "body": circular}).build()
    body, cfg = ts._trigger_trap_event(None, trap)
    assert (body, cfg["status_code"]) == ("default", 401)


def test_respond_with_rejects_non_callables():
    with pytest.raises(TypeError):
        make_sentry().trap("/t").respond_with("nope")


@pytest.mark.parametrize("headers, error", [
    (["X"], TypeError), ({"X": 1}, TypeError), ({1: "x"}, TypeError),
    ({"X": "a\r\nb"}, ValueError), ({"X\n": "a"}, ValueError), ({"": "a"}, ValueError), ({"X:Y": "a"}, ValueError),
])
def test_invalid_headers_fail_at_configuration_time(headers, error):
    ts = make_sentry()
    for configure in (lambda: ts.trap("/t").respond(headers=headers),
                      lambda: ts.trap("/t").if_unauthenticated(headers=headers),
                      lambda: ts.default_response(headers=headers),
                      lambda: ts.default_unauthenticated_response(headers=headers),
                      lambda: ts.template("t", 401, {}, "application/json", headers)):
        with pytest.raises(error):
            configure()


def test_template_carries_headers_and_excludes_other_arguments():
    ts = make_sentry()
    ts.template("bearer", 401, {"detail": "Not authenticated"}, headers={"WWW-Authenticate": "Bearer"})
    trap = ts.trap("/t").if_unauthenticated(template="bearer").build()
    body, cfg = ts._trigger_trap_event(None, trap)
    assert cfg["headers"] == {"WWW-Authenticate": "Bearer"} and cfg["status_code"] == 401
    with pytest.raises(TypeError):
        ts.trap("/u").respond(template="bearer", headers={"X": "1"})
    with pytest.raises(TypeError):
        ts.default_response(template="bearer", headers={"X": "1"})


def test_positional_forms_still_work():
    ts = make_sentry({"user": "u", "role": "r"})
    ts.default_response(201, {"ok": True}, "application/json")
    trap = ts.trap("/t").respond(202, "x", "text/plain").build()
    body, cfg = ts._trigger_trap_event(None, trap)
    assert (body, cfg["status_code"], cfg["mime_type"], cfg["headers"]) == ("x", 202, "text/plain", {})


def test_headers_are_copied_from_configuration():
    ts = make_sentry()
    headers = {"Vary": "Accept"}
    builder = ts.trap("/t").if_unauthenticated(headers=headers)
    headers["Vary"] = "changed"
    _, cfg = ts._trigger_trap_event(None, builder.build())
    assert cfg["headers"] == {"Vary": "Accept"}


def test_trap_fallback_keeps_headers_and_never_sends_an_empty_object():
    ts = make_sentry()
    ts.default_unauthenticated_response(body="real", headers={"WWW-Authenticate": "Bearer"})
    trap = ts.trap("/t").if_unauthenticated(body=lambda r: "x", headers={"X": "1"}).build()
    body, cfg = ts._trap_fallback(trap)
    assert body == "real" and cfg["headers"] == {"WWW-Authenticate": "Bearer"}
    body, cfg = ts._trap_fallback(None)
    assert body == "real" and cfg["status_code"] == 401
