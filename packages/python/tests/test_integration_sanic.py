import itertools

import pytest

pytest.importorskip("sanic")
pytest.importorskip("sanic_testing")

from sanic import Sanic, json as sjson, text  # noqa: E402

from trappsec.core import Sentry  # noqa: E402

Sanic.test_mode = True
_names = itertools.count()


class Capture:
    def __init__(self):
        self.events = []

    def emit(self, event):
        self.events.append(event)

    def close(self, *a, **k):
        pass


def make_app(configure, identify=None):
    app = Sanic(f"trappsec_sanic_{next(_names)}")

    @app.get("/echo", name="echo_get")
    @app.post("/echo", name="echo_post")
    async def echo(request):
        form = request.form
        return sjson({
            "args": dict(request.args),
            "x_first": request.args.get("x"),
            "x_list": request.args.getlist("x"),
            "a_list": request.args.getlist("a"),
            "query_string": request.query_string,
            "query_args": request.query_args,
            "json": request.json if request.body and "json" in (request.content_type or "") else None,
            "form": dict(form) if form else None,
            "form_x": form.get("x") if form else None,
            "form_a_list": form.getlist("a") if form else None,
            "body": request.body.decode("utf-8", "replace"),
        })

    @app.get("/users/me")
    async def me(request):
        return sjson({"args": dict(request.args)})

    @app.get("/users/<uid:int>")
    async def user(request, uid):
        return sjson({"args": dict(request.args)})

    sentry = Sentry(app, "svc", "test")
    cap = Capture()
    sentry._handlers.append(cap)
    if identify:
        sentry.identify_user(identify)
    configure(sentry)
    return app, sentry, cap


def watch_x(s):
    s.watch("/echo").query("x", intent="q").body("x", intent="b")


def hits(cap, event):
    return [e for e in cap.events if e["event"] == event]


def test_trap_unauthenticated_and_authenticated():
    def conf(s):
        s.trap("/admin/secret")

    def ident(r):
        if r.headers.get("x-user"):
            return {"user": r.headers["x-user"], "role": "admin"}
        return None

    app, s, cap = make_app(conf, ident)
    _, r = app.test_client.get("/admin/secret")
    assert r.status == 401
    _, r = app.test_client.get("/admin/secret", headers={"x-user": "bob"})
    traps = hits(cap, "trappsec.trap_hit")
    assert len(traps) == 2
    assert traps[0]["type"] == "signal" and not traps[0].get("user")
    assert traps[1]["type"] == "alert" and traps[1]["user"] == "bob"


def test_bootstrap_idempotent():
    app, s, cap = make_app(lambda s: s.trap("/t1"))
    s.bootstrap()
    s.bootstrap()
    s.bootstrap()
    _, r = app.test_client.get("/t1")
    assert r.status == 401
    assert len(hits(cap, "trappsec.trap_hit")) == 1


def test_duplicate_trap_fails_loud():
    app, s, cap = make_app(lambda s: s.trap("/echo"))
    with pytest.raises(RuntimeError, match="duplicates an existing"):
        s.bootstrap()


def test_query_detect_strip_and_types_preserved():
    app, s, cap = make_app(watch_x)
    _, r = app.test_client.get("/echo?x=evil&a=1&a=2&keep=")
    d = r.json
    ev = hits(cap, "trappsec.watch_hit")
    assert len(ev) == 1
    f = ev[0]["found_fields"][0]
    assert f["field"] == "x" and f["type"] == "query" and f["value"] == "evil"
    assert d["x_first"] is None and d["x_list"] == []
    assert "x" not in d["query_string"]
    assert "x" not in dict(d["query_args"])
    # non-watched multi values survive and RequestParameters API keeps working
    assert d["a_list"] == ["1", "2"]
    assert "a=1" in d["query_string"] and "a=2" in d["query_string"]


def test_query_duplicate_key_evasion():
    def conf(s):
        s.watch("/echo").query("x", default="ok")

    app, s, cap = make_app(conf)
    _, r = app.test_client.get("/echo?x=ok&x=evil")
    ev = hits(cap, "trappsec.watch_hit")
    assert len(ev) == 1, "x=ok&x=evil must not evade detection"
    assert r.json["x_list"] == []
    cap.events.clear()
    _, r = app.test_client.get("/echo?x=ok")
    assert hits(cap, "trappsec.watch_hit") == []
    assert r.json["x_list"] == []  # still always stripped
    cap.events.clear()
    _, r = app.test_client.get("/echo?x=ok&x=ok")
    assert hits(cap, "trappsec.watch_hit") == []


def test_json_detect_strip():
    app, s, cap = make_app(watch_x)
    _, r = app.test_client.post("/echo", json={"x": "evil", "keep": 1})
    d = r.json
    assert d["json"] == {"keep": 1}
    assert "evil" not in d["body"]
    ev = hits(cap, "trappsec.watch_hit")
    assert ev[0]["found_fields"][0]["type"] == "body"


def test_json_array_and_non_dict_bodies():
    app, s, cap = make_app(watch_x)
    _, r = app.test_client.post("/echo", json=[{"x": "e1", "k": 1}, {"k": 2}, 5])
    assert r.json["json"] == [{"k": 1}, {"k": 2}, 5]
    assert len(hits(cap, "trappsec.watch_hit")) == 1
    _, r = app.test_client.post("/echo", content='"str"', headers={"content-type": "application/json"})
    assert r.status == 200
    _, r = app.test_client.post("/echo", content="{bad", headers={"content-type": "application/json"})
    assert r.status in (200, 400)


def test_form_detect_strip_multivalue_preserved():
    app, s, cap = make_app(watch_x)
    _, r = app.test_client.post("/echo", data="x=evil&a=1&a=2&b=3", headers={"content-type": "application/x-www-form-urlencoded"})
    d = r.json
    assert d["form_x"] is None
    assert d["form_a_list"] == ["1", "2"]
    assert "x=" not in d["body"]
    assert len(hits(cap, "trappsec.watch_hit")) == 1


def test_multipart_strip():
    app, s, cap = make_app(watch_x)
    _, r = app.test_client.post("/echo", data={"x": "evil", "a": "1"}, files={"f": ("f.txt", b"hello")})
    d = r.json
    assert d["form"] is not None and "x" not in d["form"]
    assert "evil" not in d["body"]
    assert "hello" in d["body"]
    assert len(hits(cap, "trappsec.watch_hit")) == 1


def test_raising_identify_user_does_not_break_request():
    def boom(r):
        raise RuntimeError("identify exploded")

    app, s, cap = make_app(watch_x, boom)
    _, r = app.test_client.get("/echo?x=evil&a=1")
    assert r.status == 200
    assert r.json["x_list"] == []
    assert r.json["a_list"] == ["1"]


def test_raising_identify_user_trap_still_decoys():
    def boom(r):
        raise RuntimeError("identify exploded")

    app, s, cap = make_app(lambda s: s.trap("/t2"), boom)
    _, r = app.test_client.get("/t2")
    assert r.status == 401


def test_no_global_request_patching():
    from sanic.request import Request

    app, s, cap = make_app(watch_x)
    assert isinstance(Request.__dict__["args"], property)
    assert not getattr(Request, "_trappsec_overrides_patched", False)
    assert Request.json.fget.__module__.startswith("sanic")


def test_param_route_watch_and_static_route_not_watched():
    def conf(s):
        s.watch("/users/<uid:int>").query("x")

    app, s, cap = make_app(conf)
    _, r = app.test_client.get("/users/5?x=1")
    assert r.json["args"] == {}
    assert len(hits(cap, "trappsec.watch_hit")) == 1
    cap.events.clear()
    _, r = app.test_client.get("/users/me?x=1")
    assert r.json["args"] == {"x": ["1"]}
    assert hits(cap, "trappsec.watch_hit") == []


import codecs  # noqa: E402
import json as _json  # noqa: E402

_PAYLOAD = {"x": "evil", "name": "n"}


@pytest.mark.parametrize("ctype,raw", [
    ("application/json", _json.dumps(_PAYLOAD).encode("utf-16")),
    ("application/json", _json.dumps(_PAYLOAD).encode("utf-32")),
    ("application/json", codecs.BOM_UTF8 + _json.dumps(_PAYLOAD).encode()),
    ("application/json; charset=utf-16", _json.dumps(_PAYLOAD).encode("utf-16")),
    ("text/plain", _json.dumps(_PAYLOAD).encode()),
    ("application/vnd.api+json", _json.dumps(_PAYLOAD).encode()),
])
def test_encoding_and_content_type_bypasses_stripped(ctype, raw):
    app, s, cap = make_app(watch_x)
    _, r = app.test_client.post("/echo", content=raw, headers={"content-type": ctype})
    assert _json.loads(r.json["body"]) == {"name": "n"}
    assert len(hits(cap, "trappsec.watch_hit")) == 1
