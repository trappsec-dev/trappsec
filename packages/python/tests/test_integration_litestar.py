import json

import pytest

pytest.importorskip("litestar")
pytest.importorskip("httpx")

from litestar import Litestar, Request, get, post  # noqa: E402
from litestar.testing import TestClient  # noqa: E402

from trappsec.core import Sentry  # noqa: E402


class Capture:
    def __init__(self):
        self.events = []

    def emit(self, event):
        self.events.append(event)

    def close(self, *a, **k):
        pass


def make(configure, identify=None, with_lifespan=True):
    @get("/echo")
    async def echo_get(request: Request) -> dict:
        return await _echo(request)

    @post("/echo", status_code=200)
    async def echo_post(request: Request) -> dict:
        return await _echo(request)

    @get("/users/me")
    async def me(request: Request) -> dict:
        return {"who": "me", "query": request.scope["query_string"].decode(), "q": dict(request.query_params)}

    @get("/users/{uid:int}")
    async def user(uid: int, request: Request) -> dict:
        return {"who": uid, "query": request.scope["query_string"].decode()}

    app = Litestar(route_handlers=[echo_get, echo_post, me, user])
    sentry = Sentry(app, "svc", "test")
    cap = Capture()
    sentry._handlers.append(cap)
    if identify:
        sentry.identify_user(identify)
    configure(sentry)
    return app, sentry, cap


async def _echo(request):
    body = await request.body()
    out = {
        "query": request.scope["query_string"].decode(),
        "q": request.query_params.getall("a", []),
        "x": request.query_params.get("x"),
        "body": body.decode("utf-8", "replace"),
        "clen": request.headers.get("content-length"),
    }
    ct = request.headers.get("content-type", "")
    if "json" in ct and body:
        try:
            out["json"] = await request.json()
        except Exception:
            out["json"] = "unparseable"
    if "urlencoded" in ct or "multipart" in ct:
        form = await request.form()
        out["form_x"] = form.get("x")
        out["form_a"] = form.getall("a", []) if hasattr(form, "getall") else None
    return out


def watch_x(s):
    s.watch("/echo").query("x", intent="q").body("x", intent="b")


def hits(cap, event):
    return [e for e in cap.events if e["event"] == event]


def test_trap_unauth_and_auth_lazy_bootstrap_no_lifespan():
    def ident(request):
        # a real litestar Request: cookies and headers must be available
        assert hasattr(request, "cookies") and hasattr(request, "state")
        if request.cookies.get("sid") == "s1":
            return {"user": "bob", "role": "admin"}
        return None

    app, s, cap = make(lambda s: s.trap("/admin/secret"), ident)
    client = TestClient(app)  # no `with`: lifespan never runs
    r = client.get("/admin/secret")
    assert r.status_code == 401
    r = client.get("/admin/secret", cookies={"sid": "s1"})
    traps = hits(cap, "trappsec.trap_hit")
    assert [t["type"] for t in traps] == ["signal", "alert"]
    assert traps[1]["user"] == "bob"


def test_bootstrap_idempotent_with_lifespan():
    app, s, cap = make(lambda s: s.trap("/t1"))
    s.bootstrap()
    s.bootstrap()
    with TestClient(app) as client:
        assert client.get("/t1").status_code == 401
    assert len(hits(cap, "trappsec.trap_hit")) == 1


def test_duplicate_trap_fails_loud():
    app, s, cap = make(lambda s: s.trap("/echo").methods("GET"))
    with pytest.raises(RuntimeError, match="duplicates an existing"):
        s.bootstrap()


def test_query_detect_strip_and_multivalue():
    app, s, cap = make(watch_x)
    with TestClient(app) as c:
        d = c.get("/echo?x=evil&a=1&a=2&b=").json()
    assert d["x"] is None
    assert d["q"] == ["1", "2"]
    assert "x=" not in d["query"].replace("b=", "")
    ev = hits(cap, "trappsec.watch_hit")
    assert len(ev) == 1
    f = ev[0]["found_fields"][0]
    assert f["type"] == "query" and f["field"] == "x" and f["value"] == "evil"


def test_query_duplicate_key_evasion():
    app, s, cap = make(lambda s: s.watch("/echo").query("x", default="ok"))
    with TestClient(app) as c:
        d = c.get("/echo?x=ok&x=evil").json()
        assert len(hits(cap, "trappsec.watch_hit")) == 1
        assert d["x"] is None
        cap.events.clear()
        c.get("/echo?x=ok")
        c.get("/echo?x=ok&x=ok")
        assert hits(cap, "trappsec.watch_hit") == []


def test_json_strip_updates_content_length():
    app, s, cap = make(watch_x)
    payload = {"x": "evil" * 100, "keep": 1}
    with TestClient(app) as c:
        d = c.post("/echo", json=payload).json()
    assert d["json"] == {"keep": 1}
    assert int(d["clen"]) == len(d["body"].encode())
    assert len(hits(cap, "trappsec.watch_hit")) == 1


def test_json_array_and_junk():
    app, s, cap = make(watch_x)
    with TestClient(app) as c:
        d = c.post("/echo", json=[{"x": 1, "k": 1}, 5]).json()
        assert d["json"] == [{"k": 1}, 5]
        r = c.post("/echo", content=b"{bad", headers={"content-type": "application/json"})
        assert r.status_code == 200 and r.json()["body"] == "{bad"
        r = c.post("/echo", content=b'"str"', headers={"content-type": "application/json"})
        assert r.status_code == 200


def test_form_strip_multivalue_preserved():
    app, s, cap = make(watch_x)
    with TestClient(app) as c:
        d = c.post("/echo", data={"x": "evil", "a": ["1", "2"], "b": "3"}).json()
    assert d["form_x"] is None
    assert d["form_a"] == ["1", "2"]
    assert "x=" not in d["body"]
    assert len(hits(cap, "trappsec.watch_hit")) == 1


def test_multipart_strip():
    app, s, cap = make(watch_x)
    with TestClient(app) as c:
        d = c.post("/echo", data={"x": "evil", "a": "1"}, files={"f": ("f.txt", b"hello")}).json()
    assert d["form_x"] is None
    assert "evil" not in d["body"] and "hello" in d["body"]
    assert int(d["clen"]) == len(d["body"].encode())
    assert len(hits(cap, "trappsec.watch_hit")) == 1


def test_no_body_buffering_when_only_query_watched():
    app, s, cap = make(lambda s: s.watch("/echo").query("x"))
    seen = {}
    orig = s.integration._read_body

    async def spy(*a, **k):
        seen["called"] = True
        return await orig(*a, **k)

    s.integration._read_body = spy
    with TestClient(app) as c:
        c.post("/echo", json={"x": 1})
    assert "called" not in seen


def test_raising_identify_user_does_not_500():
    def boom(r):
        raise RuntimeError("x")

    app, s, cap = make(watch_x, boom)
    with TestClient(app) as c:
        r = c.get("/echo?x=evil&a=1")
        assert r.status_code == 200 and r.json()["x"] is None and r.json()["q"] == ["1"]
        r = c.post("/echo", json={"x": 1, "k": 2})
        assert r.status_code == 200 and r.json()["json"] == {"k": 2}


def test_raising_identify_user_trap_decoy():
    def boom(r):
        raise RuntimeError("x")

    app, s, cap = make(lambda s: s.trap("/t3"), boom)
    with TestClient(app) as c:
        assert c.get("/t3").status_code == 401


def test_static_vs_param_route():
    app, s, cap = make(lambda s: s.watch("/users/{uid}").query("x"))
    with TestClient(app) as c:
        r = c.get("/users/5?x=1&y=2").json()
        assert r["query"] == "y=2"
        assert len(hits(cap, "trappsec.watch_hit")) == 1
        r = c.get("/users/me?x=1&y=2").json()
        assert r["who"] == "me" and "x=1" in r["query"]
        assert len(hits(cap, "trappsec.watch_hit")) == 1  # unchanged: static route not watched
    cap.events.clear()


def test_typed_param_watch_template():
    app, s, cap = make(lambda s: s.watch("/users/{uid:int}").query("x"))
    with TestClient(app) as c:
        assert c.get("/users/5?x=1").json()["query"] == ""
        assert len(hits(cap, "trappsec.watch_hit")) == 1


def test_trap_json_body_is_not_double_encoded():
    app, s, cap = make(lambda s: s.trap("/t4").if_unauthenticated(status=403, body={"a": 1}))
    with TestClient(app) as c:
        r = c.get("/t4")
        assert r.status_code == 403 and r.json() == {"a": 1}


import codecs  # noqa: E402

_PAYLOAD = {"x": "evil", "name": "n"}
_VARIANTS = [
    ("application/json", json.dumps(_PAYLOAD).encode("utf-16")),
    ("application/json", json.dumps(_PAYLOAD).encode("utf-32")),
    ("application/json", codecs.BOM_UTF8 + json.dumps(_PAYLOAD).encode()),
    ("application/json; charset=utf-16", json.dumps(_PAYLOAD).encode("utf-16")),
    ("text/plain", json.dumps(_PAYLOAD).encode()),
    ("application/vnd.api+json", json.dumps(_PAYLOAD).encode()),
]


@pytest.mark.parametrize("ctype,raw", _VARIANTS)
def test_encoding_and_content_type_bypasses_stripped(ctype, raw):
    app, s, cap = make(watch_x)
    with TestClient(app) as c:
        d = c.post("/echo", content=raw, headers={"content-type": ctype}).json()
        assert json.loads(d["body"]) == {"name": "n"}
        assert int(d["clen"]) == len(d["body"].encode())
        assert len(hits(cap, "trappsec.watch_hit")) == 1


def test_body_over_inspect_limit_passes_through_intact(monkeypatch):
    import trappsec.integrations.litestar as ls_integration

    monkeypatch.setattr(ls_integration, "MAX_INSPECT_BYTES", 200)
    app, s, cap = make(watch_x)
    big = json.dumps({"x": "evil", "pad": "a" * 5000}).encode()
    with TestClient(app) as c:
        d = c.post("/echo", content=big, headers={"content-type": "application/json"}).json()
    assert d["body"] == big.decode()
    assert hits(cap, "trappsec.watch_hit") == []


def test_streamed_body_over_inspect_limit_is_replayed_intact(monkeypatch):
    """No content-length: the chunks read before the limit are replayed, then the rest streams."""
    import asyncio
    import trappsec.integrations.litestar as ls_integration

    monkeypatch.setattr(ls_integration, "MAX_INSPECT_BYTES", 200)
    app, s, cap = make(watch_x)
    big = json.dumps({"x": "evil", "pad": "a" * 5000}).encode()
    chunks = [big[i:i + 150] for i in range(0, len(big), 150)]
    messages = [{"type": "http.request", "body": ch, "more_body": i < len(chunks) - 1} for i, ch in enumerate(chunks)]
    sent = []

    async def receive():
        return messages.pop(0) if messages else {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "POST",
        "scheme": "http", "path": "/echo", "raw_path": b"/echo", "root_path": "", "query_string": b"",
        "headers": [(b"host", b"testserver"), (b"content-type", b"application/json")],
        "client": ("127.0.0.1", 1234), "server": ("testserver", 80), "state": {},
    }
    asyncio.run(app(scope, receive, send))
    body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    assert json.loads(body)["body"] == big.decode()
    assert hits(cap, "trappsec.watch_hit") == []


def test_body_under_inspect_limit_is_inspected(monkeypatch):
    import trappsec.integrations.litestar as ls_integration

    monkeypatch.setattr(ls_integration, "MAX_INSPECT_BYTES", 200)
    app, s, cap = make(watch_x)
    with TestClient(app) as c:
        d = c.post("/echo", json={"x": "evil", "pad": "a" * 50}).json()
    assert d["json"] == {"pad": "a" * 50}
    assert len(hits(cap, "trappsec.watch_hit")) == 1


@pytest.mark.parametrize("key", [None, "skip_csrf"])
def test_traps_answer_under_csrf_protection(key):
    """R22: CSRF middleware must not turn a POST trap into a silent 403."""
    from litestar.config.csrf import CSRFConfig

    @post("/real", status_code=200)
    async def real() -> dict:
        return {"ok": True}

    cfg = CSRFConfig(secret="s") if key is None else CSRFConfig(secret="s", exclude_from_csrf_key=key)
    app = Litestar(route_handlers=[real], csrf_config=cfg)
    sentry = Sentry(app, "svc", "test")
    cap = Capture()
    sentry._handlers.append(cap)
    sentry.trap("/admin/backup").methods("POST")
    with TestClient(app) as c:
        assert c.post("/real", data={"a": "1"}).status_code == 403  # CSRF still protects real routes
        assert c.post("/admin/backup", data={"a": "1"}).status_code == 401
    assert len(hits(cap, "trappsec.trap_hit")) == 1


def test_watch_on_router_route():
    """R7: routes mounted through a Router (with a path prefix) are watched."""
    from litestar import Router

    @post("/users/{uid:str}", status_code=200)
    async def user(uid: str, request: Request) -> dict:
        return {"args": dict(request.query_params), "json": await request.json()}

    app = Litestar(route_handlers=[Router(path="/api", route_handlers=[user])])
    sentry = Sentry(app, "svc", "test")
    cap = Capture()
    sentry._handlers.append(cap)
    sentry.watch("/api/users/{uid:str}").query("debug", intent="q").body("is_admin", intent="b")
    with TestClient(app) as c:
        r = c.post("/api/users/7?debug=1&x=1", json={"is_admin": True, "n": 1})
    assert r.json() == {"args": {"x": "1"}, "json": {"n": 1}}
    [event] = hits(cap, "trappsec.watch_hit")
    assert {f["field"] for f in event["found_fields"]} == {"debug", "is_admin"}


def _multipart(boundary, *parts):
    out = b""
    for head, value in parts:
        out += b"--" + boundary + b"\r\n" + head + b"\r\n\r\n" + value + b"\r\n"
    return out + b"--" + boundary + b"--\r\n"


def test_multipart_boundary_text_inside_value_does_not_end_parsing():
    # The route reads the raw body only: Litestar's own multipart parser rejects
    # boundary text inside a value on some supported versions (2.13), so the
    # handler's form() is not what this test is about. The body it is handed
    # must lose only the honey part, and the event must be sent.
    @post("/raw", status_code=200)
    async def raw(request: Request) -> dict:
        return {"body": (await request.body()).decode("utf-8", "replace")}

    app = Litestar(route_handlers=[raw])
    sentry = Sentry(app, "svc", "test")
    cap = Capture()
    sentry._handlers.append(cap)
    sentry.watch("/raw").body("x", intent="b")
    body = _multipart(
        b"XB",
        (b'Content-Disposition: form-data; name="a"', b"1 --XB-- 2"),
        (b'Content-Disposition: form-data; name="x"', b"evil"),
        (b'Content-Disposition: form-data; name="b"', b"3"),
    )
    with TestClient(app) as c:
        d = c.post("/raw", content=body, headers={"content-type": "multipart/form-data; boundary=XB"}).json()
    assert "evil" not in d["body"] and "1 --XB-- 2" in d["body"] and 'name="b"' in d["body"]
    (hit,) = hits(cap, "trappsec.watch_hit")
    assert [f["field"] for f in hit["found_fields"]] == ["x"]


def test_multipart_file_part_under_watched_name_detected_and_stripped():
    app, s, cap = make(watch_x)
    with TestClient(app) as c:
        d = c.post("/echo", files={"x": ("a.txt", b"secret-bytes"), "f": ("f.txt", b"hello")}).json()
    assert d["form_x"] is None
    assert "secret-bytes" not in d["body"] and "hello" in d["body"]
    (hit,) = hits(cap, "trappsec.watch_hit")
    assert hit["found_fields"][0]["field"] == "x"
    assert hit["found_fields"][0]["value"] == "<bytes>"


def test_single_occurrence_scalar_multiple_occurrences_list():
    app, s, cap = make(watch_x)
    with TestClient(app) as c:
        c.get("/echo?x=one")
        c.get("/echo?x=one&x=two")
    one, two = [h["found_fields"][0]["value"] for h in hits(cap, "trappsec.watch_hit")]
    assert one == "one" and two == ["one", "two"]


def test_unrelated_non_utf8_query_value_preserved():
    app, s, cap = make(lambda s: s.watch("/echo").query("a"))
    with TestClient(app) as c:
        d = c.get("/echo?p=%ff&a=1&q=%C3%A9").json()
    assert d["query"] == "p=%ff&q=%C3%A9"


def test_route_template_normalisation_is_memoised():
    from trappsec.integrations.litestar import _normalize_template
    _normalize_template.cache_clear()
    for _ in range(3):
        assert _normalize_template("/u/{id:int}/") == "/u/{id}"
    assert _normalize_template.cache_info().hits == 2


def test_failing_trap_event_answers_with_the_traps_own_unauthenticated_response():
    app, s, cap = make(lambda s: s.trap("/t403").if_unauthenticated(status=403, body={"no": 1}))

    def boom(*a, **k):
        raise RuntimeError("emit failed")

    s._trigger_trap_event = boom
    with TestClient(app) as c:
        r = c.get("/t403")
    assert r.status_code == 403 and r.json() == {"no": 1}


def test_trap_headers_response_hook_and_fallback():
    from _trap_mirror import configure_mirror, check_mirror
    app, s, cap = make(configure_mirror)
    with TestClient(app) as client:
        def get(path, headers):
            r = client.get(path, headers=headers)
            return r.status_code, r.headers, r.content
        check_mirror(get)
