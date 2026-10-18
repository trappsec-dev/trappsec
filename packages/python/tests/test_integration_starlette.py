import json
import pytest

pytest.importorskip("starlette")
pytest.importorskip("httpx")
pytest.importorskip("multipart")

from starlette.applications import Starlette
from starlette.endpoints import HTTPEndpoint
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route, Router
from starlette.testclient import TestClient

from trappsec import Sentry


class Capture:
    def __init__(self):
        self.events = []

    def emit(self, event):
        self.events.append(event)


async def _dump(request):
    ctype = request.headers.get("content-type", "")
    out = {"args": {k: request.query_params.getlist(k) for k in request.query_params}}
    if "json" in ctype:
        out["json"] = await request.json()
    elif "form" in ctype or "multipart" in ctype:
        form = await request.form()
        out["form"] = {}
        for k, v in form.multi_items():
            out["form"].setdefault(k, []).append(v if isinstance(v, str) else "<file:%s>" % v.filename)
    return JSONResponse(out)


def sync_dump(request):
    # sync def endpoints are run in a threadpool by Starlette
    return JSONResponse({"args": {k: request.query_params.getlist(k) for k in request.query_params}})


class Endpoint(HTTPEndpoint):
    async def get(self, request):
        return JSONResponse({"args": {k: request.query_params.getlist(k) for k in request.query_params}})

    async def post(self, request):
        return await _dump(request)


def make(routes_first=True, identify=None, routes=None):
    all_routes = routes or [
        Route("/items", _dump, methods=["GET", "POST"]),
        Route("/sync", sync_dump, methods=["GET"]),
        Route("/cls", Endpoint),
    ]
    app = Starlette(routes=list(all_routes) if routes_first else [])
    sentry = Sentry(app, "svc", "test")
    cap = Capture()
    sentry._handlers.append(cap)
    if identify:
        sentry.identify_user(identify)
    if not routes_first:
        for r in all_routes:
            app.router.routes.append(r)
    return app, sentry, cap


def watch_events(cap):
    return [e for e in cap.events if e["event"] == "trappsec.watch_hit"]


def test_trap_no_lifespan_first_request_bootstrap():
    user = lambda r: {"user": "bob", "role": "x"} if r.headers.get("x-user") else None
    app, sentry, cap = make(identify=user)
    sentry.trap("/admin/debug").intent("recon")
    c = TestClient(app)  # no `with`: lifespan never runs
    assert c.get("/admin/debug").status_code == 401
    assert cap.events[-1]["type"] == "signal" and cap.events[-1]["intent"] == "recon"
    assert c.get("/admin/debug", headers={"x-user": "bob"}).status_code == 200
    assert cap.events[-1]["type"] == "alert" and cap.events[-1]["user"] == "bob"


def test_lifespan_bootstrap_and_explicit_bootstrap_idempotent():
    app, sentry, cap = make()
    sentry.trap("/t")
    sentry.bootstrap()
    with TestClient(app) as c:
        sentry.bootstrap()
        assert c.get("/t").status_code == 401
    assert len(cap.events) == 1


@pytest.mark.parametrize("routes_first", [True, False])
def test_query_strip_and_source(routes_first):
    app, sentry, cap = make(routes_first)
    sentry.watch("/items").query("debug")
    r = TestClient(app).get("/items?debug=1&keep=a&keep=b&blank=")
    assert r.json()["args"] == {"keep": ["a", "b"], "blank": [""]}
    ev = watch_events(cap)[0]
    assert ev["found_fields"][0]["type"] == "query"


def test_sync_endpoint_and_http_endpoint_class_work():
    app, sentry, cap = make()
    sentry.watch("/sync").query("debug")
    sentry.watch("/cls").query("debug").body("secret")
    c = TestClient(app)
    r = c.get("/sync?debug=1&a=1")
    assert r.status_code == 200 and r.json()["args"] == {"a": ["1"]}
    r = c.get("/cls?debug=1&a=1")
    assert r.status_code == 200 and r.json()["args"] == {"a": ["1"]}
    r = c.post("/cls", json={"secret": 1, "a": 2})
    assert r.status_code == 200 and r.json()["json"] == {"a": 2}
    assert len(watch_events(cap)) == 3


def test_json_body_strip_and_non_object_json():
    app, sentry, cap = make(identify=lambda r: {"user": "u", "role": "r"})
    sentry.watch("/items").body("is_admin", default=False)
    c = TestClient(app)
    r = c.post("/items", json={"is_admin": True, "n": 1})
    assert r.json()["json"] == {"n": 1}
    assert watch_events(cap)[0]["type"] == "alert"
    cap.events.clear()
    assert c.post("/items", json={"is_admin": False}).json()["json"] == {}
    assert watch_events(cap) == []
    for payload in ([1, 2], "str", 5, None, [{"is_admin": 1}, "x"]):
        r = c.post("/items", content=json.dumps(payload), headers={"content-type": "application/json"})
        assert r.status_code == 200
    # malformed JSON passes through untouched: the app (not trappsec) fails to parse it
    c2 = TestClient(app, raise_server_exceptions=False)
    r = c2.post("/items", content=b"{nope", headers={"content-type": "application/json"})
    assert r.status_code == 500


def test_form_multivalue_and_duplicate_evasion():
    app, sentry, cap = make()
    sentry.watch("/items").body("role", default="user")
    c = TestClient(app)
    r = c.post("/items", data={"role": ["user", "admin"], "tag": ["a", "b"], "n": "z"})
    assert r.json()["form"] == {"tag": ["a", "b"], "n": ["z"]}
    assert len(watch_events(cap)) == 1
    cap.events.clear()
    c.post("/items", data={"role": ["user", "user"]})
    assert watch_events(cap) == []


def test_multipart_strip_preserves_files_and_multivalues():
    app, sentry, cap = make()
    sentry.watch("/items").body("secret")
    c = TestClient(app)
    r = c.post("/items", data={"secret": "1", "tag": ["a", "b"]},
               files={"up": ("a.txt", b"hello", "text/plain")})
    assert r.status_code == 200
    assert r.json()["form"] == {"tag": ["a", "b"], "up": ["<file:a.txt>"]}
    assert len(watch_events(cap)) == 1
    assert watch_events(cap)[0]["found_fields"][0]["value"] == "1"


def test_raising_identify_user_does_not_break_request():
    def boom(r):
        raise RuntimeError("x")
    app, sentry, cap = make(identify=boom)
    sentry.trap("/trap")
    sentry.watch("/items").query("debug")
    c = TestClient(app)
    assert c.get("/trap").status_code == 401
    r = c.get("/items?debug=1&x=2")
    assert r.status_code == 200 and r.json()["args"] == {"x": ["2"]}


def test_mounted_router_routes_are_watched():
    inner = Router(routes=[Route("/items", _dump)])
    app = Starlette(routes=[Mount("/api", app=inner)])
    sentry = Sentry(app, "svc", "test")
    cap = Capture()
    sentry._handlers.append(cap)
    sentry.watch("/api/items").query("debug")
    r = TestClient(app).get("/api/items?debug=1")
    assert r.json()["args"] == {}
    assert len(watch_events(cap)) == 1


def test_trap_duplicate_fails_loud_and_catch_all_does_not_shadow():
    app, sentry, cap = make()
    sentry.trap("/items").methods("GET")
    with pytest.raises(RuntimeError, match="duplicates"):
        sentry.bootstrap()

    app = Starlette(routes=[Mount("/", app=Router(routes=[Route("/{p:path}", _dump)]))])
    sentry = Sentry(app, "svc", "test")
    sentry._handlers.append(Capture())
    sentry.trap("/admin")
    assert TestClient(app).get("/admin").status_code == 401


import codecs  # noqa: E402

_PAYLOAD = {"is_admin": True, "name": "x"}
_VARIANTS = [
    ("application/json", json.dumps(_PAYLOAD).encode("utf-16")),
    ("application/json", json.dumps(_PAYLOAD).encode("utf-32")),
    ("application/json", codecs.BOM_UTF8 + json.dumps(_PAYLOAD).encode()),
    ("application/json; charset=utf-16", json.dumps(_PAYLOAD).encode("utf-16")),
    ("text/plain", json.dumps(_PAYLOAD).encode()),
    ("application/vnd.api+json", json.dumps(_PAYLOAD).encode()),
]


async def _raw(request):
    raw = await request.body()
    return JSONResponse({"json": await request.json(), "raw": json.loads(raw),
                         "clen": request.headers.get("content-length"), "alen": len(raw)})


@pytest.mark.parametrize("ctype,raw", _VARIANTS)
def test_encoding_and_content_type_bypasses_stripped(ctype, raw):
    app, sentry, cap = make(routes=[Route("/raw", _raw, methods=["POST"])])
    sentry.watch("/raw").body("is_admin")
    r = TestClient(app).post("/raw", content=raw, headers={"content-type": ctype})
    d = r.json()
    assert d["json"] == {"name": "x"} and d["raw"] == {"name": "x"}
    assert int(d["clen"]) == d["alen"]
    assert len(watch_events(cap)) == 1


def test_non_json_unknown_body_passes_through_untouched():
    app, sentry, cap = make(routes=[Route("/raw", _raw, methods=["POST"])])
    sentry.watch("/raw").body("is_admin")
    r = TestClient(app, raise_server_exceptions=False).post(
        "/raw", content=b"\x00\x01binary", headers={"content-type": "application/octet-stream"})
    assert r.status_code == 500 and watch_events(cap) == []


def test_is_trap_lets_a_global_csrf_middleware_skip_traps():
    """R22: third-party CSRF middleware runs before routing; is_trap() is the skip hook."""
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.responses import PlainTextResponse

    async def real(request):
        return PlainTextResponse("ok")

    app = Starlette(routes=[Route("/real", real, methods=["POST"])])
    sentry = Sentry(app, "svc", "test")
    cap = Capture()
    sentry._handlers.append(cap)
    sentry.trap("/admin/backup").methods("POST")

    async def csrf(request, call_next):  # stand-in for starlette-csrf & co.
        if request.method == "POST" and not sentry.is_trap(request) and "x-csrf-token" not in request.headers:
            return PlainTextResponse("csrf", status_code=403)
        return await call_next(request)

    app.add_middleware(BaseHTTPMiddleware, dispatch=csrf)
    with TestClient(app) as c:
        assert c.post("/real").status_code == 403
        assert c.post("/admin/backup").status_code == 401
    assert len([e for e in cap.events if e["event"] == "trappsec.trap_hit"]) == 1


@pytest.mark.parametrize("skip", [False, True])
def test_is_trap_with_starlette_csrf(skip):
    """R22 with the real starlette-csrf: it has no skip callback, so traps bypass it
    in a thin ASGI wrapper; without that the trap is blocked and alerts nothing."""
    csrf = pytest.importorskip("starlette_csrf")
    from starlette.requests import Request
    from starlette.responses import PlainTextResponse

    async def real(request):
        return PlainTextResponse("ok")

    app = Starlette(routes=[Route("/real", real, methods=["POST"])])
    sentry = Sentry(app, "svc", "test")
    cap = Capture()
    sentry._handlers.append(cap)
    sentry.trap("/admin/backup").methods("POST")

    class SkipTraps:
        def __init__(self, app, **options):
            self.app = app
            self.csrf = csrf.CSRFMiddleware(app, **options)

        async def __call__(self, scope, receive, send):
            target = self.app if skip and scope["type"] == "http" and sentry.is_trap(Request(scope)) else self.csrf
            await target(scope, receive, send)

    app.add_middleware(SkipTraps, secret="test-secret")
    with TestClient(app) as c:
        assert c.post("/real").status_code == 403
        assert c.post("/admin/backup").status_code == (401 if skip else 403)
    assert len([e for e in cap.events if e["event"] == "trappsec.trap_hit"]) == (1 if skip else 0)


def test_watch_matches_converter_and_trailing_slash_routes():
    async def one(request):
        return JSONResponse({"args": dict(request.query_params)})

    app, sentry, cap = make(routes=[
        Route("/u/{id:int}", one), Route("/t/", one), Route("/f/{p:path}", one)])
    sentry.watch("/u/{id}").query("debug")
    sentry.watch("/t").query("debug")
    sentry.watch("/f/{p}").query("debug")
    c = TestClient(app)
    assert c.get("/u/5?debug=1&k=a").json()["args"] == {"k": "a"}
    assert c.get("/t/?debug=1&k=a").json()["args"] == {"k": "a"}
    assert c.get("/f/a/b?debug=1&k=a").json()["args"] == {"k": "a"}
    assert len(watch_events(cap)) == 3


def test_trap_conflicts_with_converter_route():
    app, sentry, cap = make(routes=[Route("/u/{id:int}", _dump)])
    sentry.trap("/u/{id}").methods("GET")
    with pytest.raises(RuntimeError, match="duplicates"):
        sentry.bootstrap()


def test_oversized_body_passes_through_uninspected(monkeypatch):
    from trappsec.integrations import starlette as mod
    monkeypatch.setattr(mod, "MAX_INSPECT_BYTES", 64)
    app, sentry, cap = make()
    sentry.watch("/items").body("is_admin")
    payload = json.dumps({"is_admin": True, "pad": "x" * 200})
    r = TestClient(app).post("/items", content=payload, headers={"content-type": "application/json"})
    assert r.json()["json"]["is_admin"] is True and len(r.json()["json"]["pad"]) == 200
    assert watch_events(cap) == []

    # streamed in several messages, no Content-Length: replay what was read, stream the rest
    import asyncio
    raw = payload.encode()
    parts = [raw[i:i + 70] for i in range(0, len(raw), 70)]
    queue = [{"type": "http.request", "body": c, "more_body": i < len(parts) - 1}
             for i, c in enumerate(parts)]
    sent = []

    async def receive():
        return queue.pop(0)

    async def send(message):
        sent.append(message)

    scope = {"type": "http", "method": "POST", "path": "/items", "raw_path": b"/items",
             "query_string": b"", "headers": [(b"content-type", b"application/json")],
             "scheme": "http", "server": ("t", 80), "client": ("c", 1), "root_path": "",
             "http_version": "1.1", "state": {}}
    asyncio.run(app(scope, receive, send))
    body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    assert json.loads(body)["json"]["is_admin"] is True
    assert watch_events(cap) == []


def test_single_occurrence_fields_are_scalars():
    app, sentry, cap = make()
    sentry.watch("/items").query("role", default=["1"]).query("mode", default="1")
    TestClient(app).get("/items?role=1&mode=1")
    # a list default does not match a field that occurred once (as in Go/Node/Litestar)
    fields = [f["field"] for f in watch_events(cap)[0]["found_fields"]]
    assert fields == ["role"]


def test_trap_headers_response_hook_and_fallback():
    from _trap_mirror import configure_mirror, check_mirror
    app, sentry, cap = make()
    configure_mirror(sentry)
    c = TestClient(app)

    def get(path, headers):
        r = c.get(path, headers=headers)
        return r.status_code, r.headers, r.content
    check_mirror(get)
