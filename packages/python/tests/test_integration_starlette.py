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
