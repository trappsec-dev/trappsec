import json
import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("multipart")

from typing import Any, List, Optional

from fastapi import APIRouter, FastAPI, Query, Request
from fastapi.testclient import TestClient

from trappsec import Sentry


class Capture:
    def __init__(self):
        self.events = []

    def emit(self, event):
        self.events.append(event)


def add_routes(target):
    @target.api_route("/items", methods=["GET", "POST"])
    async def items(request: Request):
        ctype = request.headers.get("content-type", "")
        out = {"args": {k: request.query_params.getlist(k) for k in request.query_params}}
        if "json" in ctype:
            out["json"] = await request.json()
        elif "form" in ctype:
            form = await request.form()
            out["form"] = {}
            for k, v in form.multi_items():
                out["form"].setdefault(k, []).append(v if isinstance(v, str) else "<file:%s>" % v.filename)
        return out

    @target.get("/typed")
    def typed(q: Optional[str] = None, tags: List[str] = Query(default=[])):
        # sync def + validated query params
        return {"q": q, "tags": list(tags)}


def make(order="before", identify=None):
    app = FastAPI()
    if order == "before":
        add_routes(app)
    sentry = Sentry(app, "svc", "test")
    cap = Capture()
    sentry._handlers.append(cap)
    if identify:
        sentry.identify_user(identify)
    if order == "after":
        add_routes(app)
    return app, sentry, cap


def watch_events(cap):
    return [e for e in cap.events if e["event"] == "trappsec.watch_hit"]


@pytest.mark.parametrize("order", ["before", "after"])
def test_routes_before_and_after_sentry_are_watched(order):
    app, sentry, cap = make(order)
    sentry.watch("/items").query("debug")
    sentry.watch("/typed").query("debug")
    c = TestClient(app)  # no lifespan
    r = c.get("/items?debug=1&k=a&k=b")
    assert r.json()["args"] == {"k": ["a", "b"]}
    r = c.get("/typed?debug=1&q=z&tags=a&tags=b")
    assert r.json() == {"q": "z", "tags": ["a", "b"]}
    evs = watch_events(cap)
    assert len(evs) == 2
    assert all(e["found_fields"][0]["type"] == "query" for e in evs)


def test_include_router_routes_watched_with_prefix():
    app = FastAPI()
    router = APIRouter(prefix="/v1")
    add_routes(router)
    app.include_router(router)
    sentry = Sentry(app, "svc", "test")
    cap = Capture()
    sentry._handlers.append(cap)
    sentry.watch("/v1/items").body("secret")
    r = TestClient(app).post("/v1/items", json={"secret": 1, "a": 1})
    assert r.json()["json"] == {"a": 1}
    assert len(watch_events(cap)) == 1


def test_include_router_after_sentry_still_watched():
    app = FastAPI()
    sentry = Sentry(app, "svc", "test")
    cap = Capture()
    sentry._handlers.append(cap)
    router = APIRouter()
    add_routes(router)
    app.include_router(router)
    sentry.watch("/items").query("debug")
    TestClient(app).get("/items?debug=1")
    assert len(watch_events(cap)) == 1


def test_trap_works_without_lifespan_and_with_lifespan():
    user = lambda r: {"user": "bob", "role": "x"} if r.headers.get("x-user") else None
    app, sentry, cap = make(identify=user)
    sentry.trap("/admin").intent("recon")
    c = TestClient(app)
    assert c.get("/admin").status_code == 401
    assert c.get("/admin", headers={"x-user": "bob"}).status_code == 200
    assert [e["type"] for e in cap.events] == ["signal", "alert"]
    with TestClient(app) as c2:
        assert c2.get("/admin").status_code == 401
    assert len(cap.events) == 3


def test_trap_query_param_named_trap_is_not_injected():
    app, sentry, cap = make()
    sentry.trap("/admin").intent("recon").if_unauthenticated(status=403, body={"error": "forbidden"})
    r = TestClient(app).get("/admin?trap=1")
    assert r.status_code == 403
    assert r.json() == {"error": "forbidden"}
    assert [e["event"] for e in cap.events] == ["trappsec.trap_hit"]


def test_trap_json_is_compact_like_fastapi():
    app, sentry, cap = make()
    sentry.trap("/admin").if_unauthenticated(status=401, body={"error": "unauthorized", "code": 1})

    @app.get("/real")
    def real():
        return {"error": "unauthorized", "code": 1}

    c = TestClient(app)
    assert c.get("/admin").content == c.get("/real").content == b'{"error":"unauthorized","code":1}'


def test_bootstrap_idempotent():
    app, sentry, cap = make()
    sentry.trap("/t")
    sentry.watch("/items").query("debug")
    sentry.bootstrap()
    sentry.bootstrap()
    c = TestClient(app)
    c.get("/items?debug=1")
    assert c.get("/t").status_code == 401
    assert len(cap.events) == 2


def test_json_body_and_non_object():
    app, sentry, cap = make()
    sentry.watch("/items").body("is_admin", default=False)
    c = TestClient(app)
    assert c.post("/items", json={"is_admin": True, "n": 1}).json()["json"] == {"n": 1}
    assert len(watch_events(cap)) == 1
    for payload in ([1, 2], "s", 3, None):
        r = c.post("/items", content=json.dumps(payload), headers={"content-type": "application/json"})
        assert r.status_code == 200 and r.json()["json"] == payload
    r = c.post("/items", json=[{"is_admin": True}, {"k": 1}])
    assert r.json()["json"] == [{}, {"k": 1}]


def test_form_multivalue_duplicate_evasion_and_multipart():
    app, sentry, cap = make()
    sentry.watch("/items").body("role", default="user")
    c = TestClient(app)
    r = c.post("/items", data={"role": ["user", "admin"], "tag": ["a", "b"]})
    assert r.json()["form"] == {"tag": ["a", "b"]}
    assert len(watch_events(cap)) == 1
    cap.events.clear()
    r = c.post("/items", data={"role": "admin", "tag": ["a", "b"]},
               files={"up": ("a.txt", b"hello", "text/plain")})
    assert r.json()["form"] == {"tag": ["a", "b"], "up": ["<file:a.txt>"]}
    assert len(watch_events(cap)) == 1


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


def test_trap_duplicate_fails_loud():
    app, sentry, cap = make()
    sentry.trap("/items").methods("GET")
    with pytest.raises(RuntimeError, match="duplicates"):
        sentry.bootstrap()


def test_nested_include_router_and_trap_conflict_in_included_router():
    app = FastAPI()
    outer = APIRouter(prefix="/outer")
    inner = APIRouter(prefix="/inner")
    add_routes(inner)
    outer.include_router(inner)
    app.include_router(outer)
    sentry = Sentry(app, "svc", "test")
    cap = Capture()
    sentry._handlers.append(cap)
    sentry.watch("/outer/inner/items").query("debug")
    r = TestClient(app).get("/outer/inner/items?debug=1&a=1")
    assert r.json()["args"] == {"a": ["1"]}
    assert len(watch_events(cap)) == 1

    app2 = FastAPI()
    r2 = APIRouter(prefix="/v1")
    add_routes(r2)
    app2.include_router(r2)
    s2 = Sentry(app2, "svc", "test")
    s2.trap("/v1/items").methods("GET")
    with pytest.raises(RuntimeError, match="duplicates"):
        s2.bootstrap()


import codecs  # noqa: E402

_PAYLOAD = {"is_admin": True, "name": "x"}


@pytest.mark.parametrize("ctype,raw", [
    ("application/json", json.dumps(_PAYLOAD).encode("utf-16")),
    ("application/json", json.dumps(_PAYLOAD).encode("utf-32")),
    ("application/json", codecs.BOM_UTF8 + json.dumps(_PAYLOAD).encode()),
    ("text/plain", json.dumps(_PAYLOAD).encode()),
    ("application/vnd.api+json", json.dumps(_PAYLOAD).encode()),
])
def test_encoding_and_content_type_bypasses_stripped(ctype, raw):
    app, sentry, cap = make("before")

    @app.post("/raw")
    async def raw_route(request: Request):
        return {"json": await request.json(), "raw": json.loads(await request.body())}

    sentry.watch("/raw").body("is_admin")
    d = TestClient(app).post("/raw", content=raw, headers={"content-type": ctype}).json()
    assert d == {"json": {"name": "x"}, "raw": {"name": "x"}}
    assert len(watch_events(cap)) == 1


@pytest.mark.parametrize("routes_first", [True, False])
def test_catch_all_route_does_not_shadow_trap(routes_first):
    """R2: FastAPI matches routes in order, so traps must be prepended."""
    app = FastAPI()

    def routes():
        @app.get("/{rest:path}")
        def catch_all(rest: str):
            return {"catchall": rest}

    if routes_first:
        routes()
    sentry = Sentry(app, "svc", "test")
    cap = Capture()
    sentry._handlers.append(cap)
    sentry.trap("/admin/backup")
    if not routes_first:
        routes()
    with TestClient(app) as c:
        assert c.get("/admin/backup").status_code == 401
        assert c.get("/other").json() == {"catchall": "other"}
    assert len([e for e in cap.events if e["event"] == "trappsec.trap_hit"]) == 1


def test_watch_and_trap_match_path_params_converters_and_trailing_slash():
    app = FastAPI()

    @app.get("/u/{uid:int}")
    def user(uid: int, k: Optional[str] = None):
        return {"k": k}

    @app.get("/f/{p:path}")
    def files(p: str, k: Optional[str] = None):
        return {"k": k}

    router = APIRouter(prefix="/v1")

    @router.get("/t/")
    def slash(k: Optional[str] = None):
        return {"k": k}

    app.include_router(router)
    sentry = Sentry(app, "svc", "test")
    cap = Capture()
    sentry._handlers.append(cap)
    sentry.watch("/u/{uid}").query("debug")
    sentry.watch("/f/{p}").query("debug")
    sentry.watch("/v1/t").query("debug")
    c = TestClient(app)
    assert c.get("/u/5?debug=1&k=a").json() == {"k": "a"}
    assert c.get("/f/a/b?debug=1&k=a").json() == {"k": "a"}
    assert c.get("/v1/t/?debug=1&k=a").json() == {"k": "a"}
    assert len(watch_events(cap)) == 3


def test_trap_conflicts_with_path_param_route():
    app = FastAPI()

    @app.get("/u/{uid:int}")
    def user(uid: int):
        return {}

    sentry = Sentry(app, "svc", "test")
    sentry.trap("/u/{uid}").methods("GET")
    with pytest.raises(RuntimeError, match="duplicates"):
        sentry.bootstrap()


def test_failing_trap_event_answers_with_the_traps_own_unauthenticated_response(monkeypatch):
    from starlette.applications import Starlette
    for app in (FastAPI(), Starlette()):
        ts = Sentry(app, "svc", "test")
        ts.trap("/decoy").methods("GET").if_unauthenticated(status=403, body={"no": 1})

        def boom(*_a, **_k):
            raise RuntimeError("emit failed")

        monkeypatch.setattr(ts, "_trigger_trap_event", boom)
        with TestClient(app) as client:
            r = client.get("/decoy")
        assert (r.status_code, r.json()) == (403, {"no": 1}), type(app).__name__
