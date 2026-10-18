import io
import json
import sys
import types
import uuid

import pytest

django = pytest.importorskip("django")
pytest.importorskip("werkzeug")  # used only as a WSGI test client

from django.conf import settings

if not settings.configured:
    settings.configure(
        DEBUG=False,
        SECRET_KEY="test",
        ALLOWED_HOSTS=["*"],
        ROOT_URLCONF="tests._unused",
        MIDDLEWARE=[
            "django.middleware.common.CommonMiddleware",
            "django.middleware.csrf.CsrfViewMiddleware",
        ],
        INSTALLED_APPS=[],
        USE_TZ=True,
    )
    django.setup()

from django.core.handlers.wsgi import WSGIHandler
from django.http import JsonResponse
from django.test.utils import override_settings
from django.urls import clear_url_caches, path
from django.views.decorators.csrf import csrf_exempt
from werkzeug.test import Client

from trappsec import Sentry


class Capture:
    def __init__(self):
        self.events = []

    def emit(self, event):
        self.events.append(event)


@csrf_exempt
def items(request, **kwargs):
    out = {
        "get": {k: request.GET.getlist(k) for k in request.GET},
        "ctype": request.META.get("CONTENT_TYPE", ""),
    }
    if request.method == "POST":
        if request.GET.get("files_first"):
            out["files"] = sorted(request.FILES)
        out["post"] = {k: request.POST.getlist(k) for k in request.POST}
        out["files"] = sorted(request.FILES)
        if "json" in out["ctype"]:
            try:
                out["json"] = json.loads(request.body)
            except Exception:
                out["json"] = "unparsable"
    return JsonResponse(out)


def make(identify=None, urlpatterns=None):
    name = "urlconf_%s" % uuid.uuid4().hex
    mod = types.ModuleType(name)
    mod.urlpatterns = urlpatterns if urlpatterns is not None else [
        path("items", items),
        path("items/<int:pk>", items),
    ]
    sys.modules[name] = mod
    ctx = override_settings(ROOT_URLCONF=name)
    ctx.enable()
    clear_url_caches()
    handler = WSGIHandler()
    sentry = Sentry(handler, "svc", "test")
    cap = Capture()
    sentry._handlers.append(cap)
    if identify:
        sentry.identify_user(identify)
    return handler, sentry, cap, ctx


@pytest.fixture
def env():
    made = []

    def _make(**kw):
        h, s, c, ctx = make(**kw)
        made.append(ctx)
        return h, s, c

    yield _make
    for ctx in made:
        ctx.disable()
    clear_url_caches()


def client(handler):
    return Client(handler)


def watch_events(cap):
    return [e for e in cap.events if e["event"] == "trappsec.watch_hit"]


def test_trap_hit_under_default_csrf_middleware(env):
    h, s, cap = env(identify=lambda r: {"user": "bob", "role": "r"} if r.headers.get("x-user") else None)
    s.trap("/admin/debug").intent("recon")
    c = client(h)
    r = c.post("/admin/debug", data={"a": "b"})
    assert r.status_code == 401  # not a CSRF 403
    ev = cap.events[-1]
    assert ev["event"] == "trappsec.trap_hit" and ev["type"] == "signal" and ev["intent"] == "recon"
    r = c.post("/admin/debug", headers={"x-user": "bob"})
    assert r.status_code == 200 and cap.events[-1]["type"] == "alert"


def test_two_sentries_in_one_process_and_bootstrap_idempotent(env):
    h1, s1, cap1 = env()
    h2, s2, cap2 = env()  # used to raise "already bootstrapped"
    s1.trap("/t")
    s1.bootstrap()
    s1.bootstrap()
    assert client(h1).get("/t").status_code == 401
    assert len(cap1.events) == 1


def test_query_detect_strip_multivalue(env):
    h, s, cap = env()
    s.watch("/items").query("debug")
    r = client(h).get("/items?debug=1&k=a&k=b&blank=")
    assert r.get_json()["get"] == {"k": ["a", "b"], "blank": [""]}
    ev = watch_events(cap)[0]
    assert ev["found_fields"][0]["type"] == "query"


def test_parametrised_route_and_script_name(env):
    h, s, cap = env()
    s.watch("/items/<int:pk>").query("debug")
    c = client(h)
    # SCRIPT_NAME=/app: routing must use path_info
    r = c.get("/items/5?debug=1&x=1", base_url="http://localhost/app")
    assert r.status_code == 200
    assert r.get_json()["get"] == {"x": ["1"]}
    assert len(watch_events(cap)) == 1


def test_trap_with_script_name(env):
    h, s, cap = env()
    s.trap("/t")
    assert client(h).get("/t", base_url="http://localhost/app").status_code == 401


def test_json_body_strip_and_non_object(env):
    h, s, cap = env(identify=lambda r: {"user": "u", "role": "r"})
    s.watch("/items").body("is_admin", default=False)
    c = client(h)
    r = c.post("/items", json={"is_admin": True, "n": 1})
    assert r.get_json()["json"] == {"n": 1}
    assert watch_events(cap)[0]["type"] == "alert"
    cap.events.clear()
    assert c.post("/items", json={"is_admin": False}).get_json()["json"] == {}
    assert watch_events(cap) == []
    for payload in ([1, 2], "s", 3, None, [{"is_admin": 1}]):
        r = c.post("/items", data=json.dumps(payload), content_type="application/json")
        assert r.status_code == 200


def test_form_multivalue_and_duplicate_evasion(env):
    h, s, cap = env()
    s.watch("/items").body("role", default="user")
    r = client(h).post("/items", data={"role": ["user", "admin"], "tag": ["a", "b"], "blank": ""})
    assert r.get_json()["post"] == {"tag": ["a", "b"], "blank": [""]}
    assert len(watch_events(cap)) == 1


def test_multipart_strip_sticks_even_if_files_read_first(env):
    h, s, cap = env()
    s.watch("/items").body("secret")
    r = client(h).post(
        "/items?files_first=1",
        data={"secret": "1", "tag": ["a", "b"], "f": (io.BytesIO(b"hi"), "a.txt")},
    )
    body = r.get_json()
    assert body["post"] == {"tag": ["a", "b"]}
    assert body["files"] == ["f"]
    assert len(watch_events(cap)) == 1


def test_multipart_file_named_like_watched_field_is_stripped(env):
    h, s, cap = env()
    s.watch("/items").body("secret")
    r = client(h).post("/items", data={"secret": (io.BytesIO(b"hi"), "a.txt"), "x": "1"})
    body = r.get_json()
    assert body["files"] == [] and body["post"] == {"x": ["1"]}
    assert len(watch_events(cap)) == 1


def test_raising_identify_user_does_not_break_request(env):
    def boom(r):
        raise RuntimeError("x")
    h, s, cap = env(identify=boom)
    s.trap("/trap")
    s.watch("/items").query("debug")
    c = client(h)
    assert c.get("/trap").status_code == 401
    r = c.get("/items?debug=1&x=2")
    assert r.status_code == 200 and r.get_json()["get"] == {"x": ["2"]}


def test_trap_duplicate_route_fails_loud(env):
    h, s, cap = env()
    s.trap("/items")
    with pytest.raises(RuntimeError, match="duplicates"):
        s.bootstrap()


import codecs  # noqa: E402

_PAYLOAD = {"is_admin": True, "name": "x"}


@csrf_exempt
def raw_view(request):
    raw = request.body
    return JsonResponse({"json": json.loads(raw), "clen": request.META.get("CONTENT_LENGTH"),
                         "alen": len(raw)})


@pytest.mark.parametrize("ctype,raw", [
    ("application/json", json.dumps(_PAYLOAD).encode("utf-16")),
    ("application/json", json.dumps(_PAYLOAD).encode("utf-32")),
    ("application/json", codecs.BOM_UTF8 + json.dumps(_PAYLOAD).encode()),
    ("application/json; charset=utf-16", json.dumps(_PAYLOAD).encode("utf-16")),
    ("text/plain", json.dumps(_PAYLOAD).encode()),
    ("application/vnd.api+json", json.dumps(_PAYLOAD).encode()),
])
def test_encoding_and_content_type_bypasses_stripped(env, ctype, raw):
    h, s, cap = env(urlpatterns=[path("raw", raw_view)])
    s.watch("/raw").body("is_admin")
    r = client(h).post("/raw", data=raw, headers={"content-type": ctype})
    d = r.get_json()
    assert d["json"] == {"name": "x"}
    assert int(d["clen"]) == d["alen"]
    assert len(watch_events(cap)) == 1


def test_watch_on_included_urlconf(env):
    """R7: routes mounted with include() are watched by their full pattern."""
    from django.urls import include

    h, s, cap = env(urlpatterns=[path("api/", include([path("users/<int:pk>", items)]))])
    s.watch("/api/users/<int:pk>").query("debug", intent="q").body("is_admin", intent="b")
    r = client(h).post("/api/users/7?debug=1&x=1", data=json.dumps({"is_admin": True, "n": 1}),
                       content_type="application/json")
    assert r.status_code == 200
    assert r.get_json()["get"] == {"x": ["1"]}
    assert r.get_json()["json"] == {"n": 1}
    [event] = watch_events(cap)
    assert {f["field"] for f in event["found_fields"]} == {"debug", "is_admin"}


def test_catch_all_route_does_not_shadow_trap(env):
    """R2: Django matches urlpatterns in order, so traps must come first."""
    from django.urls import re_path

    h, s, cap = env(urlpatterns=[re_path(r"^.*$", items)])
    s.trap("/admin/backup")
    c = client(h)
    assert c.get("/admin/backup").status_code == 401
    assert c.get("/other").status_code == 200
    assert len([e for e in cap.events if e["event"] == "trappsec.trap_hit"]) == 1


def test_concurrent_first_requests_bootstrap_once(env):
    """R8: threaded WSGI servers can deliver many first requests at once."""
    import threading
    import urllib.error
    import urllib.request
    from socketserver import ThreadingMixIn
    from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server

    class Quiet(WSGIRequestHandler):
        def log_message(self, *a):
            pass

    class Threaded(ThreadingMixIn, WSGIServer):
        daemon_threads = True

    h, s, cap = env()
    s.trap("/admin/backup")
    srv = make_server("127.0.0.1", 0, h, server_class=Threaded, handler_class=Quiet)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    codes, start = [], threading.Barrier(24)

    def hit():
        start.wait()
        try:
            urllib.request.urlopen("http://127.0.0.1:%d/admin/backup" % srv.server_port, timeout=10)
        except urllib.error.HTTPError as e:
            codes.append(e.code)

    threads = [threading.Thread(target=hit) for _ in range(24)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    srv.shutdown()
    srv.server_close()
    assert codes == [401] * 24
    assert len([e for e in cap.events if e["event"] == "trappsec.trap_hit"]) == 24


def test_trap_with_path_params(env):
    h, s, cap = env()
    s.trap("/users/<id>/secret").methods("GET")
    s.trap("/dump/<path:p>").methods("GET")
    c = client(h)
    assert c.get("/users/7/secret").status_code == 401
    assert c.get("/dump/a/b").status_code == 401
    assert len([e for e in cap.events if e["event"] == "trappsec.trap_hit"]) == 2


@pytest.mark.parametrize("conflicting", [
    lambda: __import__("django.urls", fromlist=["re_path"]).re_path(r"^legacy$", items),
    lambda: path("legacy", items),
    lambda: path("legacy/<int:pk>", items),
])
def test_trap_duplicate_detected_via_url_resolution(env, conflicting):
    h, s, cap = env(urlpatterns=[conflicting()])
    s.trap("/legacy" if "pk" not in str(conflicting()) else "/legacy/5")
    with pytest.raises(RuntimeError, match="duplicates"):
        s.bootstrap()


def test_trap_duplicate_detected_through_include(env):
    from django.urls import include

    h, s, cap = env(urlpatterns=[path("api/", include([path("v1/<int:pk>", items)]))])
    s.trap("/api/v1/3")
    with pytest.raises(RuntimeError, match="duplicates"):
        s.bootstrap()


def test_wildcard_route_is_not_a_duplicate(env):
    h, s, cap = env(urlpatterns=[path("<slug:slug>", items)])
    s.trap("/admin")
    assert client(h).get("/admin").status_code == 401


def test_multipart_body_readable_after_post_is_parsed(env):
    @csrf_exempt
    def hashing(request):
        return JsonResponse({"post": sorted(request.POST), "len": len(request.body)})

    h, s, cap = env(urlpatterns=[path("up", hashing)])
    s.watch("/up").body("secret")
    r = client(h).post("/up", data={"secret": "1", "x": "2", "f": (io.BytesIO(b"hi"), "a.txt")})
    assert r.status_code == 200
    assert r.get_json()["post"] == ["x"] and r.get_json()["len"] > 0
    assert len(watch_events(cap)) == 1


def test_single_occurrence_scalar_for_list_default(env):
    h, s, cap = env()
    s.watch("/items").query("role", default=["1"]).query("mode", default="1")
    client(h).get("/items?role=1&mode=1")
    assert [f["field"] for f in watch_events(cap)[0]["found_fields"]] == ["role"]


def test_asgi_handler_with_watches_and_traps(env):
    import asyncio
    from django.core.handlers.asgi import ASGIHandler

    name = "urlconf_%s" % uuid.uuid4().hex
    mod = types.ModuleType(name)
    mod.urlpatterns = [path("items", items)]
    sys.modules[name] = mod
    ctx = override_settings(ROOT_URLCONF=name)
    ctx.enable()
    clear_url_caches()
    try:
        handler = ASGIHandler()
        s = Sentry(handler, "svc", "test")
        cap = Capture()
        s._handlers.append(cap)
        s.trap("/admin/debug")
        s.watch("/items").query("debug")

        def call(method, target, query=b""):
            sent, msgs = [], [{"type": "http.request", "body": b"", "more_body": False}]

            async def receive():
                if msgs:
                    return msgs.pop(0)
                await asyncio.sleep(0.2)  # let the response finish, then disconnect
                return {"type": "http.disconnect"}

            async def send(message):
                sent.append(message)

            scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
                     "method": method, "scheme": "http", "path": target, "raw_path": target.encode(),
                     "query_string": query, "root_path": "", "headers": [(b"host", b"testserver")],
                     "client": ("1.2.3.4", 1), "server": ("testserver", 80)}
            asyncio.run(handler(scope, receive, send))
            status = next(m["status"] for m in sent if m["type"] == "http.response.start")
            body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
            return status, body

        assert call("GET", "/admin/debug")[0] == 401
        status, body = call("GET", "/items", b"debug=1&x=2")
        assert status == 200 and json.loads(body)["get"] == {"x": ["2"]}
        assert len(watch_events(cap)) == 1
    finally:
        ctx.disable()
        clear_url_caches()


def test_trap_headers_response_hook_and_fallback(env):
    from _trap_mirror import configure_mirror, check_mirror
    h, s, cap = env()
    configure_mirror(s)
    c = client(h)

    def get(path, headers):
        r = c.get(path, headers=headers)
        return r.status_code, r.headers, r.get_data()
    check_mirror(get)
