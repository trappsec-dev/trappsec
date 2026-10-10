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
