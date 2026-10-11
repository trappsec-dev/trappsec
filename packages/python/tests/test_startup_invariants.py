"""R10 and R13 for every Python integration.

Watches are declared before traps (an order an app may well use) and both must
work. After the first request the trap and watch lists are made to raise:
lookups must go through the indexes built at startup, never scan the
configuration per request. trappsec catches its own errors, so a scan shows up
as missing events and a logged error.
"""
import logging
import pathlib
import sys
import types
import uuid

import pytest

try:
    import trappsec  # noqa: F401
except ImportError:
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from trappsec import Sentry


class Capture:
    def __init__(self):
        self.events = []

    def emit(self, event):
        self.events.append(event)


def _scan(self):
    raise AssertionError("per-request scan of the trap/watch configuration")


def make_sentry(app, watch_path):
    sentry = Sentry(app, "svc", "test")
    cap = Capture()
    sentry._handlers.append(cap)
    sentry.watch(watch_path).query("debug")
    sentry.trap("/admin/backup").methods("POST")
    return sentry, cap


def exercise(sentry, cap, send):
    assert send("GET", "/users/1") == 200  # first request: indexes are built by now
    sentry.__class__ = type("Locked", (Sentry,), {"traps": property(_scan), "watches": property(_scan)})
    assert send("POST", "/admin/backup") == 401
    assert send("GET", "/users/7?debug=1") == 200
    assert send("GET", "/users/8") == 200
    assert [e["event"] for e in cap.events] == ["trappsec.trap_hit", "trappsec.watch_hit"]


def flask_case():
    flask = pytest.importorskip("flask")
    app = flask.Flask(__name__)
    app.get("/users/<uid>")(lambda uid: "ok")
    sentry, cap = make_sentry(app, "/users/<uid>")
    c = app.test_client()
    exercise(sentry, cap, lambda m, p: c.open(p, method=m).status_code)


def _asgi_client_case(app, sentry, cap, client_cls):
    with client_cls(app) as c:
        exercise(sentry, cap, lambda m, p: c.request(m, p).status_code)


def fastapi_case():
    fastapi = pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    app = fastapi.FastAPI()
    app.get("/users/{uid}")(lambda uid: "ok")
    sentry, cap = make_sentry(app, "/users/{uid}")
    _asgi_client_case(app, sentry, cap, TestClient)


def starlette_case():
    pytest.importorskip("starlette")
    from starlette.applications import Starlette
    from starlette.responses import PlainTextResponse
    from starlette.routing import Route
    from starlette.testclient import TestClient

    async def user(request):
        return PlainTextResponse("ok")

    app = Starlette(routes=[Route("/users/{uid}", user)])
    sentry, cap = make_sentry(app, "/users/{uid}")
    _asgi_client_case(app, sentry, cap, TestClient)


def litestar_case():
    pytest.importorskip("litestar")
    from litestar import Litestar, get
    from litestar.testing import TestClient

    @get("/users/{uid:str}")
    async def user(uid: str) -> str:
        return "ok"

    app = Litestar(route_handlers=[user])
    sentry, cap = make_sentry(app, "/users/{uid:str}")
    _asgi_client_case(app, sentry, cap, TestClient)


def sanic_case():
    pytest.importorskip("sanic")
    pytest.importorskip("sanic_testing")
    from sanic import Sanic, text

    app = Sanic("trappsec_invariants_%s" % uuid.uuid4().hex[:8])

    @app.get("/users/<uid>")
    async def user(request, uid):
        return text("ok")

    sentry, cap = make_sentry(app, "/users/<uid>")

    def send(m, p):
        _, resp = app.test_client.request(p, http_method=m.lower())
        return resp.status

    exercise(sentry, cap, send)


def tornado_case():
    pytest.importorskip("tornado")
    import tornado.testing
    import tornado.web

    class User(tornado.web.RequestHandler):
        def get(self, uid):
            self.write("ok")

    holder = {}

    class Case(tornado.testing.AsyncHTTPTestCase):
        def get_app(self):
            app = tornado.web.Application([(r"/users/(\d+)", User)])
            holder["sentry"], holder["cap"] = make_sentry(app, r"/users/(\d+)")
            return app

        def runTest(self):
            exercise(holder["sentry"], holder["cap"],
                     lambda m, p: self.fetch(p, method=m, body=b"" if m == "POST" else None).code)

    case = Case()
    case.setUp()
    try:
        case.runTest()
    finally:
        case.tearDown()


def django_case():
    pytest.importorskip("django")
    pytest.importorskip("werkzeug")
    from django.conf import settings

    if not settings.configured:
        import django

        settings.configure(DEBUG=False, SECRET_KEY="test", ALLOWED_HOSTS=["*"], MIDDLEWARE=[],
                           ROOT_URLCONF="tests._unused", INSTALLED_APPS=[], USE_TZ=True)
        django.setup()
    from django.core.handlers.wsgi import WSGIHandler
    from django.http import HttpResponse
    from django.test.utils import override_settings
    from django.urls import clear_url_caches, path
    from werkzeug.test import Client

    name = "urlconf_inv_%s" % uuid.uuid4().hex
    mod = types.ModuleType(name)
    mod.urlpatterns = [path("users/<str:uid>", lambda request, uid: HttpResponse("ok"))]
    sys.modules[name] = mod
    with override_settings(ROOT_URLCONF=name):
        clear_url_caches()
        handler = WSGIHandler()
        sentry, cap = make_sentry(handler, "/users/<str:uid>")
        c = Client(handler)
        exercise(sentry, cap, lambda m, p: c.open(p, method=m).status_code)
    clear_url_caches()


CASES = {
    "flask": flask_case, "fastapi": fastapi_case, "starlette": starlette_case, "litestar": litestar_case,
    "sanic": sanic_case, "tornado": tornado_case, "django": django_case,
}


@pytest.mark.parametrize("framework", list(CASES))
def test_watches_before_traps_and_no_per_request_scans(framework, caplog):
    with caplog.at_level(logging.ERROR):
        CASES[framework]()
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR and "trappsec" in r.name.lower()]
