"""R1 and R11 for every Python integration.

One request goes to a watched *parameterised* route with a honey query field.
The watch must match by route pattern (R1), strip the field, and the event must
carry the request context exactly as the framework sees it (R11): the path,
the method, the User-Agent and the client address the handler itself reports.
"""
import json
import pathlib
import sys

import pytest

try:
    import trappsec  # noqa: F401
except ImportError:
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from trappsec import Sentry

UA = "trappsec-context-probe/1.0"


class Capture:
    def __init__(self):
        self.events = []

    def emit(self, event):
        self.events.append(event)


def attach(app, watch_path):
    sentry = Sentry(app, "svc", "test")
    cap = Capture()
    sentry._handlers.append(cap)
    sentry.watch(watch_path).query("debug", intent="recon")
    return cap


def flask_case():
    flask = pytest.importorskip("flask")
    app = flask.Flask(__name__)

    @app.get("/users/<uid>")
    def user(uid):
        r = flask.request
        return {"ip": r.remote_addr, "args": r.args.to_dict()}

    cap = attach(app, "/users/<uid>")
    resp = app.test_client().get("/users/7?debug=1&x=1", headers={"User-Agent": UA})
    return cap, resp.get_json()


def fastapi_case():
    fastapi = pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    app = fastapi.FastAPI()

    @app.get("/users/{uid}")
    def user(uid: str, request: fastapi.Request):
        return {"ip": request.client.host, "args": dict(request.query_params)}

    cap = attach(app, "/users/{uid}")
    with TestClient(app) as c:
        resp = c.get("/users/7?debug=1&x=1", headers={"User-Agent": UA})
    return cap, resp.json()


def starlette_case():
    pytest.importorskip("starlette")
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse
    from starlette.routing import Route
    from starlette.testclient import TestClient

    async def user(request):
        return JSONResponse({"ip": request.client.host, "args": dict(request.query_params)})

    app = Starlette(routes=[Route("/users/{uid}", user)])
    cap = attach(app, "/users/{uid}")
    with TestClient(app) as c:
        resp = c.get("/users/7?debug=1&x=1", headers={"User-Agent": UA})
    return cap, resp.json()


def litestar_case():
    pytest.importorskip("litestar")
    from litestar import Litestar, Request, get
    from litestar.testing import TestClient

    @get("/users/{uid:str}")
    async def user(uid: str, request: Request) -> dict:
        return {"ip": request.client.host, "args": dict(request.query_params)}

    app = Litestar(route_handlers=[user])
    cap = attach(app, "/users/{uid:str}")
    with TestClient(app) as c:
        resp = c.get("/users/7?debug=1&x=1", headers={"User-Agent": UA})
    return cap, resp.json()


def sanic_case():
    pytest.importorskip("sanic")
    pytest.importorskip("sanic_testing")
    from sanic import Sanic, json as sjson

    app = Sanic("trappsec_context_probe")

    @app.get("/users/<uid>")
    async def user(request, uid):
        return sjson({"ip": request.remote_addr or request.ip, "args": {k: v[0] for k, v in request.args.items()}})

    cap = attach(app, "/users/<uid>")
    _, resp = app.test_client.get("/users/7?debug=1&x=1", headers={"User-Agent": UA})
    return cap, resp.json


def tornado_case():
    pytest.importorskip("tornado")
    import tornado.testing
    import tornado.web

    class User(tornado.web.RequestHandler):
        def get(self, uid):
            self.write({"ip": self.request.remote_ip,
                        "args": {k: v[0].decode() for k, v in self.request.arguments.items()}})

    result = {}

    class Case(tornado.testing.AsyncHTTPTestCase):
        def get_app(self):
            app = tornado.web.Application([(r"/users/(\d+)", User)])
            result["cap"] = attach(app, r"/users/(\d+)")
            return app

        def runTest(self):
            r = self.fetch("/users/7?debug=1&x=1", headers={"User-Agent": UA})
            result["body"] = json.loads(r.body)

    case = Case()
    case.setUp()
    try:
        case.runTest()
    finally:
        case.tearDown()
    return result["cap"], result["body"]


def django_case():
    pytest.importorskip("django")
    pytest.importorskip("werkzeug")
    from django.conf import settings

    if not settings.configured:
        import django

        settings.configure(DEBUG=False, SECRET_KEY="test", ALLOWED_HOSTS=["*"], MIDDLEWARE=[],
                           ROOT_URLCONF="tests._unused", INSTALLED_APPS=[], USE_TZ=True)
        django.setup()
    import types
    import uuid

    from django.core.handlers.wsgi import WSGIHandler
    from django.http import JsonResponse
    from django.test.utils import override_settings
    from django.urls import clear_url_caches, path
    from werkzeug.test import Client  # WSGI client: drives the handler trappsec is attached to

    def user(request, uid):
        return JsonResponse({"ip": request.META.get("REMOTE_ADDR"), "args": {k: request.GET[k] for k in request.GET}})

    name = "urlconf_ctx_%s" % uuid.uuid4().hex
    mod = types.ModuleType(name)
    mod.urlpatterns = [path("users/<str:uid>", user)]
    sys.modules[name] = mod
    with override_settings(ROOT_URLCONF=name):
        clear_url_caches()
        handler = WSGIHandler()
        cap = attach(handler, "/users/<str:uid>")
        resp = Client(handler).get("/users/7?debug=1&x=1", headers={"User-Agent": UA},
                                   environ_overrides={"REMOTE_ADDR": "203.0.113.5"})
        body = json.loads(resp.data)
    clear_url_caches()
    return cap, body


CASES = {
    "flask": flask_case, "fastapi": fastapi_case, "starlette": starlette_case, "litestar": litestar_case,
    "sanic": sanic_case, "tornado": tornado_case, "django": django_case,
}


@pytest.mark.parametrize("framework", list(CASES))
def test_parameterised_watch_and_event_context(framework):
    cap, seen = CASES[framework]()
    assert seen["args"] == {"x": "1"}, "honey query field must be stripped before the handler"
    events = [e for e in cap.events if e["event"] == "trappsec.watch_hit"]
    assert len(events) == 1, "the watch must match the parameterised route pattern (R1)"
    event = events[0]
    assert event["path"] == "/users/7"
    assert event["method"] == "GET"
    assert event["user_agent"] == UA
    assert event["ip"] and event["ip"] == seen["ip"], "event ip must be the client address the framework reports"
    assert event["found_fields"] == [{"type": "query", "field": "debug", "value": "1", "intent": "recon"}]
