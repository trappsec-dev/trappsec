import json
import pytest

flask = pytest.importorskip("flask")
pytest.importorskip("werkzeug")

from flask import Flask, jsonify, request

from trappsec import Sentry


class Capture:
    def __init__(self):
        self.events = []

    def emit(self, event):
        self.events.append(event)


def make(setup_routes_first=True, identify=None):
    app = Flask(__name__)

    def routes():
        @app.route("/items", methods=["GET", "POST"])
        def items():
            return jsonify(
                args={k: request.args.getlist(k) for k in request.args},
                form={k: request.form.getlist(k) for k in request.form},
                json=request.get_json(silent=True),
            )

    if setup_routes_first:
        routes()
    sentry = Sentry(app, "svc", "test")
    cap = Capture()
    sentry._handlers.append(cap)
    if identify:
        sentry.identify_user(identify)
    if not setup_routes_first:
        routes()
    return app, sentry, cap


def watch_events(cap):
    return [e for e in cap.events if e["event"] == "trappsec.watch_hit"]


def test_trap_hit_unauthenticated_and_authenticated():
    app, sentry, cap = make(identify=lambda r: {"user": r.headers.get("x-user"), "role": "admin"} if r.headers.get("x-user") else None)
    sentry.trap("/admin/debug").intent("recon")
    c = app.test_client()

    r = c.get("/admin/debug")
    assert r.status_code == 401
    ev = [e for e in cap.events if e["event"] == "trappsec.trap_hit"][-1]
    assert ev["type"] == "signal" and ev["intent"] == "recon"

    r = c.post("/admin/debug", headers={"x-user": "bob"})
    assert r.status_code == 200
    ev = [e for e in cap.events if e["event"] == "trappsec.trap_hit"][-1]
    assert ev["type"] == "alert" and ev["user"] == "bob"


def test_bootstrap_idempotent_and_explicit():
    app, sentry, cap = make()
    sentry.trap("/t1")
    sentry.bootstrap()
    sentry.bootstrap()
    assert app.test_client().get("/t1").status_code == 401
    assert len(cap.events) == 1


@pytest.mark.parametrize("routes_first", [True, False])
def test_query_watch_detect_and_strip(routes_first):
    app, sentry, cap = make(routes_first)
    sentry.watch("/items").query("debug", intent="probe")
    r = app.test_client().get("/items?debug=1&keep=a&keep=b")
    assert r.get_json()["args"] == {"keep": ["a", "b"]}
    evs = watch_events(cap)
    assert len(evs) == 1
    assert evs[0]["found_fields"][0]["type"] == "query"
    assert evs[0]["found_fields"][0]["field"] == "debug"


def test_json_body_strip_and_authenticated_alert():
    app, sentry, cap = make(identify=lambda r: {"user": "u1", "role": "r"})
    sentry.watch("/items").body("is_admin", default=False)
    c = app.test_client()
    r = c.post("/items", json={"is_admin": True, "name": "x"})
    assert r.get_json()["json"] == {"name": "x"}
    ev = watch_events(cap)[0]
    assert ev["type"] == "alert" and ev["user"] == "u1"
    assert ev["found_fields"][0]["type"] == "body"
    # matching default: stripped but no event
    cap.events.clear()
    r = c.post("/items", json={"is_admin": False, "name": "y"})
    assert r.get_json()["json"] == {"name": "y"}
    assert watch_events(cap) == []


def test_form_and_multipart_strip_and_multivalue_preserved():
    import io
    app, sentry, cap = make()
    sentry.watch("/items").body("secret")
    c = app.test_client()
    r = c.post("/items", data={"secret": "1", "tag": ["a", "b"], "n": "z"})
    assert r.get_json()["form"] == {"tag": ["a", "b"], "n": ["z"]}
    assert len(watch_events(cap)) == 1

    cap.events.clear()
    r = c.post("/items", data={"secret": "1", "tag": ["a", "b"], "f": (io.BytesIO(b"x"), "x.txt")},
               content_type="multipart/form-data")
    assert r.get_json()["form"] == {"tag": ["a", "b"]}
    assert len(watch_events(cap)) == 1


def test_duplicate_key_evasion_detected():
    app, sentry, cap = make()
    sentry.watch("/items").query("role", default="user").body("role", default="user")
    c = app.test_client()
    # first value matches the default, second does not
    r = c.get("/items?role=user&role=admin")
    assert r.get_json()["args"] == {}
    assert len(watch_events(cap)) == 1
    cap.events.clear()
    c.post("/items", data={"role": ["user", "admin"]})
    assert len(watch_events(cap)) == 1
    cap.events.clear()
    # all occurrences match -> no violation
    c.get("/items?role=user&role=user")
    assert watch_events(cap) == []


@pytest.mark.parametrize("payload", [[1, 2], "just a string", 5, None, [{"x": 1}, "y"]])
def test_non_object_json_does_not_500(payload):
    app, sentry, cap = make()
    sentry.watch("/items").body("secret")
    r = app.test_client().post("/items", data=json.dumps(payload), content_type="application/json")
    assert r.status_code == 200


def test_json_array_elements_are_stripped():
    app, sentry, cap = make()
    sentry.watch("/items").body("secret")
    r = app.test_client().post("/items", json=[{"secret": 1, "a": 2}])
    assert r.get_json()["json"] == [{"a": 2}]
    assert len(watch_events(cap)) == 1


def test_raising_identify_user_does_not_break_request():
    def boom(r):
        raise RuntimeError("nope")
    app, sentry, cap = make(identify=boom)
    sentry.trap("/trap")
    sentry.watch("/items").query("debug")
    c = app.test_client()
    assert c.get("/trap").status_code == 401
    r = c.get("/items?debug=1&x=2")
    assert r.status_code == 200
    assert r.get_json()["args"] == {"x": ["2"]}


def test_proxyfix_preserved():
    from werkzeug.middleware.proxy_fix import ProxyFix
    app, sentry, cap = make()
    sentry.trap("/trap")
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)
    c = app.test_client()
    c.get("/trap", headers={"X-Forwarded-For": "9.9.9.9"})
    c.get("/trap", headers={"X-Forwarded-For": "8.8.8.8"})
    assert [e["ip"] for e in cap.events] == ["9.9.9.9", "8.8.8.8"]


def test_trap_duplicate_route_fails_loud():
    app, sentry, cap = make()
    sentry.trap("/items").methods("GET")
    with pytest.raises(RuntimeError, match="duplicates"):
        sentry.bootstrap()


def test_trap_not_shadowed_by_catch_all():
    app = Flask(__name__)

    @app.route("/<path:p>")
    def catch(p):
        return "app"

    sentry = Sentry(app, "svc", "test")
    cap = Capture()
    sentry._handlers.append(cap)
    sentry.trap("/admin")
    r = app.test_client().get("/admin")
    assert r.status_code == 401
    assert app.test_client().get("/other").data == b"app"


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


@pytest.mark.parametrize("ctype,raw", _VARIANTS)
def test_encoding_and_content_type_bypasses_stripped_everywhere(ctype, raw):
    app, sentry, cap = make()

    @app.route("/raw", methods=["POST"])
    def rawview():
        a = request.get_data()
        b = request.data  # noqa: F841
        return jsonify(
            forced=request.get_json(force=True, silent=True),
            raw=json.loads(a),
            stream=json.loads(request.stream.read()),
            clen=request.content_length,
            alen=len(a),
        )

    sentry.watch("/raw").body("is_admin")
    r = app.test_client().post("/raw", data=raw, headers={"content-type": ctype})
    d = r.get_json()
    assert d["forced"] == {"name": "x"} and d["raw"] == {"name": "x"} and d["stream"] == {"name": "x"}
    assert d["clen"] == d["alen"]
    assert len(watch_events(cap)) == 1


def test_get_data_consistent_when_get_json_read_first():
    app, sentry, cap = make()

    @app.route("/raw2", methods=["POST"])
    def raw2():
        first = request.get_json(silent=True)
        return jsonify(first=first, raw=json.loads(request.get_data()))

    sentry.watch("/raw2").body("is_admin")
    d = app.test_client().post("/raw2", json=_PAYLOAD).get_json()
    assert d["first"] == {"name": "x"} and d["raw"] == {"name": "x"}


def test_watch_on_blueprint_route():
    """R7: routes mounted through a Blueprint (with url_prefix) are watched."""
    from flask import Blueprint

    app = Flask(__name__)
    bp = Blueprint("api", __name__, url_prefix="/api")

    @bp.post("/users/<uid>")
    def user(uid):
        return jsonify(args=request.args.to_dict(), json=request.get_json(silent=True))

    app.register_blueprint(bp)
    sentry = Sentry(app, "svc", "test")
    cap = Capture()
    sentry._handlers.append(cap)
    sentry.watch("/api/users/<uid>").query("debug", intent="q").body("is_admin", intent="b")

    r = app.test_client().post("/api/users/7?debug=1&x=1", json={"is_admin": True, "n": 1})
    assert r.get_json() == {"args": {"x": "1"}, "json": {"n": 1}}
    [event] = watch_events(cap)
    assert {f["field"] for f in event["found_fields"]} == {"debug", "is_admin"}


def test_concurrent_first_requests_bootstrap_once():
    """R8: Flask bootstraps on the first request; under a threaded server many arrive at once."""
    import threading
    import urllib.error
    import urllib.request
    from werkzeug.serving import make_server

    app = Flask(__name__)
    sentry = Sentry(app, "svc", "test")
    cap = Capture()
    sentry._handlers.append(cap)
    sentry.trap("/admin/backup")
    srv = make_server("127.0.0.1", 0, app, threaded=True)
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
    assert codes == [401] * 24
    assert len([e for e in cap.events if e["event"] == "trappsec.trap_hit"]) == 24


@pytest.mark.parametrize("csrf_first", [True, False])
def test_traps_answer_under_flask_wtf_csrf(csrf_first):
    """R22: Flask-WTF's CSRFProtect must not turn a POST trap into a silent 400."""
    csrf_mod = pytest.importorskip("flask_wtf.csrf")
    app = Flask(__name__)
    app.secret_key = "s"

    @app.post("/real")
    def real():
        return "ok"

    if csrf_first:
        csrf_mod.CSRFProtect(app)
    sentry = Sentry(app, "svc", "test")
    cap = Capture()
    sentry._handlers.append(cap)
    sentry.trap("/admin/backup").methods("POST")
    if not csrf_first:
        csrf_mod.CSRFProtect(app)
    c = app.test_client()
    assert c.post("/real").status_code == 400  # CSRF still protects real routes
    assert c.post("/admin/backup").status_code == 401
    assert len([e for e in cap.events if e["event"] == "trappsec.trap_hit"]) == 1
