import json

import pytest

pytest.importorskip("tornado")

import tornado.web  # noqa: E402
from tornado.httpserver import HTTPServer  # noqa: E402
import tornado.testing  # noqa: E402  (module import: pytest must not collect the base TestCase)

from trappsec.core import Sentry  # noqa: E402


class Capture:
    def __init__(self):
        self.events = []

    def emit(self, event):
        self.events.append(event)

    def close(self, *a, **k):
        pass


class EchoHandler(tornado.web.RequestHandler):
    def _dump(self):
        self.write({
            "args": {k: [v.decode() for v in vs] for k, vs in self.request.arguments.items()},
            "query_args": {k: [v.decode() for v in vs] for k, vs in self.request.query_arguments.items()},
            "body_args": {k: [v.decode() for v in vs] for k, vs in self.request.body_arguments.items()},
            "x_arg": self.get_argument("x", None),
            "a_all": self.get_arguments("a"),
            "query": self.request.query,
            "uri": self.request.uri,
            "body": self.request.body.decode("utf-8", "replace"),
            "clen": self.request.headers.get("Content-Length"),
        })

    get = post = put = _dump


class UserHandler(tornado.web.RequestHandler):
    def get(self, uid):
        self.write({"who": uid, "args": {k: [v.decode() for v in vs] for k, vs in self.request.arguments.items()}})


class MeHandler(tornado.web.RequestHandler):
    def get(self):
        self.write({"who": "me", "args": {k: [v.decode() for v in vs] for k, vs in self.request.arguments.items()}})


class SentryCase(tornado.testing.AsyncHTTPTestCase):
    watches = staticmethod(lambda s: s.watch("/echo").query("x", intent="q").body("x", intent="b"))
    identify = None
    traps = staticmethod(lambda s: s.trap("/admin/secret"))

    def get_app(self):
        app = tornado.web.Application([
            (r"/echo", EchoHandler),
            (r"/users/me", MeHandler),
            (r"/users/(\d+)", UserHandler),
        ])
        self.sentry = Sentry(app, "svc", "test")
        self.cap = Capture()
        self.sentry._handlers.append(self.cap)
        if self.identify:
            self.sentry.identify_user(self.identify)
        if self.traps:
            self.traps(self.sentry)
        if self.watches:
            self.watches(self.sentry)
        return app

    def hits(self, event):
        return [e for e in self.cap.events if e["event"] == event]

    def runTest(self):  # Tornado < 6.4 looks this name up when pytest instantiates the class
        pass


class TestTraps(SentryCase):
    @staticmethod
    def identify(r):
        u = r.headers.get("X-User")
        return {"user": u, "role": "admin"} if u else None

    traps = staticmethod(lambda s: (s.trap("/admin/secret").methods("GET"), s.trap("/dup/trap")))

    def test_trap_unauth_and_auth_via_httpserver_path(self):
        # AsyncHTTPTestCase serves the app with HTTPServer(app): no app.listen() involved.
        r = self.fetch("/admin/secret")
        assert r.code == 401
        r = self.fetch("/admin/secret", headers={"X-User": "bob"})
        traps = self.hits("trappsec.trap_hit")
        assert len(traps) == 2
        assert traps[0]["type"] == "signal"
        assert traps[1]["type"] == "alert" and traps[1]["user"] == "bob"

    def test_wrong_method_looks_like_a_real_route_and_does_not_trigger(self):
        """R14: a trap's 405 must be indistinguishable from an application route's."""
        def shape(r):
            skip = {"Date", "Content-Length", "Etag"}
            return r.code, sorted(k for k in r.headers if k not in skip), r.body

        trap = self.fetch("/admin/secret", method="DELETE")
        real = self.fetch("/users/me", method="DELETE")  # MeHandler implements GET only
        assert trap.code == 405
        assert shape(trap) == shape(real)
        assert self.hits("trappsec.trap_hit") == []

    def test_bootstrap_idempotent(self):
        self.sentry.bootstrap()
        self.sentry.bootstrap()
        assert self.fetch("/admin/secret").code == 401
        assert len(self.hits("trappsec.trap_hit")) == 1

    def test_traps_precede_app_rules(self):
        self.sentry.bootstrap()
        rules = self.sentry.integration.app.default_router.rules
        assert getattr(rules[0].target, "rules", None) is not None
        first_leaf = rules[0].target.rules[0].target
        assert getattr(first_leaf, "_trappsec_trap", False)


class TestWatches(SentryCase):
    def test_query_detect_strip_consistent(self):
        r = self.fetch("/echo?x=evil&a=1&a=2&keep=")
        d = json.loads(r.body)
        assert d["x_arg"] is None
        assert "x" not in d["args"] and "x" not in d["query_args"]
        assert d["a_all"] == ["1", "2"]
        assert d["args"]["keep"] == [""]
        assert "x=" not in d["query"].replace("keep=", "") and "evil" not in d["uri"]
        ev = self.hits("trappsec.watch_hit")
        assert len(ev) == 1
        f = ev[0]["found_fields"][0]
        assert f["type"] == "query" and f["field"] == "x" and f["value"] == "evil"

    def test_duplicate_key_evasion_query(self):
        self.sentry.watch("/echo").query("y", default="ok")
        r = self.fetch("/echo?y=ok&y=evil")
        assert len(self.hits("trappsec.watch_hit")) == 1
        assert "y" not in json.loads(r.body)["args"]

    def test_json_detect_strip_and_content_length(self):
        body = json.dumps({"x": "evil" * 50, "keep": 1})
        r = self.fetch("/echo", method="POST", body=body, headers={"Content-Type": "application/json"})
        d = json.loads(r.body)
        assert json.loads(d["body"]) == {"keep": 1}
        assert int(d["clen"]) == len(d["body"])
        assert len(self.hits("trappsec.watch_hit")) == 1

    def test_json_array_and_junk_bodies(self):
        r = self.fetch("/echo", method="POST", body=json.dumps([{"x": 1, "k": 1}, 3]), headers={"Content-Type": "application/json"})
        assert json.loads(json.loads(r.body)["body"]) == [{"k": 1}, 3]
        r = self.fetch("/echo", method="POST", body="{nope", headers={"Content-Type": "application/json"})
        assert r.code == 200

    def test_form_detect_strip_multivalue(self):
        r = self.fetch("/echo", method="POST", body="x=evil&a=1&a=2&b=3",
                       headers={"Content-Type": "application/x-www-form-urlencoded"})
        d = json.loads(r.body)
        assert d["x_arg"] is None
        assert "x" not in d["args"] and "x" not in d["body_args"]
        assert d["a_all"] == ["1", "2"]
        assert "x=" not in d["body"]
        assert len(self.hits("trappsec.watch_hit")) == 1

    def test_multipart_body_rewritten(self):
        boundary = "XBOUND"
        body = (
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"x\"\r\n\r\nevil\r\n"
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n"
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"f\"; filename=\"f.txt\"\r\n"
            f"Content-Type: text/plain\r\n\r\nhello\r\n"
            f"--{boundary}--\r\n"
        ).encode()
        r = self.fetch("/echo", method="POST", body=body,
                       headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
        d = json.loads(r.body)
        assert d["x_arg"] is None
        assert "x" not in d["body_args"] and d["a_all"] == ["1"]
        assert "evil" not in d["body"] and "hello" in d["body"]
        assert int(d["clen"]) == len(d["body"].encode())
        assert len(self.hits("trappsec.watch_hit")) == 1

    def test_param_route_watch_static_route_not_watched(self):
        self.sentry.watch(r"/users/(\d+)").query("x")
        r = self.fetch("/users/5?x=1")
        assert json.loads(r.body)["args"] == {}
        assert len(self.hits("trappsec.watch_hit")) == 1
        r = self.fetch("/users/me?x=1")
        assert json.loads(r.body)["args"] == {"x": ["1"]}
        assert len(self.hits("trappsec.watch_hit")) == 1


class TestRaisingIdentify(SentryCase):
    @staticmethod
    def identify(r):
        raise RuntimeError("boom")

    def test_watch_request_survives(self):
        r = self.fetch("/echo?x=evil&a=1")
        assert r.code == 200
        d = json.loads(r.body)
        assert d["x_arg"] is None and d["a_all"] == ["1"]

    def test_trap_still_decoys(self):
        assert self.fetch("/admin/secret").code == 401


class TestDuplicateTrap(SentryCase):
    traps = staticmethod(lambda s: s.trap("/echo").methods("GET"))

    def test_fail_loud(self):
        with pytest.raises(RuntimeError, match="duplicates an existing"):
            self.sentry.bootstrap()


class TestTrapSamePathOtherMethod(SentryCase):
    traps = staticmethod(lambda s: s.trap("/users/me").methods("DELETE"))

    def test_app_route_still_serves_other_methods(self):
        assert self.fetch("/users/me").code == 200
        assert self.fetch("/users/me", method="DELETE").code == 401
        assert len(self.hits("trappsec.trap_hit")) == 1


def test_explicit_httpserver_listen_path():
    """HTTPServer(app).listen() (no app.listen) must still be protected."""
    import asyncio

    async def run():
        app = tornado.web.Application([(r"/echo", EchoHandler)])
        s = Sentry(app, "svc", "test")
        cap = Capture()
        s._handlers.append(cap)
        s.trap("/admin/secret")
        s.watch("/echo").query("x")
        sock, port = tornado.testing.bind_unused_port()
        server = HTTPServer(app)
        server.add_sockets([sock])
        from tornado.httpclient import AsyncHTTPClient
        client = AsyncHTTPClient()
        r = await client.fetch(f"http://127.0.0.1:{port}/admin/secret", raise_error=False)
        assert r.code == 401
        r = await client.fetch(f"http://127.0.0.1:{port}/echo?x=1&a=2", raise_error=False)
        assert json.loads(r.body)["x_arg"] is None
        server.stop()
        client.close()
        return cap.events

    events = asyncio.run(run())
    assert {e["event"] for e in events} == {"trappsec.trap_hit", "trappsec.watch_hit"}


import codecs  # noqa: E402

_PAYLOAD = {"x": "evil", "name": "n"}


class BypassTests(SentryCase):
    def test_encoding_and_content_type_bypasses_stripped(self):
        variants = [
            ("application/json", json.dumps(_PAYLOAD).encode("utf-16")),
            ("application/json", json.dumps(_PAYLOAD).encode("utf-32")),
            ("application/json", codecs.BOM_UTF8 + json.dumps(_PAYLOAD).encode()),
            ("application/json; charset=utf-16", json.dumps(_PAYLOAD).encode("utf-16")),
            ("text/plain", json.dumps(_PAYLOAD).encode()),
            ("application/vnd.api+json", json.dumps(_PAYLOAD).encode()),
        ]
        for n, (ctype, raw) in enumerate(variants, 1):
            r = self.fetch("/echo", method="POST", body=raw, headers={"Content-Type": ctype})
            d = json.loads(r.body)
            assert json.loads(d["body"]) == {"name": "n"}, ctype
            assert int(d["clen"]) == len(d["body"].encode())
            assert len(self.hits("trappsec.watch_hit")) == n


class TestTrapsUnderXsrfCookies(SentryCase):
    """R22: xsrf_cookies must not turn a POST trap into a 403."""
    traps = staticmethod(lambda s: s.trap("/admin/backup").methods("POST"))

    def get_app(self):
        app = super().get_app()
        app.settings["xsrf_cookies"] = True
        app.settings["cookie_secret"] = "s"
        return app

    def test_trap_answers_and_real_route_stays_protected(self):
        assert self.fetch("/echo", method="POST", body="a=1").code == 403
        assert self.fetch("/admin/backup", method="POST", body="a=1").code == 401
        assert len(self.hits("trappsec.trap_hit")) == 1


class TestNestedRouterWatch(SentryCase):
    """R7: routes inside a nested Rule(PathMatches(...), [...]) are watched."""
    traps = None
    watches = staticmethod(lambda s: s.watch(r"/api/users/(\d+)").query("debug").body("is_admin"))

    def get_app(self):
        from tornado.routing import PathMatches, Rule

        app = tornado.web.Application([Rule(PathMatches(r"/api/.*"), [(r"/api/users/(\d+)", NestedHandler)])])
        self.sentry = Sentry(app, "svc", "test")
        self.cap = Capture()
        self.sentry._handlers.append(self.cap)
        self.watches(self.sentry)
        return app

    def test_nested_route_watched(self):
        r = self.fetch("/api/users/7?debug=1&x=1", method="POST", body=json.dumps({"is_admin": True, "n": 1}),
                       headers={"Content-Type": "application/json"})
        assert json.loads(r.body) == {"args": {"x": ["1"]}, "body": {"n": 1}}
        assert len(self.hits("trappsec.watch_hit")) == 1


class NestedHandler(tornado.web.RequestHandler):
    def post(self, uid):
        self.write({"args": {k: [v.decode() for v in vs] for k, vs in self.request.arguments.items()},
                    "body": json.loads(self.request.body)})
