# /// script
# dependencies = [
#   "tornado",
#   "requests",
#   "opentelemetry-api",
#   "opentelemetry-sdk",
#   "opentelemetry-instrumentation-tornado",
# ]
# ///

import sys
import os
import json
import random
import argparse
from urllib.parse import parse_qs

import tornado.ioloop
import tornado.web

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../packages/python/src")))
import trappsec


class RegisterHandler(tornado.web.RequestHandler):
    def post(self):
        email = None
        ctype = self.request.headers.get("Content-Type", "")
        if "application/json" in ctype:
            try:
                data = json.loads(self.request.body.decode("utf-8"))
                email = data.get("email")
            except Exception:
                email = None
        else:
            parsed = parse_qs(self.request.body.decode("utf-8")) if self.request.body else {}
            if "email" in parsed and parsed["email"]:
                email = parsed["email"][0]

        self.write({"status": "registered", "email": email})


class ProfileHandler(tornado.web.RequestHandler):
    def get(self):
        self.write({"name": self.request.headers.get("x-user-id"), "is_admin": False})

    def post(self):
        self.write({"name": self.request.headers.get("x-user-id"), "status": "updated"})


class OrdersHandler(tornado.web.RequestHandler):
    def get(self):
        self.write({
            "orders": [
                {"id": "ord-123", "item": "Laptop", "amount": 1200},
                {"id": "ord-124", "item": "Mouse", "amount": 45}
            ]
        })


class OrderDetailHandler(tornado.web.RequestHandler):
    def get(self, order_id):
        self.write({"id": order_id, "item": "Laptop", "amount": 1200, "status": "shipped"})


class EchoQueryHandler(tornado.web.RequestHandler):
    def get(self):
        result = {}
        for k in self.request.query_arguments:
            result[k] = self.get_query_argument(k)
        self.write(result)


class EchoBodyHandler(tornado.web.RequestHandler):
    def post(self):
        try:
            data = json.loads(self.request.body.decode("utf-8"))
            self.write(data if isinstance(data, dict) else {})
        except Exception:
            self.write({})


class EchoFormHandler(tornado.web.RequestHandler):
    def post(self):
        parsed = parse_qs(self.request.body.decode("utf-8")) if self.request.body else {}
        self.write({k: v[0] if v else "" for k, v in parsed.items()})


class EchoMultipartHandler(tornado.web.RequestHandler):
    def post(self):
        result = {}
        for k, v_list in self.request.body_arguments.items():
            if v_list:
                result[k] = v_list[0].decode("utf-8")
        self.write(result)


class IndexHandler(tornado.web.RequestHandler):
    def get(self):
        frontend_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'lure-frontend')
        with open(os.path.join(frontend_dir, "index.html"), "rb") as f:
            self.set_header("Content-Type", "text/html")
            self.write(f.read())


class StaticHandler(tornado.web.RequestHandler):
    def get(self, path):
        frontend_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'lure-frontend')
        file_path = os.path.join(frontend_dir, path)
        if not os.path.isfile(file_path):
            self.set_status(404)
            self.write("not found")
            return

        if path.endswith(".css"):
            self.set_header("Content-Type", "text/css")
        elif path.endswith(".js"):
            self.set_header("Content-Type", "application/javascript")
        else:
            self.set_header("Content-Type", "application/octet-stream")

        with open(file_path, "rb") as f:
            self.write(f.read())


def make_app():
    app = tornado.web.Application([
        (r"/auth/register", RegisterHandler),
        (r"/api/v2/profile", ProfileHandler),
        (r"/api/v2/orders", OrdersHandler),
        (r"/api/v2/orders/([^/]+)", OrderDetailHandler),
        (r"/api/v2/echo/query", EchoQueryHandler),
        (r"/api/v2/echo/body", EchoBodyHandler),
        (r"/api/v2/echo/form", EchoFormHandler),
        (r"/api/v2/echo/multipart", EchoMultipartHandler),
        (r"/", IndexHandler),
        (r"/(.*)", StaticHandler),
    ])

    ts = trappsec.Sentry(app, service="TornadoApp", environment="Development")

    ts.default_responses["unauthenticated"] = {
        "status_code": 401,
        "response_body": {"error": "authentication required"},
        "mime_type": "application/json"
    }

    ts.identify_user(lambda r: {
        "user": r.headers.get("x-user-id"),
        "role": r.headers.get("x-user-role")
    })
    ts.override_source_ip(lambda r: r.headers.get("x-real-ip", r.remote_ip))

    # Traps
    ts.trap("/deployment/config") \
        .methods("GET") \
        .intent("Reconnaissance") \
        .respond(200, {"region": "us-east-1", "deployment_type": "production"})

    ts.trap("/deployment/metrics") \
        .methods("GET") \
        .intent("Reconnaissance") \
        .respond(200, lambda _r: {"cpu": f"{random.randint(5, 95)}%", "memory": f"{random.randint(20, 90)}%"})

    ts.template("fake_deprecated_api_response", 410,
        {"error": "Gone", "message": "API v1 has been deprecated"},
        "application/json")

    ts.trap("/api/v1/orders") \
        .methods("GET", "POST") \
        .intent("Legacy API Probing") \
        .respond(template="fake_deprecated_api_response")

    ts.trap("/api/v1/profile") \
        .methods("GET", "POST") \
        .intent("Legacy API Probing") \
        .respond(template="fake_deprecated_api_response")

    # Watches
    ts.watch("/auth/register") \
        .body("role", default="user", intent="Privilege Escalation (role)") \
        .body("credits", default=0, intent="Credit Manipulation")

    ts.watch("/api/v2/profile") \
        .body("is_admin", intent="Privilege Escalation")

    ts.watch("/api/v2/orders/([^/]+)") \
        .query("discount_code", default="NONE", intent="Coupon Tampering")

    ts.watch("/api/v2/echo/query") \
        .query("honey_q", intent="Query Field Test") \
        .query("role_q", default="user", intent="Query Default Test")

    ts.watch("/api/v2/echo/body") \
        .body("honey_b", intent="Body Field Test") \
        .body("role_b", default="user", intent="Body Default Test")

    ts.watch("/api/v2/echo/form") \
        .body("honey_f", intent="Form Field Test")

    ts.watch("/api/v2/echo/multipart") \
        .body("honey_m", intent="Multipart Field Test")

    return app, ts


def setup_opentelemetry():
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
    from opentelemetry.instrumentation.tornado import TornadoInstrumentor

    provider = TracerProvider()
    provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))
    trace.set_tracer_provider(provider)

    TornadoInstrumentor().instrument()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--otel", action="store_true")
    parser.add_argument("--webhook", type=str)
    args = parser.parse_args()

    app, ts = make_app()

    if args.otel:
        setup_opentelemetry()
        ts.add_otel()

    if args.webhook:
        ts.add_webhook(url=args.webhook, alerts_only=False)

    app.listen(8000, address="127.0.0.1")
    print("Starting server on http://127.0.0.1:8000")
    tornado.ioloop.IOLoop.current().start()

