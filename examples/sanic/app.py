# /// script
# dependencies = [
#   "sanic",
#   "requests",
#   "opentelemetry-api",
#   "opentelemetry-sdk",
# ]
# ///

import sys
import os
import random
import argparse

from sanic import Sanic
from sanic.response import json as json_response
from sanic.response import file as file_response

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../packages/python/src")))
import trappsec

app = Sanic("trappsec-sanic-example")
ts = trappsec.Sentry(app, service="SanicApp", environment="Development")

# Handlers are configured at module level so that spawned worker processes
# (which re-import this module but never execute __main__) pick them up.
_webhook_url = os.environ.get("TRAPPSEC_WEBHOOK_URL")
if _webhook_url:
    ts.add_webhook(url=_webhook_url, alerts_only=False)

ts.default_responses["unauthenticated"] = {
    "status_code": 401,
    "response_body": {"error": "authentication required"},
    "mime_type": "application/json"
}

ts.identify_user(lambda r: {
    "user": r.headers.get("x-user-id"),
    "role": r.headers.get("x-user-role")
})
ts.override_source_ip(lambda r: r.headers.get("x-real-ip", r.remote_addr or "0.0.0.0"))


@app.post("/auth/register")
async def register(request):
    email = None
    content_type = request.content_type or ""
    if "application/json" in content_type and isinstance(request.json, dict):
        email = request.json.get("email")
    elif request.form:
        email = request.form.get("email")
    return json_response({"status": "registered", "email": email})


@app.get("/api/v2/profile")
async def get_profile(request):
    return json_response({"name": request.headers.get("x-user-id"), "is_admin": False})


@app.post("/api/v2/profile")
async def update_profile(request):
    return json_response({"name": request.headers.get("x-user-id"), "status": "updated"})


@app.get("/api/v2/orders")
async def get_orders(_request):
    return json_response({
        "orders": [
            {"id": "ord-123", "item": "Laptop", "amount": 1200},
            {"id": "ord-124", "item": "Mouse", "amount": 45}
        ]
    })


@app.get("/api/v2/orders/<order_id>")
async def get_order_detail(_request, order_id):
    return json_response({"id": order_id, "item": "Laptop", "amount": 1200, "status": "shipped"})


@app.get("/api/v2/echo/query")
async def echo_query(request):
    return json_response({k: v[0] if isinstance(v, list) and v else v for k, v in request.args.items()})


@app.post("/api/v2/echo/body")
async def echo_body(request):
    try:
        data = request.json
        return json_response(data if isinstance(data, dict) else {})
    except Exception:
        return json_response({})


@app.post("/api/v2/echo/form")
async def echo_form(request):
    return json_response({k: v[0] if isinstance(v, list) and v else v for k, v in request.form.items()})


@app.post("/api/v2/echo/multipart")
async def echo_multipart(request):
    return json_response({k: v[0] if isinstance(v, list) and v else v for k, v in request.form.items()})


@app.get("/")
async def serve_index(_request):
    frontend_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'lure-frontend')
    return await file_response(os.path.join(frontend_dir, "index.html"))


@app.get("/<path:path>")
async def serve_static(_request, path):
    frontend_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'lure-frontend')
    full_path = os.path.join(frontend_dir, path)
    if not os.path.isfile(full_path):
        return json_response({"error": "not found"}, status=404)
    return await file_response(full_path)


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

ts.watch("/api/v2/orders/<order_id>") \
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


def setup_opentelemetry(application):
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter

    provider = TracerProvider()
    processor = BatchSpanProcessor(ConsoleSpanExporter(formatter=lambda span: span.to_json(indent=None) + "\n"))
    provider.add_span_processor(processor)
    trace.set_tracer_provider(provider)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--otel", action="store_true")
    parser.add_argument("--webhook", type=str)
    args = parser.parse_args()

    if args.otel:
        setup_opentelemetry(app)
        ts.add_otel()

    if args.webhook:
        # Set before app.run() so spawned worker processes inherit this env var
        # and add the webhook handler via the module-level block above.
        os.environ["TRAPPSEC_WEBHOOK_URL"] = args.webhook
        ts.add_webhook(url=args.webhook, alerts_only=False)

    print("Starting server on http://127.0.0.1:8000")
    app.run(host="127.0.0.1", port=8000, access_log=False)

