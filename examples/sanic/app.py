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
    if isinstance(request.json, dict):
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


@app.get("/")
async def serve_index(_request):
    frontend_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'lure-frontend')
    return await file_response(os.path.join(frontend_dir, "index.html"))


@app.get("/<path:path>")
async def serve_static(_request, path):
    frontend_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'lure-frontend')
    return await file_response(os.path.join(frontend_dir, path))


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


def setup_opentelemetry(application):
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter

    provider = TracerProvider()
    processor = BatchSpanProcessor(ConsoleSpanExporter())
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
        ts.add_webhook(url=args.webhook)

    print("Starting server on http://127.0.0.1:8000")
    app.run(host="127.0.0.1", port=8000, access_log=False)
