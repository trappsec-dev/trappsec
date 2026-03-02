# /// script
# dependencies = [
#   "starlette",
#   "uvicorn",
#   "python-multipart",
#   "requests",
#   "opentelemetry-api",
#   "opentelemetry-sdk",
#   "opentelemetry-instrumentation-asgi",
# ]
# ///

import sys
import os
import random
import argparse

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.staticfiles import StaticFiles
from starlette.routing import Route, Mount

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../packages/python/src")))
import trappsec

app = Starlette()
ts = trappsec.Sentry(app, service="StarletteApp", environment="Development")

ts.default_responses["unauthenticated"] = {
    "status_code": 401,
    "response_body": {"error": "authentication required"},
    "mime_type": "application/json"
}

ts.identify_user(lambda r: {
    "user": r.headers.get("x-user-id"),
    "role": r.headers.get("x-user-role")
})
ts.override_source_ip(lambda r: r.headers.get("x-real-ip", r.client.host if r.client else "0.0.0.0"))


async def register(request: Request):
    email = None
    ctype = request.headers.get("content-type", "")
    if "application/json" in ctype:
        data = await request.json()
        email = data.get("email") if isinstance(data, dict) else None
    else:
        form = await request.form()
        email = form.get("email")
    return JSONResponse({"status": "registered", "email": email})


async def get_profile(request: Request):
    name = request.headers.get("x-user-id")
    return JSONResponse({"name": name, "is_admin": False})


async def update_profile(request: Request):
    name = request.headers.get("x-user-id")
    return JSONResponse({"name": name, "status": "updated"})


async def get_orders(_request: Request):
    return JSONResponse({
        "orders": [
            {"id": "ord-123", "item": "Laptop", "amount": 1200},
            {"id": "ord-124", "item": "Mouse", "amount": 45}
        ]
    })


app.router.routes.extend([
    Route("/auth/register", register, methods=["POST"]),
    Route("/api/v2/profile", get_profile, methods=["GET"]),
    Route("/api/v2/profile", update_profile, methods=["POST"]),
    Route("/api/v2/orders", get_orders, methods=["GET"]),
])

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

frontend_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'lure-frontend')
app.router.routes.append(Mount("/", app=StaticFiles(directory=frontend_dir, html=True), name="frontend"))


def setup_opentelemetry(application):
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
    from opentelemetry.instrumentation.asgi import OpenTelemetryMiddleware

    provider = TracerProvider()
    provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))
    trace.set_tracer_provider(provider)

    application.add_middleware(OpenTelemetryMiddleware)


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

    import uvicorn
    print("Starting server on http://127.0.0.1:8000")
    uvicorn.run(app, host="127.0.0.1", port=8000)
