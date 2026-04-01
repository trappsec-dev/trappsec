# /// script
# dependencies = [
#   "litestar",
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
import argparse
import random

from litestar import Litestar, get, post, Request, Response

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../packages/python/src")))
import trappsec


@post("/auth/register", status_code=200)
async def register(request: Request) -> dict:
    email = None
    ctype = request.headers.get("content-type", "")
    if "application/json" in ctype:
        data = await request.json()
        email = data.get("email") if isinstance(data, dict) else None
    elif "application/x-www-form-urlencoded" in ctype or "multipart/form-data" in ctype:
        form = await request.form()
        email = form.get("email")
    return {"status": "registered", "email": email}


@get("/api/v2/profile")
async def get_profile(request: Request) -> dict:
    return {"name": request.headers.get("x-user-id"), "is_admin": False}


@post("/api/v2/profile", status_code=200)
async def update_profile(request: Request) -> dict:
    return {"name": request.headers.get("x-user-id"), "status": "updated"}


@get("/api/v2/orders")
async def get_orders() -> dict:
    return {
        "orders": [
            {"id": "ord-123", "item": "Laptop", "amount": 1200},
            {"id": "ord-124", "item": "Mouse", "amount": 45},
        ]
    }


@get("/api/v2/orders/{order_id:str}")
async def get_order_detail(order_id: str) -> dict:
    return {"id": order_id, "item": "Laptop", "amount": 1200, "status": "shipped"}


@get("/api/v2/echo/query")
async def echo_query(request: Request) -> dict:
    return dict(request.query_params)


@post("/api/v2/echo/body", status_code=200)
async def echo_body(request: Request) -> dict:
    try:
        data = await request.json()
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


@post("/api/v2/echo/form", status_code=200)
async def echo_form(request: Request) -> dict:
    form = await request.form()
    return {k: v for k, v in form.items() if isinstance(v, str)}


@post("/api/v2/echo/multipart", status_code=200)
async def echo_multipart(request: Request) -> dict:
    form = await request.form()
    return {k: v for k, v in form.items() if isinstance(v, str)}


@get("/")
async def serve_index() -> Response:
    frontend_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'lure-frontend')
    with open(os.path.join(frontend_dir, "index.html"), "rb") as f:
        return Response(content=f.read(), media_type="text/html")


@get("/{path:path}")
async def serve_static(path: str) -> Response:
    frontend_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'lure-frontend')
    file_path = os.path.join(frontend_dir, path)
    if not os.path.isfile(file_path):
        return Response(content=b"not found", status_code=404, media_type="text/plain")
    with open(file_path, "rb") as f:
        data = f.read()
    if path.endswith(".css"):
        mtype = "text/css"
    elif path.endswith(".js"):
        mtype = "application/javascript"
    else:
        mtype = "application/octet-stream"
    return Response(content=data, media_type=mtype)


app = Litestar(route_handlers=[
    register,
    get_profile,
    update_profile,
    get_orders,
    get_order_detail,
    echo_query,
    echo_body,
    echo_form,
    echo_multipart,
    serve_index,
    serve_static,
])

ts = trappsec.Sentry(app, service="LitestarApp", environment="Development")

ts.default_responses["unauthenticated"] = {
    "status_code": 401,
    "response_body": {"error": "authentication required"},
    "mime_type": "application/json",
}

ts.identify_user(lambda r: {
    "user": r.headers.get("x-user-id"),
    "role": r.headers.get("x-user-role")
})
ts.override_source_ip(lambda r: r.headers.get("x-real-ip", r.client.host if r.client else "0.0.0.0"))

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

ts.watch("/api/v2/orders/{order_id:str}") \
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
    from opentelemetry.instrumentation.asgi import OpenTelemetryMiddleware

    provider = TracerProvider()
    provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))
    trace.set_tracer_provider(provider)

    application.asgi_handler = OpenTelemetryMiddleware(application.asgi_handler)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--otel", action="store_true")
    parser.add_argument("--webhook", type=str)
    args = parser.parse_args()

    if args.otel:
        setup_opentelemetry(app)
        ts.add_otel()

    if args.webhook:
        ts.add_webhook(url=args.webhook, alerts_only=False)

    import uvicorn
    print("Starting server on http://127.0.0.1:8000")
    uvicorn.run(app, host="127.0.0.1", port=8000)

