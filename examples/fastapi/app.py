# /// script
# dependencies = [
#   "fastapi",
#   "uvicorn",
#   "requests",
#   "python-multipart",
#   "opentelemetry-api",
#   "opentelemetry-sdk",
#   "opentelemetry-instrumentation-fastapi",
# ]
# ///

import sys
import os
import logging
import random
import uvicorn

from fastapi import FastAPI, Request, Header, Body, Form
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from typing import Optional

# Ensure we can import trappsec from git repository
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../packages/python/src")))

import trappsec

logging.basicConfig(level=logging.INFO)

app = FastAPI()



ts = trappsec.Sentry(app, service="FastAPIApp", environment="Development")

# customize default responses
ts.default_responses["unauthenticated"] = {
    "status_code": 401,
    "response_body": {"error": "authentication required"},
    "mime_type": "application/json"
}

# identiy user
ts.identify_user(lambda r: {
    "user": r.headers.get("x-user-id"),
    "role": r.headers.get("x-user-role")
})

# override source ip
ts.override_source_ip(lambda r: r.headers.get("x-real-ip", r.client.host if r.client else "0.0.0.0"))

#############################
##  APPLICATION ROUTES 
#############################

@app.post("/auth/register")
async def register(
    email: Optional[str] = Form(None), 
    json_body: Optional[dict] = Body(None)
):
    # Support both form and json for email, favoring form if present
    final_email = email
    if not final_email and json_body:
        final_email = json_body.get("email")
        
    return JSONResponse(content={"status": "registered", "email": final_email})

@app.get("/api/v2/profile")
async def get_profile(x_user_id: Optional[str] = Header(None)):
    return JSONResponse(content={"name": x_user_id, "is_admin": False})

@app.post("/api/v2/profile")
async def update_profile(x_user_id: Optional[str] = Header(None)):
    return JSONResponse(content={"name": x_user_id, "status": "updated"})

@app.get("/api/v2/orders")
async def get_orders():
    return JSONResponse(content={
        "orders": [
            {"id": "ord-123", "item": "Laptop", "amount": 1200},
            {"id": "ord-124", "item": "Mouse", "amount": 45}
        ]
    })

@app.get("/api/v2/orders/{order_id}")
async def get_order_detail(order_id: str):
    return JSONResponse(content={"id": order_id, "item": "Laptop", "amount": 1200, "status": "shipped"})

@app.get("/api/v2/echo/query")
async def echo_query(request: Request):
    return JSONResponse(content=dict(request.query_params))

@app.post("/api/v2/echo/body")
async def echo_body(request: Request):
    try:
        data = await request.json()
        return JSONResponse(content=data if isinstance(data, dict) else {})
    except Exception:
        return JSONResponse(content={})

@app.post("/api/v2/echo/form")
async def echo_form(request: Request):
    form = await request.form()
    return JSONResponse(content={k: v for k, v in form.items() if isinstance(v, str)})

@app.post("/api/v2/echo/multipart")
async def echo_multipart(request: Request):
    form = await request.form()
    return JSONResponse(content={k: v for k, v in form.items() if isinstance(v, str)})

#############################
##  DECOY ROUTES
#############################

ts.trap("/deployment/config") \
    .methods("GET") \
    .intent("Reconnaissance") \
    .respond(200, {"region": "us-east-1", "deployment_type": "production"})

ts.trap("/deployment/metrics") \
    .methods("GET") \
    .intent("Reconnaissance") \
    .respond(200, lambda r: {"cpu": f"{random.randint(5, 95)}%", "memory": f"{random.randint(20, 90)}%"})

ts.template(name="fake_deprecated_api_response", status_code=410, 
    response_body={"error": "Gone", "message": "API v1 has been deprecated"},
    mime_type="application/json")

ts.trap("/api/v1/orders") \
    .methods("GET", "POST") \
    .intent("Legacy API Probing") \
    .respond(template="fake_deprecated_api_response")

ts.trap("/api/v1/profile") \
    .methods("GET", "POST") \
    .intent("Legacy API Probing") \
    .respond(template="fake_deprecated_api_response")

#############################
##  HONEY FIELDS 
#############################

ts.watch("/auth/register") \
    .body("role", default="user", intent="Privilege Escalation (role)") \
    .body("credits", default=0, intent="Credit Manipulation")

ts.watch("/api/v2/profile") \
    .body("is_admin", intent="Privilege Escalation")

ts.watch("/api/v2/orders/{order_id}") \
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

# Mount the frontend static files (placed last to avoid shadowing API routes)
FRONTEND_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'lure-frontend')
app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")


def setup_opentelemetry(app):
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

    provider = TracerProvider()
    processor = BatchSpanProcessor(ConsoleSpanExporter())
    provider.add_span_processor(processor)
    trace.set_tracer_provider(provider)

    FastAPIInstrumentor.instrument_app(app)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()

    parser.add_argument("--otel", action="store_true",
        help="Enable OpenTelemetry Integration")

    parser.add_argument("--webhook", type=str,
        help="Enable Webhook Integration")

    args = parser.parse_args()

    if args.otel:
        setup_opentelemetry(app)
        ts.add_otel()
    
    if args.webhook:
        ts.add_webhook(url=args.webhook, alerts_only=False)

    print("Starting server on http://127.0.0.1:8000")
    uvicorn.run(app, host="127.0.0.1", port=8000)

