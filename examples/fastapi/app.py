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

@app.get("/api/v2/users")
async def get_users():
    return JSONResponse(content={
        "users": [
            {"id": 1, "username": "alice", "role": "admin"},
            {"id": 2, "username": "bob", "role": "user"}
        ]
    })

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

ts.trap("/api/v1/users") \
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
    .body("is_admin", default=False, intent="Privilege Escalation (is_admin)") \
    .body("role", default="user", intent="Privilege Escalation (role)") \
    .body("credits", default=0, intent="Credit Manipulation")

ts.watch("/api/v2/profile") \
    .body("is_admin", intent="Privilege Escalation")


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
        ts.add_webhook(url=args.webhook)

    print("Starting server on http://127.0.0.1:8000")
    uvicorn.run(app, host="127.0.0.1", port=8000)
