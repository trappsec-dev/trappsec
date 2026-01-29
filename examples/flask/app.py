# /// script
# dependencies = [
#   "flask",
#   "requests",
#   "opentelemetry-api",
#   "opentelemetry-sdk",
#   "opentelemetry-instrumentation-flask",
# ]
# ///

import sys
import os
import logging
import random

from flask import Flask, request, jsonify, send_from_directory

# Ensure we can import trappsec from git repository
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../packages/python/src")))

import trappsec

logging.basicConfig(level=logging.INFO)

# Define static folder path (lure-frontend is parallel to flask folder)
FRONTEND_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'lure-frontend')

app = Flask(__name__)
app.secret_key = "super-secret-key"

ts = trappsec.Sentry(app, service="FlaskApp", environment="Development")

# customize default responses for decoy routes to blend into your application
ts.default_responses["unauthenticated"] = {
    "status_code": 401,
    "response_body": {"error": "authentication required"},
    "mime_type": "application/json"
}

# dummy logic to resolve user info for the sake of demo
ts.identify_user(lambda r: {
    "user": r.headers.get("x-user-id"),
    "role": r.headers.get("x-user-role")
})

# dummy logic to resolve ip address for the sake of demo
ts.override_source_ip(lambda r: r.headers.get("x-real-ip", r.remote_addr))

#############################
##  APPLICATION ROUTES 
#############################

@app.route("/")
def serve_index():
    return send_from_directory(FRONTEND_DIR, 'index.html')

@app.route("/<path:path>")
def serve_static(path):
    return send_from_directory(FRONTEND_DIR, path)

@app.route("/auth/register", methods=["POST"])
def register():
    email = request.form.get("email") or (request.json and request.json.get("email"))
    return jsonify({"status": "registered", "email": email})

@app.route("/api/v2/profile", methods=["GET"])
def get_profile():
    name = request.headers.get("x-user-id")
    return jsonify({"name": name, "is_admin": False})

@app.route("/api/v2/profile", methods=["POST"])
def update_profile():
    name = request.headers.get("x-user-id")
    return jsonify({"name": name, "status": "updated"})

@app.route("/api/v2/orders", methods=["GET"])
def get_orders():
    return jsonify({
        "orders": [
            {"id": "ord-123", "item": "Laptop", "amount": 1200},
            {"id": "ord-124", "item": "Mouse", "amount": 45}
        ]
    })

#############################
##  DECOY ROUTES 
#############################

# example of a decoy route with a static response
ts.trap("/deployment/config") \
    .methods("GET") \
    .intent("Reconnaissance") \
    .respond(200, {"region": "us-east-1", "deployment_type": "production"})

# example of a decoy route with a dynamic response
ts.trap("/deployment/metrics") \
    .methods("GET") \
    .intent("Reconnaissance") \
    .respond(200, lambda r: {"cpu": f"{random.randint(5, 95)}%", "memory": f"{random.randint(20, 90)}%"})

# templates can be used when a response is applicable to multiple scenarios
ts.template(name="fake_deprecated_api_response", status_code=410, 
    response_body={"error": "Gone", "message": "API v1 has been deprecated"},
    mime_type="application/json")

# a decoy route using above defined template 
ts.trap("/api/v1/orders") \
    .methods("GET", "POST") \
    .intent("Legacy API Probing") \
    .respond(template="fake_deprecated_api_response")

# another decoy route using a template
ts.trap("/api/v1/profile") \
    .methods("GET", "POST") \
    .intent("Legacy API Probing") \
    .respond(template="fake_deprecated_api_response")

#############################
##  HONEY FIELDS 
#############################

# watch if any of the fields specified exist and deviate from the default value.
# useful when lures are hardcoded keys in frontend requests or html forms.
ts.watch("/auth/register") \
    .body("is_admin", default=False, intent="Privilege Escalation (is_admin)") \
    .body("role", default="user", intent="Privilege Escalation (role)") \
    .body("credits", default=0, intent="Credit Manipulation")

# alerts on presence of key irrespective of value
# useful when lure is a dummy key returned in other API responses.
ts.watch("/api/v2/profile") \
    .body("is_admin", intent="Privilege Escalation") \

def setup_opentelemetry(app):
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
    from opentelemetry.instrumentation.flask import FlaskInstrumentor

    provider = TracerProvider()
    processor = BatchSpanProcessor(ConsoleSpanExporter())
    provider.add_span_processor(processor)
    trace.set_tracer_provider(provider)

    FlaskInstrumentor().instrument_app(app)

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
    app.run(port=8000, debug=True)
