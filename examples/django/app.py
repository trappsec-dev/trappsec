# /// script
# dependencies = [
#   "django",
#   "requests",
#   "opentelemetry-api",
#   "opentelemetry-sdk",
#   "opentelemetry-instrumentation-django",
# ]
# ///

import os
import sys
import json
import random
import argparse
from wsgiref.simple_server import make_server

from django.conf import settings
from django.http import JsonResponse, HttpResponse
from django.urls import path, re_path
from django.core.wsgi import get_wsgi_application

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../packages/python/src")))
import trappsec


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.join(os.path.dirname(BASE_DIR), "lure-frontend")


def register(request):
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    email = None
    ctype = request.headers.get("Content-Type", "")
    if "application/json" in ctype:
        try:
            data = json.loads(request.body.decode("utf-8"))
            email = data.get("email")
        except Exception:
            email = None
    else:
        email = request.POST.get("email")
    return JsonResponse({"status": "registered", "email": email})


def profile(request):
    if request.method == "GET":
        return JsonResponse({"name": request.headers.get("x-user-id"), "is_admin": False})
    if request.method == "POST":
        return JsonResponse({"name": request.headers.get("x-user-id"), "status": "updated"})
    return JsonResponse({"error": "method not allowed"}, status=405)


def get_orders(_request):
    return JsonResponse({
        "orders": [
            {"id": "ord-123", "item": "Laptop", "amount": 1200},
            {"id": "ord-124", "item": "Mouse", "amount": 45},
        ]
    })


def get_order_detail(_request, order_id):
    return JsonResponse({"id": order_id, "item": "Laptop", "amount": 1200, "status": "shipped"})


def echo_query(request):
    return JsonResponse({k: v for k, v in request.GET.items()})


def echo_body(request):
    try:
        data = json.loads(request.body.decode("utf-8"))
        return JsonResponse(data if isinstance(data, dict) else {})
    except Exception:
        return JsonResponse({})


def echo_form(request):
    return JsonResponse({k: v for k, v in request.POST.items()})


def echo_multipart(request):
    return JsonResponse({k: v for k, v in request.POST.items()})


def serve_index(_request):
    with open(os.path.join(FRONTEND_DIR, "index.html"), "rb") as f:
        return HttpResponse(f.read(), content_type="text/html")


def serve_static(_request, file_path):
    path = os.path.join(FRONTEND_DIR, file_path)
    if not os.path.isfile(path):
        return HttpResponse("not found", status=404)
    ctype = "application/octet-stream"
    if file_path.endswith(".css"):
        ctype = "text/css"
    elif file_path.endswith(".js"):
        ctype = "application/javascript"
    with open(path, "rb") as f:
        return HttpResponse(f.read(), content_type=ctype)


urlpatterns = [
    path("auth/register", register),
    path("api/v2/profile", profile),
    path("api/v2/orders", get_orders),
    path("api/v2/orders/<str:order_id>", get_order_detail),
    path("api/v2/echo/query", echo_query),
    path("api/v2/echo/body", echo_body),
    path("api/v2/echo/form", echo_form),
    path("api/v2/echo/multipart", echo_multipart),
    path("", serve_index),
    re_path(r"^(?P<file_path>.+)$", serve_static),
]


if not settings.configured:
    settings.configure(
        DEBUG=True,
        SECRET_KEY="trappsec-django-example",
        ROOT_URLCONF=__name__,
        ALLOWED_HOSTS=["*"],
        MIDDLEWARE=[],
        INSTALLED_APPS=[
            "django.contrib.contenttypes",
            "django.contrib.auth",
        ],
    )

import django
django.setup()

app = get_wsgi_application()
ts = trappsec.Sentry(app, service="DjangoApp", environment="Development")

ts.default_responses["unauthenticated"] = {
    "status_code": 401,
    "response_body": {"error": "authentication required"},
    "mime_type": "application/json"
}

ts.identify_user(lambda r: {
    "user": r.headers.get("x-user-id"),
    "role": r.headers.get("x-user-role")
})
ts.override_source_ip(lambda r: r.headers.get("x-real-ip", r.META.get("REMOTE_ADDR", "0.0.0.0")))

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

ts.watch("/api/v2/orders/<str:order_id>") \
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


def setup_opentelemetry():
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
    from opentelemetry.instrumentation.django import DjangoInstrumentor

    provider = TracerProvider()
    provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter(formatter=lambda span: span.to_json(indent=None) + "\n")))
    trace.set_tracer_provider(provider)

    DjangoInstrumentor().instrument()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--otel", action="store_true")
    parser.add_argument("--webhook", type=str)
    args = parser.parse_args()

    if args.otel:
        setup_opentelemetry()
        ts.add_otel()

    if args.webhook:
        ts.add_webhook(url=args.webhook, alerts_only=False)

    print("Starting server on http://127.0.0.1:8000")
    httpd = make_server("127.0.0.1", 8000, app)
    httpd.serve_forever()

