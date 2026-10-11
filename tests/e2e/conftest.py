import os
import threading

import pytest
import requests

from utils import AlertServer, AlertHandler, Alerts


def pytest_addoption(parser):
    parser.addoption(
        "--url",
        action="store",
        default="http://127.0.0.1:8000",
        help="Base URL of the application under test"
    )
    parser.addoption(
        "--webhook-port",
        action="store",
        type=int,
        default=5050,
        help="Port for the alert receiver the app sends webhooks to"
    )
    parser.addoption(
        "--webhook-secret",
        action="store",
        default=os.environ.get("TRAPPSEC_WEBHOOK_SECRET"),
        help="Verify every delivery's HMAC signature with this secret (default: $TRAPPSEC_WEBHOOK_SECRET)"
    )
    parser.addoption(
        "--check-alerts-only",
        action="store_true",
        default=False,
        help="The app also sends to <receiver>/alerts with alerts_only=True ($TRAPPSEC_ALERTS_WEBHOOK); check it"
    )
    parser.addoption(
        "--unsupported",
        action="store",
        default="",
        help="Comma-separated features the app under test does not support (e.g. multipart)"
    )


@pytest.fixture(scope="session")
def base_url(request):
    return request.config.getoption("--url").rstrip("/")


@pytest.fixture(scope="session")
def unsupported(request):
    return {x.strip() for x in request.config.getoption("--unsupported").split(",") if x.strip()}


@pytest.fixture(scope="session")
def api(base_url):
    with requests.Session() as session:
        yield session


@pytest.fixture(scope="session")
def alert_server(request):
    secret = request.config.getoption("--webhook-secret")
    server = AlertServer(("127.0.0.1", request.config.getoption("--webhook-port")), AlertHandler, secret=secret)
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()

    yield server

    server.shutdown()
    server.server_close()
    assert not server.problems, f"bad webhook deliveries: {server.problems}"


@pytest.fixture
def alerts(alert_server, api, base_url, request):
    return Alerts(alert_server, api, base_url, check_alerts_only=request.config.getoption("--check-alerts-only"))
