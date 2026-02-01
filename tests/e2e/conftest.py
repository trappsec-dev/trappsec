import pytest
import requests

def pytest_addoption(parser):
    parser.addoption(
        "--url", 
        action="store", 
        default="http://localhost:8000", 
        help="Base URL of the application under test"
    )

@pytest.fixture(scope="session")
def base_url(request):
    return request.config.getoption("--url").rstrip("/")

@pytest.fixture(scope="session")
def api(base_url):
    return requests.Session()
