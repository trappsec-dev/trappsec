import pytest

def pytest_addoption(parser):
    parser.addoption(
        "--url", 
        action="store", 
        default="http://localhost:8000", 
        help="Base URL of the application under test"
    )

@pytest.fixture
def base_url(request):
    return request.config.getoption("--url").rstrip("/")

@pytest.fixture
def api(base_url):
    import requests
    return requests.Session()
