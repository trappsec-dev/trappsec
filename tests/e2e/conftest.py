import pytest
import requests
import threading

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
    import requests
    with requests.Session() as session:
        yield session

from utils import AlertServer, AlertHandler

@pytest.fixture(scope="session")
def alert_server():
    server = AlertServer(('localhost', 5050), AlertHandler)
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()
    
    yield server
    
    server.shutdown()
