def test_trap_deployment_metrics(api, base_url):
    """Verify Trap: /deployment/metrics"""
    # Verify dynamic response
    r = api.get(f"{base_url}/deployment/metrics", headers={"x-user-id": "alice"})
    assert r.status_code == 200
    data = r.json()
    assert "cpu" in data
    assert "memory" in data

    # verify unauthenticated response
    r = api.get(f"{base_url}/deployment/metrics")
    assert r.status_code == 401
    assert r.json().get("error") == "authentication required"

def test_trap_deployment_config(api, base_url):
    """Verify Trap: /deployment/config"""
    # Verify static response
    r = api.get(f"{base_url}/deployment/config", headers={"x-user-id": "alice"})
    assert r.status_code == 200
    assert r.json() == {"region": "us-east-1", "deployment_type": "production"}

    # verify unauthenticated response
    r = api.get(f"{base_url}/deployment/config")
    assert r.status_code == 401
    assert r.json().get("error") == "authentication required"

def test_trap_legacy_orders(api, base_url):
    """Verify Trap: /api/v1/orders (Template)"""
    r = api.get(f"{base_url}/api/v1/orders", headers={"x-user-id": "alice"})
    assert r.status_code == 410
    assert r.json().get("error") == "Gone"

    # verify unauthenticated response
    r = api.get(f"{base_url}/api/v1/orders")
    assert r.status_code == 401
    assert r.json().get("error") == "authentication required"

def test_trap_legacy_profile(api, base_url):
    """Verify Trap: /api/v1/profile (Template)"""
    r = api.get(f"{base_url}/api/v1/profile", headers={"x-user-id": "alice"})
    assert r.status_code == 410
    assert r.json().get("error") == "Gone"

    # verify unauthenticated response
    r = api.get(f"{base_url}/api/v1/profile")
    assert r.status_code == 401
    assert r.json().get("error") == "authentication required"

def test_app_routes_happy_path(api, base_url):
    """Verify Real Application Routes"""
    # 1. Register
    r = api.post(f"{base_url}/auth/register", data={"email": "legit@example.com"})
    assert r.status_code == 200
    assert r.json().get("status") == "registered"

    # 2. Get Profile
    r = api.get(f"{base_url}/api/v2/profile", headers={"x-user-id": "alice"})
    assert r.status_code == 200
    assert r.json().get("name") == "alice"
    assert r.json().get("is_admin") is False

    # 3. Update Profile
    r = api.post(f"{base_url}/api/v2/profile", headers={"x-user-id": "alice"})
    assert r.status_code == 200
    assert r.json().get("status") == "updated"

    # 4. List Users
    r = api.get(f"{base_url}/api/v2/orders")
    assert r.status_code == 200
    assert "orders" in r.json()
    assert len(r.json()["orders"]) > 0

def test_watch_registration(api, base_url):
    """Verify Watch: /auth/register"""
    endpoint = f"{base_url}/auth/register"
    
    # Suspicious Request (Honey Field)
    # Should still succeed but trigger alert internally
    r = api.post(endpoint, data={
        "email": "hacker@example.com", 
        "password": "pass", 
        "is_admin": "true"
    })
    assert r.status_code == 200
    assert r.json().get("status") == "registered"

def test_watch_profile_update(api, base_url):
    """Verify Watch: /api/v2/profile"""
    endpoint = f"{base_url}/api/v2/profile"
    
    # Suspicious Request (Honey Field is_admin)
    r = api.post(endpoint, json={"is_admin": True}, headers={"x-user-id": "hacker"})
    assert r.status_code == 200
    assert r.json().get("status") == "updated"
