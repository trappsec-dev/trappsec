import pytest
import uuid
import time

def get_unique_ua():
    return f"trappsec-e2e-{uuid.uuid4()}"

def wait_for_alert(alert_server, user_agent, timeout=2):
    start = time.time()
    while time.time() - start < timeout:
        alerts = alert_server.get_alerts_for_agent(user_agent)
        if alerts:
            return alerts
        time.sleep(0.1)
    return []

def test_trap_deployment_metrics(api, base_url, alert_server):
    """Verify Trap: /deployment/metrics"""
    ua = get_unique_ua()
    r = api.get(f"{base_url}/deployment/metrics", headers={"x-user-id": "alice", "User-Agent": ua})
    assert r.status_code == 200
    data = r.json()
    assert "cpu" in data
    assert "memory" in data

    alerts = wait_for_alert(alert_server, ua)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["type"] == "alert"
    assert alert["user"] == "alice"
    assert alert["event"] == "trappsec.trap_hit"
    assert alert["intent"] == "Reconnaissance"
    assert alert["path"] == "/deployment/metrics"
    assert alert["method"] == "GET"
    assert alert["user_agent"] == ua

    ua = get_unique_ua()
    r = api.get(f"{base_url}/deployment/metrics", headers={"User-Agent": ua})
    assert r.status_code == 401
    assert r.json().get("error") == "authentication required"

    alerts = wait_for_alert(alert_server, ua)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["type"] == "signal"
    assert alert["event"] == "trappsec.trap_hit"
    assert alert["intent"] == "Reconnaissance"

def test_trap_deployment_config(api, base_url, alert_server):
    """Verify Trap: /deployment/config"""
    ua = get_unique_ua()
    r = api.get(f"{base_url}/deployment/config", headers={"x-user-id": "alice", "User-Agent": ua})
    assert r.status_code == 200
    assert r.json() == {"region": "us-east-1", "deployment_type": "production"}

    alerts = wait_for_alert(alert_server, ua)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["type"] == "alert"
    assert alert["event"] == "trappsec.trap_hit"
    assert alert["intent"] == "Reconnaissance"

    ua = get_unique_ua()
    r = api.get(f"{base_url}/deployment/config", headers={"User-Agent": ua})
    assert r.status_code == 401
    assert r.json().get("error") == "authentication required"

    alerts = wait_for_alert(alert_server, ua)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["type"] == "signal"
    assert alert["event"] == "trappsec.trap_hit"

def test_trap_legacy_orders(api, base_url, alert_server):
    """Verify Trap: /api/v1/orders (Template)"""
    ua = get_unique_ua()
    r = api.get(f"{base_url}/api/v1/orders", headers={"x-user-id": "alice", "User-Agent": ua})
    assert r.status_code == 410
    assert r.json().get("error") == "Gone"

    alerts = wait_for_alert(alert_server, ua)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["type"] == "alert"
    assert alert["event"] == "trappsec.trap_hit"
    assert alert["intent"] == "Legacy API Probing"

    ua = get_unique_ua()
    r = api.get(f"{base_url}/api/v1/orders", headers={"User-Agent": ua})
    assert r.status_code == 401
    assert r.json().get("error") == "authentication required"

    alerts = wait_for_alert(alert_server, ua)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["type"] == "signal"
    assert alert["event"] == "trappsec.trap_hit"

def test_trap_legacy_profile(api, base_url, alert_server):
    """Verify Trap: /api/v1/profile (Template)"""
    ua = get_unique_ua()
    r = api.get(f"{base_url}/api/v1/profile", headers={"x-user-id": "alice", "User-Agent": ua})
    assert r.status_code == 410
    assert r.json().get("error") == "Gone"

    alerts = wait_for_alert(alert_server, ua)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["type"] == "alert"
    assert alert["event"] == "trappsec.trap_hit"
    assert alert["intent"] == "Legacy API Probing"

    ua = get_unique_ua()
    r = api.get(f"{base_url}/api/v1/profile", headers={"User-Agent": ua})
    assert r.status_code == 401
    assert r.json().get("error") == "authentication required"

    alerts = wait_for_alert(alert_server, ua)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["type"] == "signal"
    assert alert["event"] == "trappsec.trap_hit"

def test_app_routes_happy_path(api, base_url, alert_server):
    """Verify Real Application Routes (Should NOT trigger alerts)"""
    ua = get_unique_ua()
    r = api.post(f"{base_url}/auth/register", data={"email": "legit@example.com"}, headers={"User-Agent": ua})
    assert r.status_code == 200
    assert r.json().get("status") == "registered"
    assert len(wait_for_alert(alert_server, ua, timeout=0.5)) == 0

    ua = get_unique_ua()
    r = api.get(f"{base_url}/api/v2/profile", headers={"x-user-id": "alice", "User-Agent": ua})
    assert r.status_code == 200
    assert r.json().get("name") == "alice"
    assert r.json().get("is_admin") is False
    assert len(wait_for_alert(alert_server, ua, timeout=0.5)) == 0

    ua = get_unique_ua()
    r = api.post(f"{base_url}/api/v2/profile", headers={"x-user-id": "alice", "User-Agent": ua})
    assert r.status_code == 200
    assert r.json().get("status") == "updated"
    assert len(wait_for_alert(alert_server, ua, timeout=0.5)) == 0

    ua = get_unique_ua()
    r = api.get(f"{base_url}/api/v2/orders", headers={"User-Agent": ua})
    assert r.status_code == 200
    assert "orders" in r.json()
    assert len(r.json()["orders"]) > 0
    assert len(wait_for_alert(alert_server, ua, timeout=0.5)) == 0

def test_watch_registration(api, base_url, alert_server):
    """Verify Watch: /auth/register"""
    endpoint = f"{base_url}/auth/register"
    
    ua = get_unique_ua()
    r = api.post(endpoint, data={
        "email": "hacker@example.com", 
        "password": "pass", 
        "role": "admin"
    }, headers={"User-Agent": ua})
    assert r.status_code == 200
    assert r.json().get("status") == "registered"

    alerts = wait_for_alert(alert_server, ua)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["type"] == "signal"
    assert alert["event"] == "trappsec.watch_hit"
    
    assert len(alert["found_fields"]) == 1
    assert alert["found_fields"][0]["field"] == "role"
    assert alert["found_fields"][0]["intent"] == "Privilege Escalation (role)"

def test_watch_profile_update(api, base_url, alert_server):
    """Verify Watch: /api/v2/profile"""
    endpoint = f"{base_url}/api/v2/profile"
    
    ua = get_unique_ua()
    r = api.post(endpoint, json={"is_admin": True}, headers={"x-user-id": "hacker", "User-Agent": ua})
    assert r.status_code == 200
    assert r.json().get("status") == "updated"

    alerts = wait_for_alert(alert_server, ua)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["type"] == "alert"
    assert alert["event"] == "trappsec.watch_hit"
    
    assert len(alert["found_fields"]) == 1
    assert alert["found_fields"][0]["field"] == "is_admin"
    assert alert["found_fields"][0]["intent"] == "Privilege Escalation"
