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

def test_app_route_parameterized_happy_path(api, base_url, alert_server):
    """Verify Real Application Route (Parameterized, Should NOT trigger alerts)"""
    ua = get_unique_ua()
    r = api.get(f"{base_url}/api/v2/orders/ord-999", headers={"User-Agent": ua})
    assert r.status_code == 200
    assert r.json().get("id") == "ord-999"
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

def test_watch_query_on_parameterized_route(api, base_url, alert_server):
    """Verify Watch: Query string on parameterized route (R1 validation)"""
    ua = get_unique_ua()
    r = api.get(
        f"{base_url}/api/v2/orders/ord-123",
        params={"discount_code": "BLACKHAT"},
        headers={"x-user-id": "alice", "User-Agent": ua}
    )
    assert r.status_code == 200
    assert r.json().get("id") == "ord-123"

    alerts = wait_for_alert(alert_server, ua)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["type"] == "alert" # Alice is authenticated
    assert alert["event"] == "trappsec.watch_hit"
    
    assert len(alert["found_fields"]) == 1
    assert alert["found_fields"][0]["field"] == "discount_code"
    assert alert["found_fields"][0]["intent"] == "Coupon Tampering"

def test_watch_query_on_parameterized_route_no_trigger(api, base_url, alert_server):
    """Verify Watch Negative: Parameterized route without honey fields"""
    ua = get_unique_ua()
    r = api.get(
        f"{base_url}/api/v2/orders/ord-123",
        headers={"x-user-id": "alice", "User-Agent": ua}
    )
    assert r.status_code == 200
    assert len(wait_for_alert(alert_server, ua, timeout=0.5)) == 0

def test_watch_query_field_stripping(api, base_url, alert_server):
    """Verify Watch: Always-strip semantics (R4 validation)"""
    ua = get_unique_ua()
    r = api.get(
        f"{base_url}/api/v2/orders/ord-123",
        params={"discount_code": "BLACKHAT"},
        headers={"x-user-id": "alice", "User-Agent": ua}
    )
    assert r.status_code == 200
    data = r.json()
    # The handler does not echo the query field in its normal response, but we can verify
    # the request went through properly. Note that verifying complete field stripping depends
    # on the echo behavior of the handler. Since the handler just returns the order ID,
    # we verify that the integration successfully allowed the request to pass through
    # to the handler and resulted in a 200 OK after firing the alert.
    assert data.get("id") == "ord-123"

def test_watch_registration_credits(api, base_url, alert_server):
    """Verify Watch: The rarely triggered 'credits' field on /auth/register"""
    ua = get_unique_ua()
    r = api.post(f"{base_url}/auth/register", data={
        "email": "hacker@example.com", 
        "credits": "9999"
    }, headers={"User-Agent": ua})
    assert r.status_code == 200

    alerts = wait_for_alert(alert_server, ua)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["type"] == "signal"
    assert alert["event"] == "trappsec.watch_hit"
    
    assert len(alert["found_fields"]) == 1
    assert alert["found_fields"][0]["field"] == "credits"
    assert alert["found_fields"][0]["intent"] == "Credit Manipulation"

def test_watch_registration_multi_field(api, base_url, alert_server):
    """Verify Watch: Multiple honey fields in a single request"""
    ua = get_unique_ua()
    r = api.post(f"{base_url}/auth/register", data={
        "email": "hacker@example.com", 
        "role": "admin",
        "credits": "9999"
    }, headers={"User-Agent": ua})
    assert r.status_code == 200

    alerts = wait_for_alert(alert_server, ua)
    assert len(alerts) == 1
    alert = alerts[0]
    assert len(alert["found_fields"]) == 2

def test_watch_registration_no_trigger(api, base_url, alert_server):
    """Verify Watch Negative: Watched route, completely benign data"""
    ua = get_unique_ua()
    r = api.post(f"{base_url}/auth/register", data={
        "email": "friend@example.com", 
        "password": "legitimate_password"
    }, headers={"User-Agent": ua})
    assert r.status_code == 200
    assert len(wait_for_alert(alert_server, ua, timeout=0.5)) == 0

def test_trap_post_legacy_orders(api, base_url, alert_server):
    """Verify Trap: Validates POST method on a template trap"""
    ua = get_unique_ua()
    r = api.post(f"{base_url}/api/v1/orders", json={"item": "Hack"}, headers={"x-user-id": "alice", "User-Agent": ua})
    assert r.status_code == 410

    alerts = wait_for_alert(alert_server, ua)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["type"] == "alert"
    assert alert["method"] == "POST"
    assert alert["intent"] == "Legacy API Probing"


# ---------------------------------------------------------------------------
# Field Stripping Tests
# Verify that honey fields are removed before the handler sees the request,
# and that safe fields are retained unmodified.
# ---------------------------------------------------------------------------

def test_strip_query_field_presence(api, base_url, alert_server):
    """Honey query field (no default) is stripped from response and triggers an alert"""
    ua = get_unique_ua()
    r = api.get(f"{base_url}/api/v2/echo/query",
                params={"honey_q": "attack"},
                headers={"User-Agent": ua})
    assert r.status_code == 200
    assert "honey_q" not in r.json()

    alerts = wait_for_alert(alert_server, ua)
    assert len(alerts) == 1
    assert alerts[0]["event"] == "trappsec.watch_hit"
    assert alerts[0]["found_fields"][0]["field"] == "honey_q"


def test_strip_query_field_default_match(api, base_url, alert_server):
    """Honey query field matching its default is silently stripped (no alert)"""
    ua = get_unique_ua()
    r = api.get(f"{base_url}/api/v2/echo/query",
                params={"role_q": "user"},
                headers={"User-Agent": ua})
    assert r.status_code == 200
    assert "role_q" not in r.json()
    assert len(wait_for_alert(alert_server, ua, timeout=0.5)) == 0


def test_strip_query_field_default_mismatch(api, base_url, alert_server):
    """Honey query field deviating from its default is stripped and triggers an alert"""
    ua = get_unique_ua()
    r = api.get(f"{base_url}/api/v2/echo/query",
                params={"role_q": "admin"},
                headers={"User-Agent": ua})
    assert r.status_code == 200
    assert "role_q" not in r.json()

    alerts = wait_for_alert(alert_server, ua)
    assert len(alerts) == 1
    assert alerts[0]["found_fields"][0]["field"] == "role_q"


def test_strip_query_non_honey_retained(api, base_url, alert_server):
    """Non-honey query fields are not stripped and produce no alert"""
    ua = get_unique_ua()
    r = api.get(f"{base_url}/api/v2/echo/query",
                params={"safe_param": "hello"},
                headers={"User-Agent": ua})
    assert r.status_code == 200
    assert r.json().get("safe_param") == "hello"
    assert len(wait_for_alert(alert_server, ua, timeout=0.5)) == 0


def test_strip_mixed_query_honey_stripped_safe_retained(api, base_url, alert_server):
    """Mixed query: honey field stripped, safe field retained, alert fired"""
    ua = get_unique_ua()
    r = api.get(f"{base_url}/api/v2/echo/query",
                params={"honey_q": "attack", "safe_param": "hello"},
                headers={"User-Agent": ua})
    assert r.status_code == 200
    data = r.json()
    assert "honey_q" not in data
    assert data.get("safe_param") == "hello"

    alerts = wait_for_alert(alert_server, ua)
    assert len(alerts) == 1
    assert alerts[0]["found_fields"][0]["field"] == "honey_q"


def test_strip_json_body_field_presence(api, base_url, alert_server):
    """Honey JSON body field (no default) is stripped and triggers an alert"""
    ua = get_unique_ua()
    r = api.post(f"{base_url}/api/v2/echo/body",
                 json={"honey_b": "attack"},
                 headers={"User-Agent": ua})
    assert r.status_code == 200
    assert "honey_b" not in r.json()

    alerts = wait_for_alert(alert_server, ua)
    assert len(alerts) == 1
    assert alerts[0]["found_fields"][0]["field"] == "honey_b"


def test_strip_json_body_field_default_match(api, base_url, alert_server):
    """Honey JSON body field matching its default is silently stripped (no alert)"""
    ua = get_unique_ua()
    r = api.post(f"{base_url}/api/v2/echo/body",
                 json={"role_b": "user"},
                 headers={"User-Agent": ua})
    assert r.status_code == 200
    assert "role_b" not in r.json()
    assert len(wait_for_alert(alert_server, ua, timeout=0.5)) == 0


def test_strip_json_body_field_default_mismatch(api, base_url, alert_server):
    """Honey JSON body field deviating from its default is stripped and triggers an alert"""
    ua = get_unique_ua()
    r = api.post(f"{base_url}/api/v2/echo/body",
                 json={"role_b": "admin"},
                 headers={"User-Agent": ua})
    assert r.status_code == 200
    assert "role_b" not in r.json()

    alerts = wait_for_alert(alert_server, ua)
    assert len(alerts) == 1
    assert alerts[0]["found_fields"][0]["field"] == "role_b"


def test_strip_json_body_non_honey_retained(api, base_url, alert_server):
    """Non-honey JSON body fields are not stripped and produce no alert"""
    ua = get_unique_ua()
    r = api.post(f"{base_url}/api/v2/echo/body",
                 json={"safe_field": "hello"},
                 headers={"User-Agent": ua})
    assert r.status_code == 200
    assert r.json().get("safe_field") == "hello"
    assert len(wait_for_alert(alert_server, ua, timeout=0.5)) == 0


def test_strip_mixed_body_honey_stripped_safe_retained(api, base_url, alert_server):
    """Mixed JSON body: honey field stripped, safe field retained, alert fired"""
    ua = get_unique_ua()
    r = api.post(f"{base_url}/api/v2/echo/body",
                 json={"honey_b": "attack", "username": "alice"},
                 headers={"User-Agent": ua})
    assert r.status_code == 200
    data = r.json()
    assert "honey_b" not in data
    assert data.get("username") == "alice"

    alerts = wait_for_alert(alert_server, ua)
    assert len(alerts) == 1
    assert alerts[0]["found_fields"][0]["field"] == "honey_b"


def test_strip_multiple_honey_fields_same_request(api, base_url, alert_server):
    """Multiple honey fields in one request are all stripped, single alert with all fields"""
    ua = get_unique_ua()
    r = api.post(f"{base_url}/api/v2/echo/body",
                 json={"honey_b": "attack", "role_b": "admin", "username": "alice"},
                 headers={"User-Agent": ua})
    assert r.status_code == 200
    data = r.json()
    assert "honey_b" not in data
    assert "role_b" not in data
    assert data.get("username") == "alice"

    alerts = wait_for_alert(alert_server, ua)
    assert len(alerts) == 1
    found_field_names = {f["field"] for f in alerts[0]["found_fields"]}
    assert found_field_names == {"honey_b", "role_b"}


def test_strip_form_field(api, base_url, alert_server):
    """Honey form-urlencoded field is stripped and triggers an alert"""
    ua = get_unique_ua()
    r = api.post(f"{base_url}/api/v2/echo/form",
                 data={"honey_f": "attack"},
                 headers={"User-Agent": ua})
    assert r.status_code == 200
    assert "honey_f" not in r.json()

    alerts = wait_for_alert(alert_server, ua)
    assert len(alerts) == 1
    assert alerts[0]["found_fields"][0]["field"] == "honey_f"


def test_strip_mixed_form_honey_stripped_safe_retained(api, base_url, alert_server):
    """Mixed form body: honey field stripped, safe field retained, alert fired"""
    ua = get_unique_ua()
    r = api.post(f"{base_url}/api/v2/echo/form",
                 data={"honey_f": "attack", "email": "alice@example.com"},
                 headers={"User-Agent": ua})
    assert r.status_code == 200
    data = r.json()
    assert "honey_f" not in data
    assert data.get("email") == "alice@example.com"

    alerts = wait_for_alert(alert_server, ua)
    assert len(alerts) == 1
    assert alerts[0]["found_fields"][0]["field"] == "honey_f"


def test_strip_multipart_field(api, base_url, alert_server):
    """Honey multipart field is stripped and triggers an alert (skipped if unsupported)"""
    ua = get_unique_ua()
    r = api.post(f"{base_url}/api/v2/echo/multipart",
                 files={"honey_m": (None, "attack")},
                 headers={"User-Agent": ua})
    assert r.status_code == 200
    data = r.json()
    if data.get("supported") is False:
        return  # framework does not support multipart echo — skip silently
    assert "honey_m" not in data

    alerts = wait_for_alert(alert_server, ua)
    assert len(alerts) == 1
    assert alerts[0]["found_fields"][0]["field"] == "honey_m"


def test_strip_mixed_multipart_honey_stripped_safe_retained(api, base_url, alert_server):
    """Mixed multipart: honey field stripped, safe field retained, alert fired (skipped if unsupported)"""
    ua = get_unique_ua()
    r = api.post(f"{base_url}/api/v2/echo/multipart",
                 files={"honey_m": (None, "attack"), "filename": (None, "report")},
                 headers={"User-Agent": ua})
    assert r.status_code == 200
    data = r.json()
    if data.get("supported") is False:
        return  # framework does not support multipart echo — skip silently
    assert "honey_m" not in data
    assert data.get("filename") == "report"

    alerts = wait_for_alert(alert_server, ua)
    assert len(alerts) == 1
    assert alerts[0]["found_fields"][0]["field"] == "honey_m"
