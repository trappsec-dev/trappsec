import pytest

from utils import unique_ua

ALICE = {"x-user-id": "alice"}


def headers(ua, **extra):
    return {"User-Agent": ua, **extra}


# ---------------------------------------------------------------------------
# Traps: authenticated requests get the decoy response and an alert,
# unauthenticated ones get the 401 template and a signal.
# ---------------------------------------------------------------------------

TRAPS = [
    ("/deployment/metrics", "GET", 200, "Reconnaissance"),
    ("/deployment/config", "GET", 200, "Reconnaissance"),
    ("/api/v1/orders", "GET", 410, "Legacy API Probing"),
    ("/api/v1/orders", "POST", 410, "Legacy API Probing"),
    ("/api/v1/profile", "GET", 410, "Legacy API Probing"),
]


@pytest.mark.parametrize("path,method,status,intent", TRAPS, ids=[f"{m} {p}" for p, m, _, _ in TRAPS])
def test_trap_authenticated_alert(api, base_url, alerts, path, method, status, intent):
    ua = unique_ua()
    r = api.request(method, f"{base_url}{path}", json={"item": "x"} if method == "POST" else None,
                    headers=headers(ua, **ALICE))
    assert r.status_code == status

    [alert] = alerts.expect(ua)
    assert alert["type"] == "alert"
    assert alert["user"] == "alice"
    assert alert["event"] == "trappsec.trap_hit"
    assert alert["intent"] == intent
    assert alert["path"] == path
    assert alert["method"] == method


@pytest.mark.parametrize("path,method,status,intent", TRAPS, ids=[f"{m} {p}" for p, m, _, _ in TRAPS])
def test_trap_unauthenticated_signal(api, base_url, alerts, path, method, status, intent):
    ua = unique_ua()
    r = api.request(method, f"{base_url}{path}", headers=headers(ua))
    assert r.status_code == 401
    assert r.json().get("error") == "authentication required"

    [alert] = alerts.expect(ua)
    assert alert["type"] == "signal"
    assert alert["user"] is None and alert["role"] is None
    assert alert["event"] == "trappsec.trap_hit"
    assert alert["intent"] == intent


def test_trap_static_and_dynamic_bodies(api, base_url, alerts):
    r = api.get(f"{base_url}/deployment/config", headers=headers(unique_ua(), **ALICE))
    assert r.json() == {"region": "us-east-1", "deployment_type": "production"}
    r = api.get(f"{base_url}/deployment/metrics", headers=headers(unique_ua(), **ALICE))
    assert {"cpu", "memory"} <= set(r.json())
    r = api.get(f"{base_url}/api/v1/orders", headers=headers(unique_ua(), **ALICE))
    assert r.json().get("error") == "Gone"


def test_role_is_reported(api, base_url, alerts):
    ua = unique_ua()
    api.get(f"{base_url}/deployment/config", headers=headers(ua, **ALICE, **{"x-user-role": "admin"}))
    [alert] = alerts.expect(ua)
    assert alert["role"] == "admin"


# ---------------------------------------------------------------------------
# Real application routes never alert.
# ---------------------------------------------------------------------------

def test_app_routes_happy_path(api, base_url, alerts):
    ua = unique_ua()
    r = api.post(f"{base_url}/auth/register", data={"email": "legit@example.com"}, headers=headers(ua))
    assert r.status_code == 200
    assert r.json().get("status") == "registered"

    r = api.get(f"{base_url}/api/v2/profile", headers=headers(ua, **ALICE))
    assert r.status_code == 200
    assert r.json().get("name") == "alice"
    assert r.json().get("is_admin") is False

    r = api.post(f"{base_url}/api/v2/profile", headers=headers(ua, **ALICE))
    assert r.status_code == 200
    assert r.json().get("status") == "updated"

    r = api.get(f"{base_url}/api/v2/orders", headers=headers(ua))
    assert r.status_code == 200
    assert len(r.json()["orders"]) > 0

    r = api.get(f"{base_url}/api/v2/orders/ord-999", headers=headers(ua))
    assert r.status_code == 200
    assert r.json().get("id") == "ord-999"

    alerts.expect_none(ua)


# ---------------------------------------------------------------------------
# Watches: honey fields alert and are stripped; benign requests do not alert.
# ---------------------------------------------------------------------------

def test_watch_registration_role_signal(api, base_url, alerts):
    ua = unique_ua()
    r = api.post(f"{base_url}/auth/register",
                 data={"email": "hacker@example.com", "password": "pass", "role": "admin"},
                 headers=headers(ua))
    assert r.status_code == 200
    assert r.json().get("status") == "registered"

    [alert] = alerts.expect(ua)
    assert alert["type"] == "signal"
    assert alert["event"] == "trappsec.watch_hit"
    assert alert["found_fields"] == [
        {"type": "body", "field": "role", "value": "admin", "intent": "Privilege Escalation (role)"}]


def test_watch_registration_credits(api, base_url, alerts):
    ua = unique_ua()
    r = api.post(f"{base_url}/auth/register", data={"email": "hacker@example.com", "credits": "9999"},
                 headers=headers(ua))
    assert r.status_code == 200

    [alert] = alerts.expect(ua)
    assert alert["found_fields"] == [
        {"type": "body", "field": "credits", "value": "9999", "intent": "Credit Manipulation"}]


def test_watch_registration_multi_field(api, base_url, alerts):
    ua = unique_ua()
    r = api.post(f"{base_url}/auth/register",
                 data={"email": "hacker@example.com", "role": "admin", "credits": "9999"}, headers=headers(ua))
    assert r.status_code == 200

    [alert] = alerts.expect(ua)
    assert {f["field"] for f in alert["found_fields"]} == {"role", "credits"}


def test_watch_registration_defaults_do_not_alert(api, base_url, alerts):
    ua = unique_ua()
    r = api.post(f"{base_url}/auth/register",
                 data={"email": "friend@example.com", "password": "pw", "role": "user", "credits": "0"},
                 headers=headers(ua))
    assert r.status_code == 200
    alerts.expect_none(ua)


def test_watch_profile_update_alert(api, base_url, alerts):
    ua = unique_ua()
    r = api.post(f"{base_url}/api/v2/profile", json={"is_admin": True}, headers=headers(ua, **{"x-user-id": "hacker"}))
    assert r.status_code == 200
    assert r.json().get("status") == "updated"

    [alert] = alerts.expect(ua)
    assert alert["type"] == "alert"
    assert alert["user"] == "hacker"
    assert alert["event"] == "trappsec.watch_hit"
    assert alert["found_fields"] == [
        {"type": "body", "field": "is_admin", "value": True, "intent": "Privilege Escalation"}]


def test_watch_query_on_parameterized_route(api, base_url, alerts):
    """R1: watches match the route pattern, not the raw URL."""
    ua = unique_ua()
    r = api.get(f"{base_url}/api/v2/orders/ord-123", params={"discount_code": "BLACKHAT"},
                headers=headers(ua, **ALICE))
    assert r.status_code == 200
    assert r.json().get("id") == "ord-123"

    [alert] = alerts.expect(ua)
    assert alert["type"] == "alert"
    assert alert["path"].startswith("/api/v2/orders/ord-123")
    assert alert["found_fields"] == [
        {"type": "query", "field": "discount_code", "value": "BLACKHAT", "intent": "Coupon Tampering"}]


def test_watch_query_on_parameterized_route_no_trigger(api, base_url, alerts):
    ua = unique_ua()
    for params in ({}, {"discount_code": "NONE"}):
        r = api.get(f"{base_url}/api/v2/orders/ord-123", params=params, headers=headers(ua, **ALICE))
        assert r.status_code == 200
    alerts.expect_none(ua)


# ---------------------------------------------------------------------------
# Field stripping (R4): honey fields never reach the handler, safe fields do.
# ---------------------------------------------------------------------------

def test_strip_query_field_presence(api, base_url, alerts):
    ua = unique_ua()
    r = api.get(f"{base_url}/api/v2/echo/query", params={"honey_q": "attack"}, headers=headers(ua))
    assert r.status_code == 200
    assert "honey_q" not in r.json()

    [alert] = alerts.expect(ua)
    assert alert["found_fields"] == [
        {"type": "query", "field": "honey_q", "value": "attack", "intent": "Query Field Test"}]


def test_strip_query_field_default_match(api, base_url, alerts):
    ua = unique_ua()
    r = api.get(f"{base_url}/api/v2/echo/query", params={"role_q": "user"}, headers=headers(ua))
    assert r.status_code == 200
    assert "role_q" not in r.json()
    alerts.expect_none(ua)


def test_strip_query_field_default_mismatch(api, base_url, alerts):
    ua = unique_ua()
    r = api.get(f"{base_url}/api/v2/echo/query", params={"role_q": "admin"}, headers=headers(ua))
    assert r.status_code == 200
    assert "role_q" not in r.json()

    [alert] = alerts.expect(ua)
    assert alert["found_fields"][0]["field"] == "role_q"


def test_strip_query_duplicate_keys(api, base_url, alerts):
    """R18: repeating a watched key cannot smuggle a value past the default."""
    ua = unique_ua()
    r = api.get(f"{base_url}/api/v2/echo/query?role_q=user&role_q=admin&safe_param=hello", headers=headers(ua))
    assert r.status_code == 200
    data = r.json()
    assert "role_q" not in data
    assert data.get("safe_param") == "hello"

    [alert] = alerts.expect(ua)
    assert alert["found_fields"][0]["field"] == "role_q"


def test_strip_mixed_query_honey_stripped_safe_retained(api, base_url, alerts):
    ua = unique_ua()
    r = api.get(f"{base_url}/api/v2/echo/query", params={"honey_q": "attack", "safe_param": "hello"},
                headers=headers(ua))
    assert r.status_code == 200
    data = r.json()
    assert "honey_q" not in data
    assert data.get("safe_param") == "hello"
    alerts.expect(ua)


def test_strip_query_non_honey_retained(api, base_url, alerts):
    ua = unique_ua()
    r = api.get(f"{base_url}/api/v2/echo/query", params={"safe_param": "hello"}, headers=headers(ua))
    assert r.status_code == 200
    assert r.json().get("safe_param") == "hello"
    alerts.expect_none(ua)


def test_strip_json_body_field_presence(api, base_url, alerts):
    ua = unique_ua()
    r = api.post(f"{base_url}/api/v2/echo/body", json={"honey_b": "attack"}, headers=headers(ua))
    assert r.status_code == 200
    assert "honey_b" not in r.json()

    [alert] = alerts.expect(ua)
    assert alert["found_fields"] == [
        {"type": "body", "field": "honey_b", "value": "attack", "intent": "Body Field Test"}]


def test_strip_json_body_field_default_match(api, base_url, alerts):
    ua = unique_ua()
    r = api.post(f"{base_url}/api/v2/echo/body", json={"role_b": "user"}, headers=headers(ua))
    assert r.status_code == 200
    assert "role_b" not in r.json()
    alerts.expect_none(ua)


def test_strip_json_body_field_default_mismatch(api, base_url, alerts):
    ua = unique_ua()
    r = api.post(f"{base_url}/api/v2/echo/body", json={"role_b": "admin"}, headers=headers(ua))
    assert r.status_code == 200
    assert "role_b" not in r.json()

    [alert] = alerts.expect(ua)
    assert alert["found_fields"][0]["field"] == "role_b"


def test_strip_json_body_non_honey_retained(api, base_url, alerts):
    ua = unique_ua()
    r = api.post(f"{base_url}/api/v2/echo/body", json={"safe_field": "hello", "n": 1.5, "nested": {"honey_b": 1}},
                 headers=headers(ua))
    assert r.status_code == 200
    assert r.json() == {"safe_field": "hello", "n": 1.5, "nested": {"honey_b": 1}}
    alerts.expect_none(ua)


def test_strip_multiple_honey_fields_same_request(api, base_url, alerts):
    ua = unique_ua()
    r = api.post(f"{base_url}/api/v2/echo/body", json={"honey_b": "attack", "role_b": "admin", "username": "alice"},
                 headers=headers(ua))
    assert r.status_code == 200
    assert r.json() == {"username": "alice"}

    [alert] = alerts.expect(ua)
    assert {f["field"] for f in alert["found_fields"]} == {"honey_b", "role_b"}


def test_strip_json_top_level_array(api, base_url, alerts):
    ua = unique_ua()
    r = api.post(f"{base_url}/api/v2/echo/body", json=[{"honey_b": "x", "id": 1}, {"id": 2}], headers=headers(ua))
    assert r.status_code == 200
    body = r.json()
    if isinstance(body, list):  # handlers that echo arrays: the honey key is gone from every element
        assert body == [{"id": 1}, {"id": 2}]
    [alert] = alerts.expect(ua)
    assert alert["found_fields"][0]["field"] == "honey_b"


def test_strip_form_field(api, base_url, alerts):
    ua = unique_ua()
    r = api.post(f"{base_url}/api/v2/echo/form", data={"honey_f": "attack"}, headers=headers(ua))
    assert r.status_code == 200
    assert "honey_f" not in r.json()

    [alert] = alerts.expect(ua)
    assert alert["found_fields"] == [
        {"type": "body", "field": "honey_f", "value": "attack", "intent": "Form Field Test"}]


def test_strip_mixed_form_honey_stripped_safe_retained(api, base_url, alerts):
    ua = unique_ua()
    r = api.post(f"{base_url}/api/v2/echo/form", data={"honey_f": "attack", "email": "alice@example.com"},
                 headers=headers(ua))
    assert r.status_code == 200
    data = r.json()
    assert "honey_f" not in data
    assert data.get("email") == "alice@example.com"
    alerts.expect(ua)


@pytest.fixture
def multipart(api, base_url, unsupported):
    """POST multipart to the echo route; skips when the case declares multipart unsupported."""
    def post(files, ua):
        r = api.post(f"{base_url}/api/v2/echo/multipart", files=files, headers=headers(ua))
        assert r.status_code == 200
        data = r.json()
        if "multipart" in unsupported:
            assert data.get("supported") is False, "declared unsupported but the app echoes multipart"
            pytest.skip("multipart echo not supported by this app")
        assert data.get("supported") is not False, "app says multipart is unsupported; pass --unsupported=multipart"
        return data
    return post


def test_strip_multipart_field(multipart, alerts):
    ua = unique_ua()
    data = multipart({"honey_m": (None, "attack")}, ua)
    assert "honey_m" not in data

    [alert] = alerts.expect(ua)
    assert alert["found_fields"][0]["field"] == "honey_m"


def test_strip_mixed_multipart_honey_stripped_safe_retained(multipart, alerts):
    ua = unique_ua()
    data = multipart({"honey_m": (None, "attack"), "filename": (None, "report")}, ua)
    assert "honey_m" not in data
    assert data.get("filename") == "report"

    [alert] = alerts.expect(ua)
    assert alert["found_fields"][0]["field"] == "honey_m"


def test_forwarded_for_is_not_trusted_by_default(api, base_url, alerts):
    """R21: without proxy configuration a client cannot choose the recorded IP."""
    ua = unique_ua()
    spoofed = "203.0.113.77"
    api.get(f"{base_url}/deployment/config", headers=headers(ua, **{"X-Forwarded-For": spoofed, "Forwarded": f"for={spoofed}"}))
    [alert] = alerts.expect(ua)
    assert spoofed not in alert["ip"]


@pytest.mark.parametrize("method", ["DELETE", "PUT", "OPTIONS"])
def test_wrong_method_on_trap_looks_like_a_real_route(api, base_url, alerts, method):
    """R14: a trap must not be told apart from a real GET-only route by how it rejects other methods."""
    ua = unique_ua()
    real = api.request(method, f"{base_url}/api/v2/orders", headers=headers(ua))
    trap = api.request(method, f"{base_url}/deployment/config", headers=headers(ua))
    allow = lambda r: sorted(m.strip().upper() for m in r.headers.get("Allow", "").split(",") if m.strip())  # noqa: E731
    assert (trap.status_code, allow(trap)) == (real.status_code, allow(real))
    alerts.expect_none(ua)


def test_trailing_slash_on_trap_looks_like_a_real_route(api, base_url, alerts):
    """R14: a trailing slash is handled the same way (redirect, 404, or same answer) on a trap and a real route."""
    ua = unique_ua()

    def outcome(path):
        plain = api.get(f"{base_url}{path}", headers=headers(ua, **ALICE), allow_redirects=False)
        slash = api.get(f"{base_url}{path}/", headers=headers(ua, **ALICE), allow_redirects=False)
        if slash.is_redirect:
            return "redirect"
        return "same" if slash.status_code == plain.status_code else slash.status_code

    # /api/v2/profile has no child routes (unlike /api/v2/orders/{id}), so its slash variant is the same route
    assert outcome("/deployment/config") == outcome("/api/v2/profile")


def test_head_on_trap_looks_like_a_real_route(api, base_url, alerts):
    """R14: HEAD relates to GET the same way on a trap as on a real route."""
    ua = unique_ua()

    def head_like_get(path):
        get = api.get(f"{base_url}{path}", headers=headers(ua, **ALICE))
        head = api.head(f"{base_url}{path}", headers=headers(ua, **ALICE))
        return head.status_code == get.status_code

    assert head_like_get("/deployment/config") == head_like_get("/api/v2/profile")
