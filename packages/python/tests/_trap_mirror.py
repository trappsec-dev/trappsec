"""Shared trap configuration for the integration tests of response headers,
the per-request response hook and the callback fallback (R16, R23).

Each framework test serves the configured app and passes ``check_mirror`` a
``get(path, headers) -> (status, headers, body_bytes)`` function.
"""
import json


def identify(r):
    user = r.headers.get("x-user")
    return {"user": user, "role": r.headers.get("x-role")} if user else None


def hook(request, ctx):
    assert request is not None
    if ctx["role"] == "owner":
        return {"status": 201, "body": {"id": 1}}
    if ctx["role"] == "ghost":
        return {"status": 404, "body": {"detail": "Not found."}}
    return None


def configure_mirror(sentry):
    sentry.identify_user(identify)
    sentry.default_unauthenticated_response(
        status=401, body={"detail": "Not authenticated"}, headers={"WWW-Authenticate": "Bearer"})
    sentry.default_response(status=403, body="forbidden", mime_type="text/plain", headers={"X-Default": "1"})
    sentry.trap("/api/v1/projects/export").respond(
        status=403, body={"detail": "Forbidden"}, mime_type="application/json", headers={"Allow": "GET, POST", "Vary": "Accept"},
    ).respond_with(hook)
    sentry.trap("/api/v1/broken").respond(status=200, body=lambda r: 1 / 0, headers={"X-Trap": "1"})


def check_mirror(get):
    def call(path, **headers):
        status, h, body = get(path, headers)
        return status, {k.lower(): v for k, v in dict(h).items()}, body

    status, h, body = call("/api/v1/projects/export")
    assert status == 401 and h["www-authenticate"] == "Bearer"
    assert json.loads(body) == {"detail": "Not authenticated"}

    status, h, body = call("/api/v1/projects/export", **{"x-user": "bob", "x-role": "member"})
    assert status == 403 and json.loads(body) == {"detail": "Forbidden"}
    assert h["allow"] == "GET, POST" and h["vary"] == "Accept" and "www-authenticate" not in h

    status, h, body = call("/api/v1/projects/export", **{"x-user": "bob", "x-role": "owner"})
    assert status == 201 and json.loads(body) == {"id": 1} and h["allow"] == "GET, POST"

    status, h, body = call("/api/v1/projects/export", **{"x-user": "bob", "x-role": "ghost"})
    assert status == 404 and json.loads(body) == {"detail": "Not found."}

    # A failing body callback sends the default response, never "{}".
    status, h, body = call("/api/v1/broken", **{"x-user": "bob", "x-role": "member"})
    assert (status, body) == (403, b"forbidden")
    assert h["content-type"].startswith("text/plain") and h["x-default"] == "1" and "x-trap" not in h
