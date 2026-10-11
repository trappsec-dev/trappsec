import time
import json
import decimal
import math
import re
import typing
import socket
import logging
from collections.abc import Mapping, MutableMapping

from .handlers import LogHandler, _truncate_text
from .builders import TrapBuilder, WatchBuilder, NO_DEFAULT

_logger = logging.getLogger("trappsec")

_MAX_STR = 1024
_MAX_LIST = 20


def _is_number(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _es_number(v: float) -> str:
    """ECMAScript Number::toString(v): the float text JavaScript (and so Node) produces."""
    if math.isnan(v):
        return "NaN"
    if math.isinf(v):
        return "Infinity" if v > 0 else "-Infinity"
    if v == 0:
        return "0"
    sign = "-" if v < 0 else ""
    t = decimal.Decimal(repr(abs(v))).normalize().as_tuple()  # repr: shortest round-trip digits
    digits = "".join(str(d) for d in t.digits)
    k, n = len(digits), len(digits) + t.exponent  # value = 0.digits * 10**n
    if k <= n <= 21:
        text = digits + "0" * (n - k)
    elif 0 < n <= 21:
        text = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        text = "0." + "0" * -n + digits
    else:
        exp = ("+" if n - 1 >= 0 else "-") + str(abs(n - 1))
        text = (digits if k == 1 else digits[0] + "." + digits[1:]) + "e" + exp
    return sign + text


def _canonical(v) -> typing.Optional[str]:
    """Canonical string form of a bool/number, or None for anything else (R17)."""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return _es_number(v)
    return None


def values_match(actual, expected) -> bool:
    """Loose equality between a request value and a configured default (C3)."""
    try:
        # Containers compare element-wise with these same rules, never with ==
        # (which would let True match 1 inside a list).
        a_seq, e_seq = isinstance(actual, (list, tuple)), isinstance(expected, (list, tuple))
        if a_seq or e_seq:
            return (a_seq and e_seq and len(actual) == len(expected)
                    and all(values_match(a, e) for a, e in zip(actual, expected)))
        a_map, e_map = isinstance(actual, Mapping), isinstance(expected, Mapping)
        if a_map or e_map:
            return (a_map and e_map and actual.keys() == expected.keys()
                    and all(values_match(actual[k], expected[k]) for k in actual))
        a_bool, e_bool = isinstance(actual, bool), isinstance(expected, bool)
        if a_bool or e_bool:
            if a_bool and e_bool:
                return actual == expected
        elif actual == expected:
            return True
        elif _is_number(actual) and _is_number(expected):
            return actual == expected
        if isinstance(actual, str) and not isinstance(expected, str):
            c = _canonical(expected)
            return c is not None and actual == c
        if isinstance(expected, str) and not isinstance(actual, str):
            c = _canonical(actual)
            return c is not None and expected == c
    except Exception:
        return False
    return False


_PARAM_SEGMENT = re.compile(r"^(:\w+\??|\{[^}]*\}|<[^>]*>)$")


def _trap_path(p):
    if not isinstance(p, str) or not p:
        return None
    p = p.split("?", 1)[0].split("#", 1)[0]
    if not p.startswith("/"):
        p = "/" + p
    return p.rstrip("/") or "/"


def _trap_path_matches(pattern, path) -> bool:
    want = _trap_path(pattern)
    if not want:
        return False
    a, b = want.split("/"), path.split("/")
    return len(a) == len(b) and all(x == y or (y and _PARAM_SEGMENT.match(x)) for x, y in zip(a, b))


def safe_value(v):
    """Sanitize a request-derived value for inclusion in an event (C3)."""
    if v is None or isinstance(v, bool):
        return v
    if isinstance(v, int):
        return v
    if isinstance(v, float):
        return v if math.isfinite(v) else str(v)
    if isinstance(v, str):
        return _truncate_text(v, _MAX_STR)
    if isinstance(v, (list, tuple)):
        return [safe_value(x) for x in list(v)[:_MAX_LIST]]
    if isinstance(v, dict):
        # Compact, sorted, unescaped: the same text Node and Go produce (R19).
        opts = {"default": str, "separators": (",", ":"), "ensure_ascii": False}
        try:
            try:
                text = json.dumps(v, sort_keys=True, **opts)
            except TypeError:  # keys of mixed types cannot be sorted
                text = json.dumps(v, **opts)
            return _truncate_text(text, _MAX_STR)
        except Exception:
            return "<dict>"
    return "<%s>" % type(v).__name__


class IdentityContext:
    def __init__(self):
        self.ip = None
        self.auth = None

    def get_context(self, request_obj):
        u, r, ip = None, None, None

        if self.auth:
            try:
                auth_context = self.auth(request_obj)
                if isinstance(auth_context, dict):
                    u, r = auth_context.get("user"), auth_context.get("role")
            except Exception as e:
                _logger.error("identify_user callback failed: %s", e)
                u, r = None, None

        if self.ip:
            try:
                ip = self.ip(request_obj)
            except Exception as e:
                _logger.error("override_source_ip callback failed: %s", e)
                ip = None

        return {"user": u, "role": r, "ip": ip}

class RequestContext:
    def __init__(self):
        self.path = lambda r: None
        self.user_agent = lambda r: None
        self.method = lambda r: None

    def get_context(self, request_obj):
        out = {}
        for name in ("path", "user_agent", "method"):
            try:
                out[name] = getattr(self, name)(request_obj)
            except Exception as e:
                _logger.error("failed to extract request %s: %s", name, e)
                out[name] = None
        return out

class Sentry:
    def __init__(self, app, service: str, environment: str):
        self.logger = logging.getLogger("trappsec")

        self.hostname = socket.gethostname()
        self.service = service
        self.environment = environment

        self.integration = None
        
        self.identity = IdentityContext()
        self.request = RequestContext()
        
        self._traps = []
        self._watches = []
        self._templates = {}
        self._handlers = [LogHandler(self.logger)]

        self.default_responses = {
            "authenticated": {
                "status_code": 200,
                "response_body": {},
                "mime_type": "application/json"
            },
            "unauthenticated": {
                "status_code": 401,
                "response_body": {},
                "mime_type": "application/json"
            }
        }

        self._register(app)

    def bootstrap(self):
        """Install traps and watches. Idempotent and thread-safe."""
        fn = getattr(self.integration, "bootstrap", None)
        if callable(fn):
            return fn()

    def close(self, timeout: float = 5.0):
        """Stop background workers (heartbeats) and flush pending deliveries."""
        for h in self._handlers:
            fn = getattr(h, "close", None)
            if callable(fn):
                try:
                    fn(timeout)
                except Exception as e:
                    self.logger.error("error closing handler: %s", e)
    
    def default_response(self, status: int = None, body: typing.Union[dict, str, typing.Callable] = None, mime_type: str = None, template: str = None):
        """Default response for authenticated requests to traps that do not call ``respond``.

        Same arguments as ``TrapBuilder.respond``: only the arguments you pass
        change the default, and ``template`` replaces it. Resolved at bootstrap,
        so it may be called before or after declaring traps.
        """
        return self._set_default("authenticated", status, body, mime_type, template)

    def default_unauthenticated_response(self, status: int = None, body: typing.Union[dict, str, typing.Callable] = None, mime_type: str = None, template: str = None):
        """Default response for unauthenticated requests to traps that do not call ``if_unauthenticated``."""
        return self._set_default("unauthenticated", status, body, mime_type, template)

    def _set_default(self, key, status, body, mime_type, template):
        if template is not None:
            if any(arg is not None for arg in (status, body, mime_type)):
                raise TypeError("default_response: `template` cannot be used together with `status`, `body`, or `mime_type`.")
            tmpl = self._templates.get(template)
            if tmpl is None:
                raise ValueError(f"default_response: template '{template}' not found.")
            self.default_responses[key] = dict(tmpl)
            return self
        current = dict(self.default_responses[key])
        if status is not None:
            current["status_code"] = status
        if body is not None:
            current["response_body"] = body
        if mime_type is not None:
            current["mime_type"] = mime_type
        self.default_responses[key] = current
        return self

    def template(self, name: str, status_code: int, response_body: dict, mime_type: str = "application/json"):
        self._templates[name] = {"status_code": status_code, "response_body": response_body, "mime_type": mime_type}
        return self

    def trap(self, path: str):
        builder = TrapBuilder(self, path)
        self._traps.append(builder)
        return builder

    def watch(self, path: str):
        builder = WatchBuilder(path)
        self._watches.append(builder)
        return builder

    def add_webhook(
        self,
        url: str,
        secret: str = None,
        headers: dict = None,
        heartbeat_interval: int = None,
        template: typing.Callable = None,
        alerts_only: bool = True,
    ):
        from .handlers import WebhookHandler
        handler = WebhookHandler(
            url=url, 
            secret=secret, 
            headers=headers, 
            service=self.service, 
            environment=self.environment,
            heartbeat_interval=heartbeat_interval,
            template=template,
            alerts_only=alerts_only,
        )
        self._handlers.append(handler)
        return self

    def add_otel(self):
        from .handlers import OTELHandler
        self._handlers.append(OTELHandler())
        return self

    def add_slack(self, url: str, alerts_only: bool = True):
        from .handlers import SlackHandler
        self._handlers.append(
            SlackHandler(
                url=url,
                service=self.service,
                environment=self.environment,
                alerts_only=alerts_only,
            )
        )
        return self

    def identify_user(self, callback: typing.Callable):
        self.identity.auth = callback
        return self

    def override_source_ip(self, callback: typing.Callable):
        self.identity.ip = callback
        return self

    @property
    def traps(self):
        return [d.build() if hasattr(d, "build") else d for d in self._traps]

    @property
    def watches(self):
        return [r.build() if hasattr(r, "build") else r for r in self._watches]

    def _base_event(self, name, req):
        identity_ctx = self.identity.get_context(req)
        request_ctx = self.request.get_context(req)

        path = request_ctx["path"]
        ua = request_ctx["user_agent"]
        event = {
            "timestamp": time.time(),
            "event": name,
            "type": "signal",
            "path": _truncate_text(path, _MAX_STR) if isinstance(path, str) else path,
            "method": request_ctx["method"],
            "user_agent": _truncate_text(ua, _MAX_STR) if isinstance(ua, str) else ua,
            "ip": identity_ctx["ip"],
            "user": None,
            "role": None,
        }
        if identity_ctx["user"]:
            event["type"] = "alert"
            event["user"] = identity_ctx["user"]
            event["role"] = identity_ctx["role"]
        return event

    def is_trap(self, request) -> bool:
        """True when the request targets a trap (method and path).

        Use it to skip middleware that would otherwise reject a trap before it can
        answer, such as CSRF protection (R22): a trap that answers 403 is both
        disabled and easy to fingerprint. ``:id``, ``{id}`` and ``<id>`` segments
        match any single segment. Never raises.
        """
        try:
            method = str(self.request.method(request) or "").upper()
            path = _trap_path(self.request.path(request))
            if not method or not path:
                return False
            return any(
                method in {str(m).upper() for m in (t.get("methods") or [])} and _trap_path_matches(t.get("path"), path)
                for t in self.traps
            )
        except Exception:
            return False

    def trigger(self, req, reason: str, intent: str = None, metadata: dict = None):
        trigger_ctx = self._base_event("trappsec.rule_hit", req)
        trigger_ctx["reason"] = reason
        trigger_ctx["intent"] = intent
        trigger_ctx["metadata"] = metadata

        self._trigger(trigger_ctx)

    def _trigger(self, trigger_ctx):
        trigger_ctx["app"] = {
            "service": self.service,
            "environment": self.environment,
            "hostname": self.hostname
        }

        for h in self._handlers: 
            try: 
                h.emit(trigger_ctx)
            except Exception as e:
                self.logger.error("error invoking log handler: %s", e)

    def _trigger_watch_event(self, req, found_fields):
        trigger_ctx = self._base_event("trappsec.watch_hit", req)
        trigger_ctx["found_fields"] = found_fields

        self._trigger(trigger_ctx)

    def _trigger_trap_event(self, req, trap):
        trigger_ctx = self._base_event("trappsec.trap_hit", req)
        trigger_ctx["intent"] = trap.get("intent")

        response_key = "response.unauthenticated"
        if trigger_ctx["type"] == "alert":
            response_key = "response.authenticated"

        self._trigger(trigger_ctx)

        response_config = trap[response_key]
        response_body = response_config["response_body"]

        if callable(response_body):
            try:
                response_body = response_body(req)
            except Exception as e:
                self.logger.error("trap response body callback failed: %s", e)
                response_body = {}

        mime = str(response_config.get("mime_type") or "").split(";")[0].strip().lower()
        if isinstance(response_body, (str, bytes)):
            pass  # strings are sent raw regardless of mime type
        elif mime == "application/json":
            try:
                response_body = json.dumps(response_body, default=str)
            except Exception as e:
                self.logger.error("failed to encode trap response body: %s", e)
                response_body = "{}"

        return response_body, response_config

    def _detect_honey_fields(self, data, rules, request_obj=None, source="body"):
        """Detect and strip watched keys. Returns (data, found_fields, touched)."""
        found_fields = []
        touched = False

        if not rules:
            return data, found_fields, touched

        if isinstance(data, list):
            for item in data:
                if isinstance(item, MutableMapping):
                    _, f, t = self._detect_honey_fields(item, rules, request_obj, source)
                    found_fields.extend(f)
                    touched = touched or t
            return data, found_fields, touched

        if not isinstance(data, MutableMapping):
            return data, found_fields, touched

        for key in list(data.keys()):
            try:
                watched = key in rules
            except TypeError:
                watched = False
            if not watched:
                continue

            touched = True
            rule_definition = rules[key] or {}
            actual = data[key]
            # Always strip, no matter what happens while evaluating.
            try:
                del data[key]
            except Exception as e:
                self.logger.error("failed to strip watched field `%s`: %s", key, e)

            try:
                expected = rule_definition.get("default", NO_DEFAULT)
                if callable(expected):
                    try:
                        expected = expected(request_obj)
                    except Exception as e:
                        self.logger.error("failed to evaluate callable default for %s field `%s`: %s", source, key, e)
                        expected = NO_DEFAULT

                # Multi-valued fields arrive as lists: unless the whole list
                # matches (a list default), every element must match.
                if expected is NO_DEFAULT:
                    violation = True
                elif values_match(actual, expected):
                    violation = False
                elif isinstance(actual, (list, tuple)) and len(actual) > 0:
                    violation = not all(values_match(a, expected) for a in actual)
                else:
                    violation = True
            except Exception as e:
                self.logger.error("failed to evaluate %s field `%s`: %s", source, key, e)
                violation = True

            # A one-element list is reported as its scalar.
            if isinstance(actual, (list, tuple)) and len(actual) == 1:
                actual = actual[0]

            if violation:
                found_fields.append({
                    "type": source,
                    "field": key,
                    "value": safe_value(actual),
                    "intent": rule_definition.get("intent", None),
                })
        return data, found_fields, touched

    def _register(self, app):
        name = app.__class__.__name__
        module = app.__class__.__module__

        if name == "FastAPI" or module.startswith("fastapi"):
            from .integrations.fastapi import FastAPIIntegration
            self.integration = FastAPIIntegration(self, app)
        elif name == "Starlette" or module.startswith("starlette"):
            from .integrations.starlette import StarletteIntegration
            self.integration = StarletteIntegration(self, app)
        elif name == "Application" and module.startswith("tornado"):
            from .integrations.tornado import TornadoIntegration
            self.integration = TornadoIntegration(self, app)
        elif name == "Sanic" or module.startswith("sanic"):
            from .integrations.sanic import SanicIntegration
            self.integration = SanicIntegration(self, app)
        elif name == "Litestar" or module.startswith("litestar"):
            from .integrations.litestar import LitestarIntegration
            self.integration = LitestarIntegration(self, app)
        elif module.startswith("django"):
            from .integrations.django import DjangoIntegration
            self.integration = DjangoIntegration(self, app)
        elif name == "Flask" or module.startswith("flask"):
            from .integrations.flask import FlaskIntegration
            self.integration = FlaskIntegration(self, app)
        else:
            raise Exception("trappsec error: unknown framework.")
