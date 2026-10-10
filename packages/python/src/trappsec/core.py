import time
import json
import math
import typing
import socket
import logging
from collections.abc import MutableMapping

from .handlers import LogHandler, _truncate_text
from .builders import TrapBuilder, WatchBuilder, NO_DEFAULT

_logger = logging.getLogger("trappsec")

_MAX_STR = 1024
_MAX_LIST = 20


def _is_number(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _canonical(v) -> typing.Optional[str]:
    """Canonical string form of a bool/number, or None for anything else."""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        if math.isfinite(v) and v == int(v):
            return str(int(v))
        return repr(v)
    return None


def values_match(actual, expected) -> bool:
    """Loose equality between a request value and a configured default (C3)."""
    try:
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
        try:
            return _truncate_text(json.dumps(v, default=str), _MAX_STR)
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
            "intent": None,
            "user": None,
            "role": None,
        }
        if identity_ctx["user"]:
            event["type"] = "alert"
            event["user"] = identity_ctx["user"]
            event["role"] = identity_ctx["role"]
        return event

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

                # Multi-valued fields arrive as lists. One element is compared
                # as a scalar; several are a violation unless all match.
                if isinstance(actual, (list, tuple)):
                    actual = list(actual)
                    if len(actual) == 1:
                        actual = actual[0]
                        violation = expected is NO_DEFAULT or not values_match(actual, expected)
                    elif len(actual) == 0:
                        violation = expected is NO_DEFAULT or not values_match(actual, expected)
                    else:
                        violation = expected is NO_DEFAULT or not all(values_match(a, expected) for a in actual)
                else:
                    violation = expected is NO_DEFAULT or not values_match(actual, expected)
            except Exception as e:
                self.logger.error("failed to evaluate %s field `%s`: %s", source, key, e)
                violation = True

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
