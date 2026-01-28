import time
import json
import typing
import socket
import logging

from .handlers import LogHandler
from .builders import TrapBuilder, WatchBuilder, NO_DEFAULT

class IdentityContext:
    def __init__(self):
        self.ip = None
        self.auth = None

    def get_context(self, request_obj):
        u, r = None, None
        
        if self.auth:
            auth_context = self.auth(request_obj)
            if isinstance(auth_context, dict):
                u, r = auth_context.get("user"), auth_context.get("role")

        return {
            "user": u,
            "role": r,
            "ip": self.ip(request_obj) if self.ip else None
        }

class RequestContext:
    def __init__(self):
        self.path = lambda r: None
        self.user_agent = lambda r: None
        self.method = lambda r: None

    def get_context(self, request_obj):
        return {
            "path": self.path(request_obj),
            "user_agent": self.user_agent(request_obj),
            "method": self.method(request_obj)
        }

class Sentry:
    def __init__(self, app, service: str, environment: str):
        self.logger = logging.getLogger("trappsec")
        if not self.logger.handlers:
            logging.basicConfig(format="%(message)s", level=logging.WARNING)
        
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

    def add_webhook(self, url: str, secret: str = None, headers: dict = None, heartbeat_interval: int = None, template: typing.Callable = None):
        from .handlers import WebhookHandler
        handler = WebhookHandler(
            url=url, 
            secret=secret, 
            headers=headers, 
            service=self.service, 
            environment=self.environment,
            heartbeat_interval=heartbeat_interval,
            template=template
        )
        self._handlers.append(handler)
        return self

    def add_otel(self):
        from .handlers import OTELHandler
        self._handlers.append(OTELHandler())
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

    def trigger(self, req, reason: str, intent: str = None, metadata: dict = None):
        identity_ctx = self.identity.get_context(req)
        request_ctx = self.request.get_context(req)

        trigger_ctx = {
            "timestamp": time.time(),
            "event": "trappsec.rule_hit",
            "type": "signal",
            "reason": reason,
            "intent": intent,
            "path": request_ctx["path"],
            "method": request_ctx["method"],
            "user_agent": request_ctx["user_agent"],
            "ip": identity_ctx["ip"],
            "metadata": metadata,
        }

        if identity_ctx["user"]:
            trigger_ctx["type"] = "alert"
            trigger_ctx["user"] = identity_ctx["user"]
            trigger_ctx["role"] = identity_ctx["role"]

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
                self.logger.error("error invoking log handler: ", e)

    def _trigger_watch_event(self, req, found_fields):
        identity_ctx = self.identity.get_context(req)
        request_ctx = self.request.get_context(req)

        trigger_ctx = {
            "timestamp": time.time(),
            "event": "trappsec.watch_hit",
            "type": "signal",
            "path": request_ctx["path"],
            "method": request_ctx["method"],
            "user_agent": request_ctx["user_agent"],
            "ip": identity_ctx["ip"],
            "found_fields": found_fields
        }

        if identity_ctx["user"]:
            trigger_ctx["type"] = "alert"
            trigger_ctx["user"] = identity_ctx["user"]
            trigger_ctx["role"] = identity_ctx["role"]
        
        self._trigger(trigger_ctx)

    def _trigger_trap_event(self, req, trap):
        identity_ctx = self.identity.get_context(req)
        request_ctx = self.request.get_context(req)
        
        trigger_ctx = {
            "timestamp": time.time(),
            "event": "trappsec.trap_hit",
            "type": "signal",
            "path": request_ctx["path"],
            "method": request_ctx["method"],
            "user_agent": request_ctx["user_agent"],
            "ip": identity_ctx["ip"],
        }

        response_key = "response.unauthenticated"

        if identity_ctx["user"]:
            trigger_ctx["type"] = "alert"
            trigger_ctx["user"] = identity_ctx["user"]
            trigger_ctx["role"] = identity_ctx["role"]
            response_key = "response.authenticated"
        
        self._trigger(trigger_ctx)

        response_config = trap[response_key]
        response_body = response_config["response_body"]

        if callable(response_body):
            response_body = response_body(req)
        
        if response_config["mime_type"] == "application/json":
            response_body = json.dumps(response_body)
        
        return response_body, response_config
    
    def _detect_honey_fields(self, data, rules, request_obj=None):
        found_fields = []

        for key in list(data.keys()):
            if key in rules:
                rule_definition = rules[key]
                expected = rule_definition.get("default", NO_DEFAULT)
                
                try:
                    if callable(expected):
                        expected = expected(request_obj)
                    
                    if expected is NO_DEFAULT or data[key] != expected:
                        found_fields.append({
                            "type": "body",
                            "field": key,
                            "value": data[key],
                            "intent": rule_definition.get("intent", None),
                        })
                except Exception as e:
                    self.logger.error(f"failed to evaluate callable expected value for body field `{key}`: ", e)            

                del data[key]
        return data, found_fields

    def _register(self, app):
        name = app.__class__.__name__
        module = app.__class__.__module__

        if name == "FastAPI" or module.startswith("fastapi"):
            from .integrations.fastapi import FastAPIIntegration
            self.integration = FastAPIIntegration(self, app)
        elif name == "Flask" or module.startswith("flask"):
            from .integrations.flask import FlaskIntegration
            self.integration = FlaskIntegration(self, app)
        else:
            raise Exception("trappsec error: unknown framework.")