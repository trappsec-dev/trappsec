import typing
import copy

NO_DEFAULT = object()


def _copy(value):
    try:
        return copy.deepcopy(value)
    except Exception:
        return copy.copy(value)


class TrapBuilder:
    def __init__(self, ts, path):
        self.ts = ts
        self._path = path
        self._methods = ["GET", "POST"]
        self._intent = None
        # Per-response overrides, resolved against the Sentry default
        # responses only when build() is called (i.e. at bootstrap), so the
        # order of configuration calls does not matter.
        self._specs = {"authenticated": {}, "unauthenticated": {}}
        self._templates = {}

    def methods(self, *args):
        self._methods = list(args)
        self.ts._trap_index = None  # is_trap rebuilds its index
        return self

    def intent(self, intent: str):
        self._intent = intent
        return self

    def _respond(self, key: str, status: int = None, body: typing.Union[dict, str, typing.Callable] = None, mime_type: str = None, template: str = None):
        if template is not None:
            if any(arg is not None for arg in (status, body, mime_type)):
                raise TypeError("response_builder: `template` cannot be used together with `status`, `body`, or `mime_type`.")

            tmpl = self.ts._templates.get(template)
            if tmpl is None:
                raise ValueError(f"response_builder: template '{template}' not found.")

            self._templates[key] = _copy(tmpl)
            self._specs[key] = {}
        else:
            self._templates.pop(key, None)
            spec = self._specs[key]
            if status is not None:
                spec["status_code"] = status
            if body is not None:
                spec["response_body"] = body
            if mime_type is not None:
                spec["mime_type"] = mime_type

        return self

    def respond(self, status: int = None, body: typing.Union[dict, str, typing.Callable] = None, mime_type: str = None, template: str = None):
        self._respond("authenticated", status, body, mime_type, template)
        return self

    def if_unauthenticated(self, status: int = None, body: typing.Union[dict, str, typing.Callable] = None, mime_type: str = None, template: str = None):
        self._respond("unauthenticated", status, body, mime_type, template)
        return self

    def _resolve(self, key: str) -> dict:
        if key in self._templates:
            return _copy(self._templates[key])
        cfg = _copy(self.ts.default_responses[key])
        cfg.update(self._specs[key])
        return cfg

    def build(self):
        return {
            "path": self._path,
            "methods": list(self._methods),
            "intent": self._intent,
            "response.authenticated": self._resolve("authenticated"),
            "response.unauthenticated": self._resolve("unauthenticated"),
        }


class WatchBuilder:
    def __init__(self, path):
        self.path = path
        self._query = {}
        self._body = {}

    def query(self, name: str, default: typing.Any = NO_DEFAULT, intent: str = None):
        self._query[name] = {"default": default, "intent": intent}
        return self

    def body(self, name: str, default: typing.Any = NO_DEFAULT, intent: str = None):
        self._body[name] = {"default": default, "intent": intent}
        return self

    def build(self):
        return {
            "path": self.path,
            "query_fields": {k: dict(v) for k, v in self._query.items()},
            "body_fields": {k: dict(v) for k, v in self._body.items()}
        }
