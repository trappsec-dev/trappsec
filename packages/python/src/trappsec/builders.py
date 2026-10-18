import typing
import copy

NO_DEFAULT = object()

def _check_headers(label: str, headers) -> dict:
    """Validated copy of a response ``headers`` mapping (str names and values, no CR/LF)."""
    if not isinstance(headers, typing.Mapping):
        raise TypeError(f"{label}: `headers` must be a mapping of header name to value.")
    out = {}
    for name, value in headers.items():
        if not isinstance(name, str) or not isinstance(value, str):
            raise TypeError(f"{label}: header names and values must be strings, got {name!r}: {value!r}.")
        if not name or any(c in name for c in "\r\n:") or any(c in value for c in "\r\n"):
            raise ValueError(f"{label}: invalid header {name!r}.")
        out[name] = value
    return out


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
        self._hook = None

    def methods(self, *args):
        self._methods = list(args)
        self.ts._trap_index = None  # is_trap rebuilds its index
        return self

    def intent(self, intent: str):
        self._intent = intent
        return self

    def _respond(self, key: str, status: int = None, body: typing.Union[dict, str, typing.Callable] = None, mime_type: str = None, template: str = None, headers: typing.Mapping[str, str] = None):
        if template is not None:
            if any(arg is not None for arg in (status, body, mime_type, headers)):
                raise TypeError("response_builder: `template` cannot be used together with `status`, `body`, `mime_type`, or `headers`.")

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
            if headers is not None:
                spec["headers"] = _check_headers("response_builder", headers)

        return self

    def respond(self, status: int = None, body: typing.Union[dict, str, typing.Callable] = None, mime_type: str = None, template: str = None, headers: typing.Mapping[str, str] = None):
        self._respond("authenticated", status, body, mime_type, template, headers)
        return self

    def if_unauthenticated(self, status: int = None, body: typing.Union[dict, str, typing.Callable] = None, mime_type: str = None, template: str = None, headers: typing.Mapping[str, str] = None):
        self._respond("unauthenticated", status, body, mime_type, template, headers)
        return self

    def respond_with(self, hook: typing.Callable):
        """Per-request response hook, called as ``hook(request, ctx)`` on every hit.

        ``ctx`` is ``{"authenticated", "user", "role"}``. Return ``None`` to send
        the static response for that auth state, or a dict with any of
        ``status``, ``body``, ``mime_type`` and ``headers`` to override it
        (``headers`` are merged into the static ones). The hook must be
        synchronous; if it fails, the static response is sent.
        """
        if hook is not None and not callable(hook):
            raise TypeError("respond_with: `hook` must be callable or None.")
        self._hook = hook
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
            # Sent when the trap's own body cannot be produced (R16).
            "fallback.authenticated": _copy(self.ts.default_responses["authenticated"]),
            "fallback.unauthenticated": _copy(self.ts.default_responses["unauthenticated"]),
            "response_hook": self._hook,
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
