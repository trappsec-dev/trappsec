import typing
import copy

NO_DEFAULT = object()

class TrapBuilder:
    def __init__(self, ts, path):
        self.ts = ts
        self.config = {
            "path": path, 
            "methods": ["GET", "POST"],
            "intent": None,
            "response.authenticated": copy.deepcopy(self.ts.default_responses["authenticated"]),
            "response.unauthenticated": copy.deepcopy(self.ts.default_responses["unauthenticated"]),
        }

    def methods(self, *args):
        self.config["methods"] = list(args)
        return self

    def intent(self, intent: str):
        self.config["intent"] = intent
        return self
    
    def _respond(self, key: str, status: int = None, body: typing.Union[dict, typing.Callable] = None, mime_type: str = None, template: str = None):
        key = "response." + key
        if template:
            if any(arg is not None for arg in (status, body, mime_type)):
                raise TypeError("response_builder: `template` cannot be used together with `status`, `body`, or `mime_type`.")
        
            tmpl = self.ts._templates.get(template)
            if not tmpl: 
                raise ValueError(f"response_builder: template '{template}' not found.")
            
            self.config[key] = copy.deepcopy(tmpl)
        else:
            if status: 
                self.config[key]["status_code"] = status
            
            if body: 
                self.config[key]["response_body"] = body
            
            if mime_type: 
                self.config[key]["mime_type"] = mime_type
        
        return self

    def respond(self, status: int = None, body: typing.Union[dict, typing.Callable] = None, mime_type: str = None, template: str = None):
        self._respond("authenticated", status, body, mime_type, template)
        return self

    def if_unauthenticated(self, status: int = None, body: typing.Union[dict, typing.Callable] = None, mime_type: str = None, template: str = None):
        self._respond("unauthenticated", status, body, mime_type, template)
        return self

    def build(self):
        return self.config

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
            "query_fields": self._query,
            "body_fields": self._body
        }
