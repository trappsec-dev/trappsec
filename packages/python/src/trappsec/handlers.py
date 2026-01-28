import logging
import json
import hmac
import hashlib
import threading
import time

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    requests = None


class BaseHandler:
    def emit(self, event: dict): raise NotImplementedError

class LogHandler(BaseHandler):
    def __init__(self, logger: logging.Logger):
        self.logger = logger
    def emit(self, event: dict):
        self.logger.warning(json.dumps(event))

class WebhookHandler(BaseHandler):
    def __init__(self, url: str, secret: str = None, headers: dict = None, service: str = None, environment: str = None, heartbeat_interval: int = None, template: callable = None):
        if requests is None: 
            raise ImportError("requests library required for WebhookHandler")
        
        self.url = url
        self.secret = secret
        self.service = service
        self.environment = environment
        self.template = template
        self.logger = logging.getLogger("trappsec")
        
        self.headers = {"Content-Type": "application/json"}
        self.headers.update(headers or {})
        
        self.session = requests.Session()
        self.session.mount("https://", HTTPAdapter(max_retries=Retry(total=3, backoff_factor=1)))

        if heartbeat_interval:
            threading.Thread(target=self._heartbeat_loop, args=(heartbeat_interval,), daemon=True).start()
    
    def emit(self, event: dict):
        if self.template:
            try:
                event = self.template(event)
            except Exception as e:
                self.logger.error(f"Failed to apply webhook template: {e}")
        
        payload = json.dumps(event)
        self._send(payload)

    def _heartbeat_loop(self, interval: int):
        while True:
            time.sleep(interval)
            payload = json.dumps({
                "timestamp": time.time(),
                "event": "trappsec.heartbeat",
                "service": self.service,
                "environment": self.environment,
            })
            self._send(payload)

    def _send(self, payload: str):
        headers = self.headers.copy()
        if self.secret:
            headers["x-trappsec-signature"] = hmac.new(
                self.secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
        
        try:
            self.session.post(self.url, data=payload, headers=headers, timeout=5)
        except Exception as e: 
            self.logger.error(f"Failed to send webhook: {e}")

try:
    from opentelemetry import trace
except ImportError:
    trace = None

class OTELHandler(BaseHandler):
    def __init__(self):
        if trace is None: 
            raise ImportError("opentelemetry-api library required for OTELHandler")

    def emit(self, event: dict):
        current_span = trace.get_current_span()
        if current_span.is_recording():
            current_span.set_attribute("trappsec.detected", True)
            current_span.set_attribute("trappsec.event", event["event"])
            current_span.set_attribute("trappsec.type", event["type"])
            
            if event.get("user"):
                current_span.set_attribute("trappsec.user", event["user"])
            if event.get("role"):
                current_span.set_attribute("trappsec.role", event["role"])
            
            if event.get("ip"):
                current_span.set_attribute("trappsec.ip", event["ip"])
            
            if event["event"] == "trappsec.watch_hit":
                for field_info in event["found_fields"]:
                    current_span.add_event("watch_hit", field_info)
            
            if event["event"] == "trappsec.trap_hit":
                if event.get("intent"):
                    current_span.set_attribute("trappsec.intent", event["intent"])
            
            if event["event"] == "trappsec.rule_hit":
                if event.get("intent"):
                    current_span.set_attribute("trappsec.intent", event["intent"])
                if event.get("reason"):
                    current_span.set_attribute("trappsec.reason", event["reason"])
            
            if event.get("metadata"):
                metadata = event["metadata"]
                if isinstance(metadata, dict):
                    attrs = {f"metadata.{k}": v for k, v in metadata.items()}
                    current_span.set_attributes(attrs)