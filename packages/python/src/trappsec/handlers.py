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
    def __init__(self, tracer_name="trappsec"):
        if trace is None: 
            raise ImportError("opentelemetry-api library required for OTELHandler")
        self.tracer = trace.get_tracer(tracer_name)

    def emit(self, event: dict):
        with self.tracer.start_as_current_span(event["event"]) as span:
            span.set_attributes(event)
