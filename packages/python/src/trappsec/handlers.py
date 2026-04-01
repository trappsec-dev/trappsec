import logging
import json
import hmac
import hashlib
import threading
import time
from datetime import datetime

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
    def __init__(self, url: str, secret: str = None, headers: dict = None, service: str = None, environment: str = None, heartbeat_interval: int = None, template: callable = None, alerts_only: bool = True):
        if requests is None: 
            raise ImportError("requests library required for WebhookHandler")
        
        self.url = url
        self.secret = secret
        self.service = service
        self.environment = environment
        self.template = template
        self.alerts_only = alerts_only
        self.logger = logging.getLogger("trappsec")
        
        self.headers = {"Content-Type": "application/json"}
        self.headers.update(headers or {})
        
        self.session = requests.Session()
        self.session.mount("https://", HTTPAdapter(max_retries=Retry(total=3, backoff_factor=1)))

        if heartbeat_interval:
            threading.Thread(target=self._heartbeat_loop, args=(heartbeat_interval,), daemon=True).start()
    
    def emit(self, event: dict):
        if self.alerts_only and event.get("type") != "alert":
            return

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


def _stringify(value):
    if value is None:
        return "-"
    if isinstance(value, (dict, list)):
        return json.dumps(value, default=str)
    return str(value)


def _truncate(value: str, limit: int = 180) -> str:
    if len(value) <= limit:
        return value
    if limit <= 3:
        return value[:limit]
    return value[: limit - 3] + "..."


def _build_slack_payload(event: dict, service: str = None, environment: str = None) -> dict:
    app = event.get("app") or {}
    event_name = event.get("event", "trappsec.event")
    event_type = event.get("type", "signal")
    severity = "ALERT" if event_type == "alert" else "SIGNAL"
    emoji = ":rotating_light:" if event_type == "alert" else ":large_blue_circle:"

    svc = app.get("service") or service or "unknown-service"
    env = app.get("environment") or environment or "unknown-env"
    host = app.get("hostname") or "unknown-host"
    path = event.get("path") or "-"
    method = event.get("method") or "-"
    intent = event.get("intent") or "-"
    reason = event.get("reason") or "-"
    ip = event.get("ip") or "-"
    user = event.get("user") or "-"
    role = event.get("role") or "-"
    ua = _truncate(_stringify(event.get("user_agent")), 120)
    timestamp = event.get("timestamp")
    when = "-"
    if timestamp:
        try:
            when = datetime.utcfromtimestamp(float(timestamp)).isoformat() + "Z"
        except Exception:
            when = _stringify(timestamp)

    fields = [
        {"type": "mrkdwn", "text": f"*Severity*\n{severity}"},
        {"type": "mrkdwn", "text": f"*Event*\n`{event_name}`"},
        {"type": "mrkdwn", "text": f"*Service*\n`{svc}`"},
        {"type": "mrkdwn", "text": f"*Environment*\n`{env}`"},
        {"type": "mrkdwn", "text": f"*Method*\n`{method}`"},
        {"type": "mrkdwn", "text": f"*Path*\n`{_truncate(path, 80)}`"},
        {"type": "mrkdwn", "text": f"*User*\n`{_truncate(user, 80)}`"},
        {"type": "mrkdwn", "text": f"*Role*\n`{_truncate(role, 80)}`"},
        {"type": "mrkdwn", "text": f"*IP*\n`{_truncate(ip, 80)}`"},
        {"type": "mrkdwn", "text": f"*Time (UTC)*\n`{when}`"},
    ]

    blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": f"{emoji} Trappsec {severity}"}},
        {"type": "section", "fields": fields},
        {"type": "context", "elements": [{"type": "mrkdwn", "text": f"*Host:* `{host}` | *User-Agent:* `{ua}`"}]},
    ]

    if event_name == "trappsec.watch_hit" and isinstance(event.get("found_fields"), list):
        lines = []
        for f in event["found_fields"][:8]:
            field_name = _truncate(_stringify(f.get("field")), 40)
            field_type = _truncate(_stringify(f.get("type")), 20)
            field_intent = _truncate(_stringify(f.get("intent")), 50)
            lines.append(f"- `{field_type}` `{field_name}` ({field_intent})")
        if lines:
            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": "*Triggered Fields*\n" + "\n".join(lines)}})

    if reason != "-" or intent != "-":
        blocks.append({"type": "section", "fields": [
            {"type": "mrkdwn", "text": f"*Intent*\n{_truncate(intent, 120)}"},
            {"type": "mrkdwn", "text": f"*Reason*\n{_truncate(reason, 120)}"},
        ]})

    text = f"[{severity}] {event_name} {method} {path} ({svc}/{env})"
    return {"text": text, "blocks": blocks}


class SlackHandler(BaseHandler):
    def __init__(self, url: str, service: str = None, environment: str = None, alerts_only: bool = True):
        self.service = service
        self.environment = environment
        self._webhook = WebhookHandler(
            url=url,
            service=service,
            environment=environment,
            template=lambda event: _build_slack_payload(event, service=self.service, environment=self.environment),
            alerts_only=alerts_only,
        )

    def emit(self, event: dict):
        self._webhook.emit(event)

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
