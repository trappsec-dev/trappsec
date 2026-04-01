import logging
import json
import hmac
import hashlib
import threading
import time
from datetime import datetime, timezone

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


_EVENT_LABELS = {
    "trappsec.watch_hit": "Honey Field Accessed",
    "trappsec.trap_hit": "Decoy Route Triggered",
    "trappsec.rule_hit": "Security Rule Triggered",
}


def _slack_date_token(timestamp) -> str:
    try:
        seconds = int(float(timestamp))
    except Exception:
        return "-"
    if seconds <= 0:
        return "-"
    fallback = datetime.fromtimestamp(seconds, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return f"<!date^{seconds}^{{date_short_pretty}} at {{time_secs}}|{fallback}>"


def _notification_text(event_name: str, severity: str, svc: str, user: str, path: str, method: str, found_fields: list) -> str:
    actor = user or "An unauthenticated request"
    if event_name == "trappsec.watch_hit":
        if found_fields:
            names = ", ".join(f.get("field", "unknown") for f in found_fields[:3] if isinstance(f, dict))
            suffix = f" ({names})" if names else ""
            return f"[{severity}] {actor} accessed a monitored field{suffix} on {svc}"
        return f"[{severity}] {actor} accessed a monitored field on {svc}"
    if event_name == "trappsec.trap_hit":
        return f"[{severity}] Honeypot endpoint hit on {svc} - {method} {path}"
    if event_name == "trappsec.rule_hit":
        return f"[{severity}] Security rule triggered on {svc} - {method} {path}"
    return f"[{severity}] {event_name} on {svc}"


def _kv_line(key: str, value) -> str:
    if value in (None, ""):
        return None
    rendered = str(value)
    return f"*{key}:* {rendered}"


def _compact_lines(lines: list) -> list:
    return [line for line in lines if line]


def _build_slack_payload(event: dict, service: str = None, environment: str = None) -> dict:
    app = event.get("app") or {}
    event_name = event.get("event", "trappsec.event")
    event_type = event.get("type", "signal")
    level = "alert" if event_type == "alert" else "signal"
    color = "#CC0000" if level == "alert" else "#0066CC"
    svc = app.get("service") or service or "unknown-service"
    env = app.get("environment") or environment or "unknown-env"
    host = app.get("hostname") or None
    path = event.get("path") or "-"
    method = event.get("method") or "-"
    intent = event.get("intent") or None
    reason = event.get("reason") or None
    ip = event.get("ip") or None
    user = event.get("user") or None
    role = event.get("role") or None
    ua_raw = event.get("user_agent")
    ua = _truncate(_stringify(ua_raw), 120) if ua_raw is not None else None
    when = _slack_date_token(event.get("timestamp"))
    found_fields = event.get("found_fields") if isinstance(event.get("found_fields"), list) else []

    route = "-" if method == "-" and path == "-" else f"{method} {path}".strip()

    event_lines = _compact_lines([
        _kv_line("Event", _EVENT_LABELS.get(event_name, event_name)),
        _kv_line("Timestamp", when),
        _kv_line("Service", svc),
        _kv_line("Environment", env),
        _kv_line("Host", host),
    ])
    request_lines = _compact_lines([
        _kv_line("IP", ip),
        _kv_line("Route", route),
        _kv_line("User Agent", ua),
        _kv_line("User", user),
        _kv_line("Role", role),
    ])

    blocks = [
        {"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(event_lines)}},
    ]
    if request_lines:
        blocks.append({"type": "divider"})
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(request_lines)}})

    if event_name == "trappsec.watch_hit" and found_fields:
        field_lines = []
        for idx, f in enumerate(found_fields[:8], start=1):
            name = _stringify(f.get("field"))
            ftype = _stringify(f.get("type"))
            fintent = _stringify(f.get("intent"))
            parts = [name]
            if ftype != "-":
                parts.append(f"[{ftype}]")
            if fintent != "-":
                parts.append(f"- {fintent}")
            field_lines.append(_kv_line(f"Triggered Field {idx}", " ".join(parts)))
        if field_lines:
            blocks.append({"type": "divider"})
            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(field_lines)}})

    details = []
    if intent:
        details.append(_kv_line("Intent", _truncate(intent, 120)))
    if reason:
        details.append(_kv_line("Reason", _truncate(reason, 120)))
    details = _compact_lines(details)
    if details:
        blocks.append({"type": "divider"})
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(details)}})

    text = ""
    return {"text": text, "attachments": [{"color": color, "blocks": blocks}]}


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
