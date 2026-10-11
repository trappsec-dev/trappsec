import logging
import json
import hmac
import hashlib
import os
import queue
import threading
import time
import weakref
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    requests = None

_QUEUE_SIZE = 1000
_DROP_WARN_INTERVAL = 60.0
_MAX_RETRIES = 2
_STOP = object()


def _truncate_text(value: str, limit: int = 1024) -> str:
    if len(value) <= limit:
        return value
    return value[:limit] + "..."


def _dumps(event) -> str:
    """Serialize an event; never raises."""
    try:
        return json.dumps(event, default=str)
    except Exception:
        try:
            return json.dumps(event, default=str, skipkeys=True, check_circular=False)
        except Exception:
            name = event.get("event") if isinstance(event, dict) else None
            return json.dumps({"event": str(name), "error": "event could not be serialized"})


# Webhook handlers alive in this process, reset in a forked child (see below).
_webhook_handlers = weakref.WeakSet()


def _reset_webhooks_after_fork():
    for h in list(_webhook_handlers):
        h._reset_after_fork()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_reset_webhooks_after_fork)


class BaseHandler:
    def emit(self, event: dict): raise NotImplementedError

    def close(self, timeout: float = 5.0):
        pass

class LogHandler(BaseHandler):
    def __init__(self, logger: logging.Logger):
        self.logger = logger
    def emit(self, event: dict):
        self.logger.warning(_dumps(event))

class WebhookHandler(BaseHandler):
    def __init__(self, url: str, secret: str = None, headers: dict = None, service: str = None, environment: str = None, heartbeat_interval: int = None, template: callable = None, alerts_only: bool = True, timeout: float = 5, queue_size: int = _QUEUE_SIZE):
        if requests is None: 
            raise ImportError("requests library required for WebhookHandler")
        
        self.url = url
        self.secret = secret
        self.service = service
        self.environment = environment
        self.template = template
        self.alerts_only = alerts_only
        self.timeout = timeout
        self.retry_backoff = 0.5
        self.heartbeat_interval = heartbeat_interval
        self.logger = logging.getLogger("trappsec")
        
        self.headers = {"Content-Type": "application/json"}
        self.headers.update(headers or {})
        
        self.session = requests.Session()

        self._queue = queue.Queue(maxsize=queue_size)
        self._lock = threading.Lock()
        self._worker = None
        self._heartbeat = None
        self._closed = False
        self._stop = threading.Event()      # stops the heartbeat
        self._abandon = threading.Event()   # abort retries/backoff on close timeout
        self._last_drop_warning = None

        _webhook_handlers.add(self)
        if heartbeat_interval:
            self._ensure_threads()

    def _reset_after_fork(self):
        """In a forked child (e.g. gunicorn --preload): the parent's threads are
        gone, its locks may be held and its connections and queued events belong
        to the parent, which delivers them. Start clean; threads restart lazily."""
        self._lock = threading.Lock()
        self._queue = queue.Queue(maxsize=self._queue.maxsize)
        self._worker = None
        self._heartbeat = None
        self._stop = threading.Event()
        self._abandon = threading.Event()
        self.session = requests.Session()

    def _ensure_threads(self):
        """Start (or restart, e.g. after fork) the worker and heartbeat threads."""
        with self._lock:
            if self._closed:
                return
            if self._worker is None or not self._worker.is_alive():
                self._worker = threading.Thread(target=self._worker_loop, name="trappsec-webhook", daemon=True)
                self._worker.start()
            if self.heartbeat_interval and (self._heartbeat is None or not self._heartbeat.is_alive()):
                self._heartbeat = threading.Thread(
                    target=self._heartbeat_loop, args=(self.heartbeat_interval,), name="trappsec-heartbeat", daemon=True)
                self._heartbeat.start()

    def emit(self, event: dict):
        if self.alerts_only and event.get("type") != "alert":
            return

        if self.template:
            try:
                event = self.template(event)
            except Exception as e:
                # Never fall back to sending the raw event.
                self.logger.error("Failed to apply webhook template, dropping event: %s", e)
                return

        self._send(_dumps(event))

    def _heartbeat_loop(self, interval: int):
        while not self._stop.wait(interval):
            self._send(_dumps({
                "timestamp": time.time(),
                "event": "trappsec.heartbeat",
                "service": self.service,
                "environment": self.environment,
            }))

    def _send(self, payload: str):
        """Queue a payload for asynchronous delivery. Never blocks."""
        if self._closed:
            return
        try:
            self._ensure_threads()
            self._queue.put_nowait(payload)
        except queue.Full:
            self._warn_dropped()
        except Exception as e:
            self.logger.error("Failed to queue webhook: %s", e)

    def _warn_dropped(self):
        now = time.monotonic()
        last = self._last_drop_warning
        if last is None or now - last >= _DROP_WARN_INTERVAL:
            self._last_drop_warning = now
            self.logger.warning("trappsec webhook queue is full; dropping event")

    def _worker_loop(self):
        while True:
            item = self._queue.get()
            try:
                if item is _STOP:
                    return
                self._deliver(item)
            except Exception as e:
                self.logger.error("Failed to send webhook: %s", type(e).__name__)
            finally:
                self._queue.task_done()

    def _deliver(self, payload: str):
        body = payload.encode("utf-8")
        for attempt in range(_MAX_RETRIES + 1):
            if attempt:
                if self._abandon.wait(self.retry_backoff * (2 ** (attempt - 1))):
                    return
            headers = self.headers.copy()
            if self.secret:
                ts = str(int(time.time()))
                digest = hmac.new(self.secret.encode(), ts.encode() + b"." + body, hashlib.sha256).hexdigest()
                headers["x-trappsec-timestamp"] = ts
                headers["x-trappsec-signature"] = "sha256=" + digest
            try:
                resp = self.session.post(self.url, data=body, headers=headers, timeout=self.timeout)
            except Exception as e:
                # Exception text may embed the URL, which can contain secrets.
                self.logger.error("Failed to send webhook (attempt %d): %s", attempt + 1, type(e).__name__)
                continue
            try:
                status = resp.status_code
                resp.close()
            except Exception:
                status = 0
            if 200 <= status < 300:
                return
            self.logger.error("Webhook endpoint returned HTTP %s (attempt %d)", status, attempt + 1)
            if status < 500 and status != 429:
                return

    def close(self, timeout: float = 5.0):
        """Stop the heartbeat and flush queued events (bounded by ``timeout``)."""
        deadline = time.monotonic() + timeout
        self._stop.set()
        hb = self._heartbeat
        if hb is not None and hb is not threading.current_thread():
            hb.join(max(0.0, deadline - time.monotonic()))
        with self._lock:
            already = self._closed
            self._closed = True
        worker = self._worker
        if worker is not None and worker.is_alive() and not already:
            try:
                self._queue.put(_STOP, timeout=max(0.0, deadline - time.monotonic()))
            except queue.Full:
                self._abandon.set()
                return
            worker.join(max(0.0, deadline - time.monotonic()))
            if worker.is_alive():
                self._abandon.set()


def _escape(value) -> str:
    """Escape Slack control characters in request-derived text."""
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


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
    svc, path, method = _escape(svc), _escape(path), _escape(method)
    actor = _escape(user) if user else "An unauthenticated request"
    if event_name == "trappsec.watch_hit":
        if found_fields:
            names = ", ".join(_escape(f.get("field", "unknown")) for f in found_fields[:3] if isinstance(f, dict))
            suffix = f" ({names})" if names else ""
            return f"[{severity}] {actor} accessed a monitored field{suffix} on {svc}"
        return f"[{severity}] {actor} accessed a monitored field on {svc}"
    if event_name == "trappsec.trap_hit":
        return f"[{severity}] Honeypot endpoint hit on {svc} - {method} {path}"
    if event_name == "trappsec.rule_hit":
        return f"[{severity}] Security rule triggered on {svc} - {method} {path}"
    return f"[{severity}] {event_name} on {svc}"


def _kv_line(key: str, value, raw: bool = False) -> str:
    if value in (None, ""):
        return None
    rendered = str(value) if raw else _escape(value)
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
    found_fields = [f for f in event.get("found_fields") if isinstance(f, dict)] if isinstance(event.get("found_fields"), list) else []

    route = "-" if method == "-" and path == "-" else f"{method} {path}".strip()

    event_lines = _compact_lines([
        _kv_line("Event", _EVENT_LABELS.get(event_name, event_name)),
        _kv_line("Timestamp", when, raw=True),
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

    text = _truncate(
        _notification_text(event_name, "Alert" if level == "alert" else "Signal", svc, user, path, method, found_fields),
        300,
    )
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

    def close(self, timeout: float = 5.0):
        self._webhook.close(timeout)

try:
    from opentelemetry import trace
except ImportError:
    trace = None

def _otel_value(value):
    """Coerce a value to a valid OTel attribute value, or None to drop it."""
    if value is None:
        return None
    if isinstance(value, (bool, str, float)):
        return value
    if isinstance(value, int):
        return value if -(2 ** 63) <= value < 2 ** 63 else str(value)
    if isinstance(value, (list, tuple)):
        items = [_otel_value(v) for v in value if v is not None]
        items = [v for v in items if v is not None]
        for kind in (bool, str, int, float):
            if all(type(v) is kind for v in items):
                return items
        return [v if isinstance(v, str) else _stringify(v) for v in items]
    if isinstance(value, dict):
        return _dumps(value)
    return str(value)


def _otel_attrs(mapping) -> dict:
    out = {}
    for k, v in mapping.items():
        cv = _otel_value(v)
        if cv is not None:
            out[str(k)] = cv
    return out


class OTELHandler(BaseHandler):
    def __init__(self):
        if trace is None: 
            raise ImportError("opentelemetry-api library required for OTELHandler")

    def emit(self, event: dict):
        current_span = trace.get_current_span()
        if not current_span.is_recording():
            return

        def put(name, value):
            cv = _otel_value(value)
            if cv is not None:
                current_span.set_attribute(name, cv)

        current_span.set_attribute("trappsec.detected", True)
        put("trappsec.event", event.get("event"))
        put("trappsec.type", event.get("type"))

        if event.get("user"):
            put("trappsec.user", event["user"])
        if event.get("role"):
            put("trappsec.role", event["role"])
        if event.get("ip"):
            put("trappsec.ip", event["ip"])

        if event.get("event") == "trappsec.watch_hit":
            for field_info in event.get("found_fields") or []:
                if isinstance(field_info, dict):
                    current_span.add_event("watch_hit", _otel_attrs(field_info))

        if event.get("event") in ("trappsec.trap_hit", "trappsec.rule_hit"):
            if event.get("intent"):
                put("trappsec.intent", event["intent"])

        if event.get("event") == "trappsec.rule_hit" and event.get("reason"):
            put("trappsec.reason", event["reason"])

        metadata = event.get("metadata")
        if metadata and isinstance(metadata, dict):
            current_span.set_attributes(_otel_attrs({f"metadata.{k}": v for k, v in metadata.items()}))
