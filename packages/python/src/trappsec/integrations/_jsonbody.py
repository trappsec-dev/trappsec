"""Shared helpers for inspecting JSON request bodies the way the application would.

Applications call ``json.loads(bytes)`` (or the framework's equivalent), which
auto-detects UTF-8 (with or without BOM), UTF-16 and UTF-32, and most framework
JSON accessors ignore the Content-Type header entirely. Inspection therefore
parses the raw bytes, and treats any non-form body that parses to a JSON
object/array as JSON.
"""
import json
import re

FORM_MEDIA = ("application/x-www-form-urlencoded", "multipart/form-data")
_CHARSET_RE = re.compile(r"(;\s*charset\s*=\s*)(\"[^\"]*\"|[^;\s]*)", re.I)


def media_type(content_type):
    return (content_type or "").split(";")[0].strip().lower()


def is_json_media(media):
    return media == "application/json" or media.endswith("+json")


def is_form_media(media):
    return media in FORM_MEDIA


def parse_json_bytes(raw):
    """Parse like the app would (encoding auto-detected). Raises on invalid JSON."""
    return json.loads(raw)


def sniff_json(raw):
    """Parse ``raw`` if it is a JSON object/array in any JSON encoding, else None."""
    try:
        data = json.loads(raw)
    except Exception:
        return None
    return data if isinstance(data, (dict, list)) else None


def serialize(data):
    return json.dumps(data).encode("utf-8")


def fix_charset(content_type):
    """Rewrite a charset parameter (if any) to utf-8; None when there is none."""
    if not content_type or not _CHARSET_RE.search(content_type):
        return None
    return _CHARSET_RE.sub(lambda m: m.group(1) + "utf-8", content_type)
