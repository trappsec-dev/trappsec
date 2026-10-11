"""Shared helpers for inspecting and rewriting form bodies (query, urlencoded, multipart).

Inspection works on the raw bytes. Rewriting only removes the watched
fields: every unrelated byte of the original is re-emitted untouched.
"""
import re
from urllib.parse import unquote_to_bytes

_NAME_RE = re.compile(r';\s*name=(?:"([^"]*)"|([^;\s]*))', re.I)
_FILENAME_RE = re.compile(r";\s*filename\*?=", re.I)


def group_pairs(pairs):
    """[(k, v), ...] -> {k: scalar | [v, v, ...]} (lists only for repeated keys)."""
    out = {}
    for k, v in pairs:
        if k in out:
            if isinstance(out[k], list):
                out[k].append(v)
            else:
                out[k] = [out[k], v]
        else:
            out[k] = v
    return out


def _unquote(raw):
    return unquote_to_bytes(raw.replace(b"+", b" ")).decode("utf-8", "replace")


def inspect_urlencoded(ts, raw, rules, req, source="body"):
    """Detect/strip watched keys in a query / urlencoded body (bytes).

    Returns (found, new_raw_or_None); surviving ``k=v`` segments are kept verbatim,
    so unrelated values never get re-encoded.
    """
    segments = []
    for seg in raw.split(b"&"):
        if seg:
            key, _, value = seg.partition(b"=")
            segments.append((_unquote(key), _unquote(value), seg))
    data, found, touched = ts._detect_honey_fields(
        group_pairs([(k, v) for k, v, _ in segments]), rules, req, source=source)
    if not touched:
        return found, None
    return found, b"&".join(seg for k, _, seg in segments if k in data)


def multipart_boundary(content_type):
    for param in (content_type or "").split(";")[1:]:
        param = param.strip()
        if param.lower().startswith("boundary="):
            return param.split("=", 1)[1].strip().strip('"')
    return None


def multipart_parts(body, boundary):
    """Split a multipart body into (preamble, parts, tail) following RFC 2046: a
    delimiter is CRLF + "--" + boundary (the start of the body counts as an implicit
    CRLF) and the close delimiter has a trailing "--". Part values may therefore
    contain the boundary text. ``preamble`` includes the CRLF that precedes the first
    delimiter (empty when the body starts with it); raw bytes are kept so unrelated
    parts can be re-emitted byte-for-byte. File parts carry their content as bytes."""
    delim = b"--" + boundary.encode("utf-8")
    chunks = (b"\r\n" + body).split(b"\r\n" + delim)
    preamble = chunks[0][2:] + b"\r\n" if chunks[0] else b""
    tail, parts = b"", []
    for seg in chunks[1:]:
        if seg.startswith(b"--"):
            tail = seg
            break
        head, _, value = seg.partition(b"\r\n\r\n")
        name, is_file = None, False
        for line in head.split(b"\r\n"):
            text = line.decode("latin1")
            if text.lower().startswith("content-disposition"):
                m = _NAME_RE.search(text)
                if m:
                    name = m.group(1) if m.group(1) is not None else m.group(2)
                is_file = bool(_FILENAME_RE.search(text))
        parts.append({"name": name, "is_file": is_file, "raw": seg,
                      "value": value if is_file else value.decode("utf-8", "replace")})
    return preamble, parts, tail or b"--\r\n"


def rebuild_multipart(preamble, parts, tail, boundary, drop):
    delim = b"--" + boundary.encode("utf-8")
    kept = [delim + p["raw"] for p in parts if p["name"] not in drop]
    return preamble + b"\r\n".join(kept + [delim + tail])


def inspect_multipart(ts, body, content_type, rules, req):
    """Detect/strip watched fields (file parts included) in a multipart body.

    Returns (found, new_body_or_None)."""
    boundary = multipart_boundary(content_type)
    if not boundary:
        return [], None
    preamble, parts, tail = multipart_parts(body, boundary)
    pairs = [(p["name"], p["value"]) for p in parts if p["name"]]
    data, found, touched = ts._detect_honey_fields(group_pairs(pairs), rules, req)
    if not touched:
        return found, None
    drop = {k for k, _ in pairs if k not in data}
    return found, rebuild_multipart(preamble, parts, tail, boundary, drop)
