"""Offline text/encoding helpers. Decoded scripts are data and are never executed."""
from __future__ import annotations

import base64
import binascii
import html
import re
from urllib.parse import parse_qsl, urlsplit

from .core import ForensicError
from .external import evidence_identity, verify_source_unchanged


def decode_base64(value: str) -> bytes:
    compact = re.sub(r"\s+", "", value)
    if not compact:
        return b""
    if len(compact) % 4 == 1:
        raise ForensicError("Invalid Base64 length")
    padded = compact + ("=" * ((-len(compact)) % 4))
    try:
        return base64.b64decode(padded, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ForensicError(f"Invalid Base64 input: {exc}") from exc


def repeating_xor(data: bytes, key: bytes) -> bytes:
    if not key:
        raise ForensicError("XOR key must not be empty")
    return bytes(byte ^ key[index % len(key)] for index, byte in enumerate(data))


def decode_value(value: str, *, from_base64: bool = False,
                 xor_key: bytes | None = None, text_encoding: str = "utf-8") -> dict:
    data = decode_base64(value) if from_base64 else value.encode("utf-8")
    if xor_key is not None:
        data = repeating_xor(data, xor_key)
    try:
        decoded_text = data.decode(text_encoding, errors="strict")
        decode_error = None
    except (UnicodeDecodeError, LookupError) as exc:
        decoded_text = None
        decode_error = str(exc)
    return {"input_encoding": "base64" if from_base64 else "utf-8",
            "transformations": (["base64-decode"] if from_base64 else []) + (["repeating-key-xor"] if xor_key is not None else []),
            "decoded_size_bytes": len(data), "decoded_text": decoded_text,
            "text_encoding": text_encoding if decoded_text is not None else None,
            "text_decode_error": decode_error, "hex_preview": data[:128].hex(),
            "hex_preview_truncated": len(data) > 128,
            "note": "Decoded bytes are inert data. PowerShell or other recovered code is never executed."}, data


def inspect_email_urls(path, *, decode_param: str | None = None,
                       max_bytes: int = 20_000_000) -> dict:
    """Extract URLs from an RFC822 message without fetching them."""
    from email import policy
    from email.parser import BytesParser
    from pathlib import Path
    path = Path(path)
    if not path.is_file() or path.is_symlink():
        raise ForensicError(f"Email artifact not found or is a symlink: {path}")
    if path.stat().st_size > max_bytes:
        raise ForensicError(f"Email artifact exceeds max-bytes={max_bytes}")
    identity = evidence_identity(path)
    with path.open("rb") as fp:
        message = BytesParser(policy=policy.default).parse(fp)
    bodies = []
    if message.is_multipart():
        parts = message.walk()
    else:
        parts = (message,)
    for part in parts:
        if part.get_content_maintype() != "text":
            continue
        try:
            body = part.get_content()
        except (LookupError, UnicodeDecodeError):
            continue
        if isinstance(body, str):
            bodies.append(html.unescape(body))
    urls = []
    seen = set()
    pattern = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
    for body in bodies:
        for match in pattern.finditer(body):
            raw = match.group(0).rstrip(".,);]")
            if raw in seen:
                continue
            seen.add(raw)
            parsed = urlsplit(raw)
            entry = {"url": raw, "host": parsed.hostname or "", "path": parsed.path,
                     "query_parameter_names": [key for key, _ in parse_qsl(parsed.query, keep_blank_values=True)],
                     "source_artifact": str(path.resolve()), "source_sha256": identity["source_sha256"]}
            if decode_param:
                selected = [value for key, value in parse_qsl(parsed.query, keep_blank_values=True) if key == decode_param]
                if selected:
                    try:
                        data = decode_base64(selected[0])
                        entry["decoded_parameter"] = decode_param
                        entry["decoded_parameter_hex_preview"] = data[:128].hex()
                        try:
                            entry["decoded_parameter_text"] = data.decode("utf-8")
                        except UnicodeDecodeError:
                            entry["decoded_parameter_text"] = None
                    except ForensicError as exc:
                        entry["decode_error"] = str(exc)
            urls.append(entry)
    verify_source_unchanged(path, identity)
    return {**identity, "message_id": str(message.get("Message-ID", "")),
            "from": str(message.get("From", "")), "subject": str(message.get("Subject", "")),
            "date_raw": str(message.get("Date", "")), "urls": urls,
            "network_accessed": False,
            "note": "URLs are inert extracted strings; no link was opened or fetched."}
