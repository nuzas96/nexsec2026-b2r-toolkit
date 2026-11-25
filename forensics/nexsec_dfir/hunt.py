"""Bounded ASCII/UTF-16LE string hunting with offsets. No modification to input."""
from __future__ import annotations

import re
from pathlib import Path
from .core import ForensicError

DEFAULT_PATTERN = r"(?i)(https?://|[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}|flag\{|thm\{|curtin_ctf\{|powershell|cmd\.exe|\\users\\|/home/)"


def hunt_strings(path: Path, *, pattern: str = DEFAULT_PATTERN,
                 min_length: int = 5, max_bytes: int = 100 * 1024 * 1024,
                 max_hits: int = 1000) -> dict:
    if not 4 <= min_length <= 100:
        raise ForensicError("min_length must be 4..100")
    if max_bytes < 1 or max_hits < 1:
        raise ForensicError("max_bytes and max_hits must be positive")
    try:
        rgx = re.compile(pattern)
    except re.error as err:
        raise ForensicError(f"Invalid regex: {err}") from err
    ascii_pat = re.compile(rb"[\x20-\x7E]{" + str(min_length).encode() + rb",}")
    utf16_pat = re.compile(rb"(?:[\x20-\x7E]\x00){" + str(min_length).encode() + rb",}")
    size = path.stat().st_size
    scanned, hits, seen = 0, [], set()
    with path.open("rb") as fp:
        overlap = 8192
        prev = b""
        while scanned < min(size, max_bytes) and len(hits) < max_hits:
            block = fp.read(min(1024 * 1024, max_bytes - scanned))
            if not block:
                break
            data = prev + block
            origin = scanned - len(prev)
            for encoding, scanner in (("ascii", ascii_pat), ("utf-16le", utf16_pat)):
                for match in scanner.finditer(data):
                    offset = origin + match.start()
                    if (encoding, offset) in seen:
                        continue
                    # Skip extremely long strings to constrain regex and output size.
                    raw = match.group(0)[:4096]
                    string = raw.decode("utf-16le" if encoding == "utf-16le" else "ascii", errors="replace")
                    if rgx.search(string):
                        seen.add((encoding, offset))
                        hits.append({"offset_decimal": offset, "encoding": encoding, "text_excerpt": string[:300]})
                        if len(hits) >= max_hits:
                            break
                if len(hits) >= max_hits:
                    break
            scanned += len(block)
            prev = data[-overlap:]
    return {"path": str(path), "size_bytes": size, "scanned_bytes": scanned,
            "truncated": scanned < size or len(hits) >= max_hits,
            "max_hits": max_hits, "hits": hits,
            "note": "String candidates only; offsets refer to original file bytes. Binary/encoded/overlap limitations apply."}
