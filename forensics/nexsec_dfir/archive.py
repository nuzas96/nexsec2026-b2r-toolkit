"""ZIP metadata inventory only. Never extract supplied evidence."""
from __future__ import annotations

import stat
import zipfile
from pathlib import Path, PurePosixPath
from .core import ForensicError


def inventory_zip(path: Path, *, max_entries: int = 100000) -> dict:
    if not zipfile.is_zipfile(path):
        raise ForensicError("Not a recognized ZIP container; header/structure may be damaged")
    items = []
    names = set()
    total_size = 0
    with zipfile.ZipFile(path) as zf:
        members = zf.infolist()
        if len(members) > max_entries:
            raise ForensicError(f"ZIP contains {len(members)} entries, over configured {max_entries} limit")
        for info in members:
            raw = info.filename.replace("\\", "/")
            parts = PurePosixPath(raw).parts
            risky = []
            if raw.startswith("/") or ":" in raw.split("/")[0]:
                risky.append("absolute-path")
            if ".." in parts:
                risky.append("parent-traversal")
            if raw.casefold() in names:
                risky.append("duplicate-name")
            if stat.S_ISLNK(info.external_attr >> 16):
                risky.append("symlink-entry")
            if info.flag_bits & 0x1:
                risky.append("encrypted-entry")
            ratio = round(info.file_size / max(1, info.compress_size), 2)
            if info.file_size > 100 * 1024 * 1024 and ratio > 100:
                risky.append("high-expansion-ratio")
            names.add(raw.casefold())
            total_size += info.file_size
            items.append({"name": info.filename, "uncompressed_bytes": info.file_size,
                          "compressed_bytes": info.compress_size, "compression_ratio": ratio,
                          "crc32": f"{info.CRC:08x}", "encrypted": bool(info.flag_bits & 0x1),
                          "flags": risky})
    return {"container": str(path), "entries": items, "entry_count": len(items),
            "total_declared_uncompressed_bytes": total_size,
            "note": "Metadata only; archive members were not extracted, decrypted or verified."}
