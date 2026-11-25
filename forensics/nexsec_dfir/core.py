"""Evidence intake, format clues, integrity verification. Offline stdlib only."""
from __future__ import annotations

import hashlib
import json
import os
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class ForensicError(Exception):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def write_json(path: Path, data: Any) -> None:
    if path.exists():
        raise ForensicError(f"Refusing to overwrite existing output: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".partial")
    if temp.exists():
        raise ForensicError(f"Temporary output already exists (inspect first): {temp}")
    try:
        with temp.open("x", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.write("\n")
        temp.replace(path)
    except BaseException:
        temp.unlink(missing_ok=True)
        raise


def sha256_file(path: Path, *, chunk_size: int = 1024 * 1024) -> str:
    dig = hashlib.sha256()
    with path.open("rb") as fp:
        for buf in iter(lambda: fp.read(chunk_size), b""):
            dig.update(buf)
    return dig.hexdigest()


def classify_file(path: Path) -> dict[str, str]:
    with path.open("rb") as fp:
        head = fp.read(512)
    prefix = head[:32]
    kinds: list[tuple[bool, str, str]] = [
        (prefix.startswith(b"SQLite format 3\x00"), "sqlite", "SQLite 3 header"),
        (prefix.startswith(b"ElfFile\x00"), "evtx", "Windows EVTX header"),
        (prefix.startswith(b"regf"), "registry-hive", "Windows Registry hive header"),
        (len(prefix) >= 8 and prefix[4:8] == b"SCCA", "prefetch", "Windows Prefetch signature"),
        (prefix[:4] in (b"MAM\x04", b"MAM\x84"), "compressed-prefetch-candidate", "MAM compression header; decoder required"),
        (prefix.startswith(b"\x0a\x0d\x0d\x0a"), "pcapng", "PCAPNG section header"),
        (prefix.startswith((b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")), "pcap", "PCAP global header"),
        (prefix.startswith(b"EVF\x09\x0d\x0a\xff\x00"), "ewf-e01-candidate", "EWF segment signature"),
        (prefix.startswith(b"PK\x03\x04"), "zip", "ZIP local header"),
        (prefix.startswith(b"Rar!\x1a\x07"), "rar", "RAR archive header"),
        (prefix.startswith(b"7z\xbc\xaf\x27\x1c"), "7z", "7-Zip archive header"),
        (prefix.startswith(b"%PDF-"), "pdf", "PDF header"),
        (prefix.startswith(b"\x89PNG\r\n\x1a\n"), "png", "PNG header"),
        (prefix.startswith(b"\xff\xd8\xff"), "jpeg", "JPEG header"),
        (prefix.startswith((b"GIF87a", b"GIF89a")), "gif", "GIF header"),
        (prefix.startswith(b"RIFF") and head[8:12] == b"WAVE", "wav", "WAV RIFF header"),
        (prefix.startswith(b"MZ"), "pe-candidate", "DOS/PE MZ header; PE signature not yet verified"),
        (prefix.startswith(b"\x7fELF"), "elf", "ELF header"),
        (prefix.startswith(b"\x1f\x8b"), "gzip", "GZIP header"),
        (prefix.startswith(b"BZh"), "bzip2", "BZIP2 header"),
        (prefix.startswith(b"\xfd7zXZ\x00"), "xz", "XZ header"),
    ]
    for yes, name, why in kinds:
        if yes:
            return {"type": name, "basis": why, "confidence": "signature"}
    name = path.name.lower()
    suffixes = (".raw", ".dd", ".img", ".mem", ".dmp", ".bin")
    if name.endswith(suffixes):
        return {"type": "unidentified-binary", "basis": "Filename suggests a possible raw/dump artifact; not verified", "confidence": "unknown"}
    return {"type": "unknown", "basis": "No matching known header; inspect manually", "confidence": "unknown"}


def iter_evidence(root: Path, max_files: int) -> tuple[list[tuple[str, Path]], list[dict[str, str]]]:
    if root.is_symlink():
        raise ForensicError("Evidence path is a symbolic link; provide original path explicitly")
    if root.is_file():
        return [(root.name, root)], []
    if not root.is_dir():
        raise ForensicError(f"Evidence does not exist: {root}")
    out = []
    skipped: list[dict[str, str]] = []
    for dirpath, dirs, files in os.walk(root, topdown=True, followlinks=False):
        kept_dirs = []
        for d in sorted(dirs):
            if (Path(dirpath) / d).is_symlink():
                skipped.append({"relative_path": str((Path(dirpath) / d).relative_to(root)), "reason": "symlink-directory-not-followed"})
            else:
                kept_dirs.append(d)
        dirs[:] = kept_dirs
        for filename in sorted(files):
            p = Path(dirpath) / filename
            if p.is_symlink():
                skipped.append({"relative_path": str(p.relative_to(root)), "reason": "symlink-file-not-followed"})
                continue
            if not stat.S_ISREG(p.lstat().st_mode):
                skipped.append({"relative_path": str(p.relative_to(root)), "reason": "non-regular-file"})
                continue
            out.append((str(p.relative_to(root)), p))
            if len(out) > max_files:
                raise ForensicError(f"More than {max_files} files; intake stopped rather than silently truncate")
    if not out:
        raise ForensicError("No regular non-symlink files found; no manifest created")
    return out, skipped


def create_case(evidence: Path, case_dir: Path, *, max_files: int = 10000) -> dict[str, Any]:
    if evidence.is_symlink():
        raise ForensicError("Evidence root is a symbolic link; use its explicit real path")
    evidence = evidence.resolve(strict=True)
    case_dir = case_dir.resolve(strict=False)
    if case_dir == evidence or evidence in case_dir.parents or case_dir in evidence.parents:
        raise ForensicError("Case output must be outside the original evidence directory/tree")
    if case_dir.exists():
        raise ForensicError(f"Case destination already exists; refusing overwrite: {case_dir}")
    files, skipped_paths = iter_evidence(evidence, max_files)
    entries = []
    for relative, path in files:
        before = path.stat()
        digest = sha256_file(path)
        after = path.stat()
        if (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
            raise ForensicError(f"Evidence changed during hashing: {path}")
        entries.append({
            "relative_path": relative,
            "size_bytes": before.st_size,
            "sha256": digest,
            "mtime_utc_observed": datetime.fromtimestamp(before.st_mtime, timezone.utc).isoformat(),
            "classification": classify_file(path),
        })
    payload = {
        "schema": "nexsec-forensics-case-v1",
        "captured_at_utc": utc_now(),
        "original_evidence_path": str(evidence),
        "preservation_note": "No original file was written by this tool. Original mtime is metadata, not an event attribution.",
        "source_is_directory": evidence.is_dir(),
        "artifacts": entries,
        "skipped_paths": skipped_paths,
        "completeness_warning": "Some paths were skipped; review skipped_paths and original directory inventory" if skipped_paths else "All discovered regular files were hashed",
    }
    case_dir.mkdir(mode=0o700, parents=True)
    (case_dir / "reports").mkdir(mode=0o700)
    write_json(case_dir / "manifest.json", payload)
    return payload


def read_case(case_dir: Path) -> dict[str, Any]:
    manifest = case_dir / "manifest.json"
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, ValueError) as err:
        raise ForensicError(f"Cannot read case manifest: {err}") from err
    if data.get("schema") != "nexsec-forensics-case-v1":
        raise ForensicError("Unsupported manifest schema")
    return data


def verify_case(case_dir: Path) -> dict[str, Any]:
    doc = read_case(case_dir)
    root = Path(doc["original_evidence_path"])
    rows = []
    for item in doc["artifacts"]:
        target = root / item["relative_path"] if doc["source_is_directory"] else root
        status = "UNCHANGED"
        detail = ""
        if target.is_symlink():
            status, detail = "UNVERIFIABLE", "Path is now a symbolic link"
        elif not target.is_file():
            status, detail = "MISSING", "Original not found"
        else:
            try:
                fresh = sha256_file(target)
                if fresh != item["sha256"]:
                    status, detail = "CHANGED", "SHA-256 differs from original intake"
                elif target.stat().st_size != item["size_bytes"]:
                    status, detail = "CHANGED", "Size differs from intake"
            except OSError as err:
                status, detail = "UNVERIFIABLE", str(err)
        rows.append({"relative_path": item["relative_path"], "status": status, "detail": detail})
    result = {"verified_at_utc": utc_now(), "source_manifest": "manifest.json", "results": rows,
              "passed": all(x["status"] == "UNCHANGED" for x in rows)}
    write_json(case_dir / "reports" / ("integrity-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + ".json"), result)
    return result
