"""Read-only Sleuth Kit/libewf workflows for forensic images."""
from __future__ import annotations

import hashlib
import shutil
import subprocess
import threading
from pathlib import Path

from .core import ForensicError
from .external import evidence_identity, run_bounded, verify_source_unchanged


def _run(tool: str, args: list[str], timeout: int, source: Path, identity: dict) -> dict:
    executable = shutil.which(tool)
    if not executable:
        raise ForensicError(f"Required tool unavailable: {tool}")
    try:
        proc, truncated = run_bounded([executable, *args], timeout=timeout, max_output=4_000_000)
    except ForensicError as exc:
        verify_source_unchanged(source, identity)
        if "timed out" in str(exc):
            raise ForensicError(f"{tool} timed out after {timeout}s; output incomplete") from exc
        raise
    stdout = proc.stdout[:4_000_000].decode("utf-8", "replace")
    stderr = proc.stderr[:1500].decode("utf-8", "replace")
    if proc.returncode and not truncated:
        verify_source_unchanged(source, identity)
        raise ForensicError(f"{tool} exited {proc.returncode}: {stderr}")
    return {"tool": tool, "output": stdout, "stderr": stderr,
            "output_truncated": truncated}


def analyze_disk(path: Path, action: str, *, offset: int = 0,
                 sector_size: int | None = None, inode: str | None = None,
                 filesystem: str | None = None,
                 output: Path | None = None, max_bytes: int = 50_000_000,
                 timeout_seconds: int = 300) -> dict:
    path = Path(path)
    if not path.is_file() or path.is_symlink():
        raise ForensicError(f"Disk image not found or is a symlink: {path}")
    if offset < 0 or (sector_size is not None and sector_size not in (512, 1024, 2048, 4096)):
        raise ForensicError("Offset must be non-negative sectors; sector size must be 512, 1024, 2048, or 4096")
    if timeout_seconds <= 0:
        raise ForensicError("timeout must be positive")
    identity = evidence_identity(path)
    if action == "ewf-info":
        result = _run("ewfinfo", [str(path)], timeout_seconds, path, identity)
    elif action == "partitions":
        args = (["-b", str(sector_size)] if sector_size else []) + [str(path)]
        result = _run("mmls", args, timeout_seconds, path, identity)
    elif action == "filesystem":
        args = (["-f", filesystem] if filesystem else []) + ["-o", str(offset), str(path)]
        result = _run("fsstat", args, timeout_seconds, path, identity)
    elif action == "files":
        args = ["-r", "-p"] + (["-f", filesystem] if filesystem else []) + ["-o", str(offset), str(path)]
        result = _run("fls", args, timeout_seconds, path, identity)
    elif action == "extract":
        if not inode or output is None:
            raise ForensicError("extract requires --inode and --output")
        if not 1 <= max_bytes <= 1_000_000_000:
            raise ForensicError("max-bytes must be in range 1..1000000000")
        output = Path(output)
        if output.exists() or output.resolve() == path.resolve():
            raise ForensicError("Extraction output exists or points to the evidence; refusing overwrite")
        if path.resolve().parent in output.resolve().parents:
            raise ForensicError("Extraction output must be outside the source evidence directory")
        executable = shutil.which("icat")
        if not executable:
            raise ForensicError("Required tool unavailable: icat")
        cmd = [executable]
        if filesystem:
            cmd.extend(["-f", filesystem])
        cmd.extend(["-o", str(offset), str(path), str(inode)])
        digest, digest_sha1, count = hashlib.sha256(), hashlib.sha1(), 0
        output.parent.mkdir(parents=True, exist_ok=True)
        try:
            with output.open("xb") as fp:
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
                assert proc.stdout is not None
                exceeded = threading.Event()
                def copy_limited():
                    nonlocal count
                    while True:
                        chunk = proc.stdout.read(1024 * 1024)
                        if not chunk:
                            return
                        if count + len(chunk) > max_bytes:
                            exceeded.set()
                            proc.kill()
                            return
                        fp.write(chunk)
                        digest.update(chunk)
                        digest_sha1.update(chunk)
                        count += len(chunk)
                reader = threading.Thread(target=copy_limited, daemon=True)
                reader.start()
                try:
                    code = proc.wait(timeout=timeout_seconds)
                except subprocess.TimeoutExpired as exc:
                    proc.kill()
                    proc.wait()
                    reader.join(timeout=5)
                    raise ForensicError(f"icat timed out after {timeout_seconds}s; partial output removed") from exc
                reader.join(timeout=5)
                if reader.is_alive():
                    proc.kill()
                    raise ForensicError("icat output reader did not stop; partial output removed")
                if exceeded.is_set():
                    raise ForensicError(f"Extracted data exceeded --max-bytes={max_bytes}; partial output removed")
                if code:
                    raise ForensicError(f"icat exited {code}")
        except BaseException:
            verify_source_unchanged(path, identity)
            output.unlink(missing_ok=True)
            raise
        result = {"tool": "icat", "output_path": str(output.resolve()), "size_bytes": count,
                  "sha1": digest_sha1.hexdigest(), "sha256": digest.hexdigest()}
    else:
        raise ForensicError("action must be partitions, filesystem, files, ewf-info, or extract")
    verify_source_unchanged(path, identity)
    return {**identity, "action": action, "sector_offset": offset,
            "sector_size_bytes": sector_size, **result,
            "note": "Source image is opened as input only. Offsets are sectors, not bytes; validate the partition/filesystem and sector size before interpreting results."}
