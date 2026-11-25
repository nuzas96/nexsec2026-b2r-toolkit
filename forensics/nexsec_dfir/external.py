"""Shared bounded subprocess helpers for optional offline forensic tools."""
from __future__ import annotations

import subprocess
import threading
from pathlib import Path

from .core import ForensicError, sha256_file


def require_file(path: Path, label: str = "Evidence") -> Path:
    path = Path(path)
    if not path.is_file() or path.is_symlink():
        raise ForensicError(f"{label} file not found or is a symlink: {path}")
    return path.resolve()


def evidence_identity(path: Path) -> dict:
    path = require_file(path)
    return {"source_artifact": str(path), "source_sha256": sha256_file(path)}


def verify_source_unchanged(path: Path, identity: dict) -> None:
    if sha256_file(Path(path)) != identity["source_sha256"]:
        raise ForensicError("Evidence SHA-256 changed while analysis ran; stop and re-acquire/verify the source")


def run_bounded(args: list[str], *, timeout: int, max_output: int):
    """Capture bounded stdout/stderr; terminate the tool if either cap is exceeded."""
    if timeout <= 0 or max_output < 1:
        raise ForensicError("timeout and max_output must be positive")
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    truncated = threading.Event()

    def drain(name: str, stream):
        while True:
            chunk = stream.read(65536)
            if not chunk:
                return
            remaining = max_output - len(buffers[name])
            if len(chunk) > remaining:
                if remaining > 0:
                    buffers[name].extend(chunk[:remaining])
                truncated.set()
                proc.kill()
            elif remaining > 0:
                buffers[name].extend(chunk)

    readers = [threading.Thread(target=drain, args=(name, getattr(proc, name)), daemon=True)
               for name in ("stdout", "stderr")]
    for reader in readers:
        reader.start()
    try:
        returncode = proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        proc.kill()
        proc.wait()
        for reader in readers:
            reader.join(timeout=5)
        if proc.stdout:
            proc.stdout.close()
        if proc.stderr:
            proc.stderr.close()
        raise ForensicError(f"Subprocess timed out after {timeout}s") from exc
    for reader in readers:
        reader.join(timeout=5)
    if any(reader.is_alive() for reader in readers):
        proc.kill()
        raise ForensicError("Subprocess output reader did not stop")
    if proc.stdout:
        proc.stdout.close()
    if proc.stderr:
        proc.stderr.close()
    result = subprocess.CompletedProcess(args, returncode, bytes(buffers["stdout"]), bytes(buffers["stderr"]))
    return result, truncated.is_set()
