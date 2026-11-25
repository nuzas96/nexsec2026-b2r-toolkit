"""Offline read-only VHD inspection and conversion through qemu-img."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from pathlib import Path

from .core import ForensicError
from .external import evidence_identity, run_bounded, verify_source_unchanged


def convert_vhd(source: Path, output: Path, *, max_output_bytes: int = 2_000_000_000,
                timeout_seconds: int = 1800) -> dict:
    source, output = Path(source), Path(output)
    if not source.is_file() or source.is_symlink():
        raise ForensicError(f"VHD source not found or is a symlink: {source}")
    if output.exists() or output.is_symlink():
        raise ForensicError(f"Refusing to overwrite conversion output: {output}")
    source = source.resolve()
    if source.parent in output.resolve().parents:
        raise ForensicError("Converted image must be written outside the source evidence directory")
    if max_output_bytes < 1 or timeout_seconds < 1:
        raise ForensicError("max-output-bytes and timeout must be positive")
    qemu = shutil.which("qemu-img")
    if not qemu:
        raise ForensicError("qemu-img unavailable; VHD conversion is unsupported on this host")
    identity = evidence_identity(source)
    try:
        info_result, info_truncated = run_bounded([qemu, "info", "--output=json", str(source)],
                                                  timeout=min(timeout_seconds, 60), max_output=65536)
    except ForensicError as exc:
        verify_source_unchanged(source, identity)
        raise ForensicError(f"qemu-img could not inspect the input format: {exc}") from exc
    if info_result.returncode or info_truncated:
        verify_source_unchanged(source, identity)
        raise ForensicError("qemu-img info failed or exceeded its output cap; input format is unsupported or malformed")
    try:
        info = json.loads(info_result.stdout)
    except (ValueError, TypeError) as exc:
        verify_source_unchanged(source, identity)
        raise ForensicError("qemu-img returned invalid info JSON") from exc
    if info.get("format") != "vpc":
        raise ForensicError(f"Unsupported image format {info.get('format')!r}; only VHD (QEMU vpc) conversion is enabled")
    if info.get("backing-filename"):
        raise ForensicError("VHD reports a backing file; conversion is refused to avoid reading untracked evidence")
    virtual_size = info.get("virtual-size")
    if not isinstance(virtual_size, int) or virtual_size <= 0:
        raise ForensicError("qemu-img did not provide a valid virtual-size")
    if virtual_size > max_output_bytes:
        raise ForensicError(f"Virtual image size {virtual_size} exceeds max-output-bytes={max_output_bytes}")
    output.parent.mkdir(parents=True, exist_ok=True)
    linked = False
    try:
        with tempfile.TemporaryDirectory(prefix="nexsec-vhd-", dir=output.parent) as work:
            converted = Path(work) / "converted.raw"
            result, truncated = run_bounded([qemu, "convert", "-f", "vpc", "-O", "raw", str(source), str(converted)],
                                            timeout=timeout_seconds, max_output=65536)
            if result.returncode or truncated or not converted.is_file():
                verify_source_unchanged(source, identity)
                detail = result.stderr.decode("utf-8", "replace")[-1000:]
                raise ForensicError(f"qemu-img conversion failed or was truncated: {detail}")
            size = converted.stat().st_size
            if size > max_output_bytes:
                raise ForensicError(f"Converted output exceeded max-output-bytes={max_output_bytes}")
            sha = hashlib.sha256()
            with converted.open("rb") as fp:
                for chunk in iter(lambda: fp.read(1024 * 1024), b""):
                    sha.update(chunk)
            verify_source_unchanged(source, identity)
            try:
                os.link(converted, output)
            except FileExistsError as exc:
                raise ForensicError(f"Output appeared during conversion; refusing overwrite: {output}") from exc
            linked = True
            verify_source_unchanged(source, identity)
            return {**identity, "tool": qemu, "input_format": "vpc", "output_format": "raw",
                    "virtual_size_bytes": virtual_size, "output_path": str(output.resolve()),
                    "output_size_bytes": size, "output_sha256": sha.hexdigest(),
                    "note": "qemu-img converted a copy to a new raw output. Source image was hash-checked before and after; the output is not mounted or executed."}
    except BaseException:
        verify_source_unchanged(source, identity)
        if linked:
            output.unlink(missing_ok=True)
        raise
