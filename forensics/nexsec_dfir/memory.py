"""Offline, allowlisted Volatility 3 subprocess adapter."""
from __future__ import annotations

import json
import hashlib
import shutil
import tempfile
from pathlib import Path

from .core import ForensicError
from .external import evidence_identity, run_bounded, verify_source_unchanged

PLUGINS = {
    "windows-processes": "windows.pslist",
    "windows-scan-processes": "windows.psscan",
    "windows-tree": "windows.pstree",
    "windows-command-line": "windows.cmdline",
    "windows-network": "windows.netscan",
    "windows-modules": "windows.dlllist",
    "windows-malfind": "windows.malfind",
    "windows-file-scan": "windows.filescan",
    "windows-dumpfiles": "windows.dumpfiles",
    "windows-registry-hives": "windows.registry.hivelist",
    "windows-registry-key": "windows.registry.printkey",
    "linux-processes": "linux.pslist",
    "linux-tree": "linux.pstree",
    "linux-command-line": "linux.psaux",
    "linux-network": "linux.sockstat",
    "linux-modules": "linux.lsmod",
    "linux-module-check": "linux.check_modules",
}


def analyze_memory(path: Path, workflow: str, *, timeout_seconds: int = 300,
                   max_output: int = 4_000_000, registry_key: str | None = None,
                   dump_dir: Path | None = None, max_dump_bytes: int = 100_000_000,
                   pid: int | None = None, dump_filter: str | None = None) -> dict:
    if workflow not in PLUGINS:
        raise ForensicError(f"Unsupported workflow: {workflow}")
    if timeout_seconds <= 0 or max_output < 1024:
        raise ForensicError("timeout must be positive and max-output must be at least 1024 bytes")
    path = Path(path)
    if not path.is_file() or path.is_symlink():
        raise ForensicError(f"Memory image not found or is a symlink: {path}")
    if workflow == "windows-registry-key" and not registry_key:
        raise ForensicError("windows-registry-key requires --registry-key")
    if workflow == "windows-dumpfiles":
        if dump_dir is None:
            raise ForensicError("windows-dumpfiles requires a new --dump-dir")
        dump_dir = Path(dump_dir)
        if dump_dir.exists() or dump_dir.is_symlink():
            raise ForensicError(f"Refusing to reuse dump directory: {dump_dir}")
        if path.resolve().parent in dump_dir.resolve().parents:
            raise ForensicError("Dump directory must be outside the memory evidence directory")
        if not 1 <= max_dump_bytes <= 2_000_000_000:
            raise ForensicError("max-dump-bytes must be in range 1..2000000000")
    executable = shutil.which("vol") or shutil.which("volatility3")
    if not executable:
        raise ForensicError("Volatility 3 unavailable (expected 'vol' or 'volatility3')")
    plugin = PLUGINS[workflow]
    identity = evidence_identity(path)
    tool_version = "unknown"
    try:
        version_result, version_truncated = run_bounded([executable, "--version"], timeout=10, max_output=4096)
        if version_result.returncode == 0 and not version_truncated:
            tool_version = version_result.stdout.decode("utf-8", "replace").strip() or "unknown"
    except ForensicError:
        pass
    with tempfile.TemporaryDirectory(prefix="nexsec-vol-") as temp:
        args = [executable, "--offline", "-r", "json", "-f", str(path)]
        if workflow == "windows-dumpfiles":
            args.extend(["-o", temp])
        args.append(plugin)
        if workflow == "windows-dumpfiles":
            if pid is not None:
                if pid < 0:
                    raise ForensicError("pid must be non-negative")
                args.extend(["--pid", str(pid)])
            if dump_filter:
                args.extend(["--filter", dump_filter])
        if workflow == "windows-registry-key":
            args.extend(["--key", registry_key])
        try:
            result, output_truncated = run_bounded(args, timeout=timeout_seconds, max_output=max_output,
                watch_directory=Path(temp) if workflow == "windows-dumpfiles" else None,
                max_directory_bytes=max_dump_bytes if workflow == "windows-dumpfiles" else None)
        except ForensicError as exc:
            verify_source_unchanged(path, identity)
            if "timed out" in str(exc):
                raise ForensicError(f"Volatility 3 {plugin} timed out after {timeout_seconds}s") from exc
            raise
        report = _format_result(result, output_truncated, max_output)
        if result.returncode and not output_truncated:
            verify_source_unchanged(path, identity)
            msg = report["stderr"][-1200:]
            if "symbol" in msg.casefold() or "isf" in msg.casefold():
                reason = "symbol table unavailable or incompatible"
            elif "plugin" in msg.casefold() and ("not found" in msg.casefold() or "unable" in msg.casefold()):
                reason = "plugin unavailable in this Volatility version"
            else:
                reason = "plugin failed; image/profile may be unsupported or corrupt"
            raise ForensicError(f"Volatility 3 {plugin}: {reason}. {msg}")
        if workflow == "windows-dumpfiles" and not output_truncated:
            report["dumped_files"] = _copy_dumps(Path(temp), dump_dir, max_dump_bytes)
        elif workflow == "windows-dumpfiles":
            report["dumped_files"] = []
            report["dump_files_skipped_reason"] = "The tool output or dump directory reached its configured cap; no partial dump files were copied."
    verify_source_unchanged(path, identity)
    return {**identity, "tool": executable, "tool_version": tool_version, "plugin": plugin,
            "workflow": workflow, **report,
            "limitations": ["Plugin output reflects this image and local symbol availability.",
                            "Process/module presence is an observation, not a malware verdict.",
                            "Offline mode prevents remote symbol retrieval; absent symbols can make analysis unavailable.",
                            "Dumped files are untrusted data and are never executed."]}


def _format_result(result, output_truncated: bool, max_output: int) -> dict:
    stdout = result.stdout[:max_output].decode("utf-8", "replace")
    stderr = result.stderr[:max_output].decode("utf-8", "replace")
    try:
        if output_truncated:
            raise json.JSONDecodeError("output cap reached", stdout, len(stdout))
        records = json.loads(stdout)
        if isinstance(records, dict):
            records = [records]
        if not isinstance(records, list):
            records = None
    except json.JSONDecodeError:
        records = None
    return {"records": records,
            "raw_output": None if records is not None else stdout,
            "stderr": stderr, "output_truncated": output_truncated}


def _copy_dumps(temp: Path, destination: Path, max_dump_bytes: int) -> list[dict]:
    files = sorted(path for path in temp.rglob("*") if path.is_file())
    if any(path.is_symlink() for path in temp.rglob("*")):
        raise ForensicError("Volatility dump output included a symbolic link; refusing to copy")
    total = sum(path.stat().st_size for path in files)
    if total > max_dump_bytes:
        raise ForensicError(f"Volatility dumps total {total} bytes, exceeding max-dump-bytes={max_dump_bytes}")
    if not files:
        return []
    destination.mkdir(parents=True, mode=0o700)
    dumped = []
    try:
        for index, source in enumerate(files, 1):
            target = destination / f"dump-{index:04d}.bin"
            digest_sha1, digest_sha256 = hashlib.sha1(), hashlib.sha256()
            size = 0
            with source.open("rb") as src, target.open("xb") as dst:
                for chunk in iter(lambda: src.read(1024 * 1024), b""):
                    size += len(chunk)
                    digest_sha1.update(chunk)
                    digest_sha256.update(chunk)
                    dst.write(chunk)
            dumped.append({"output_path": str(target), "source_tool_filename": source.name,
                           "size_bytes": size, "sha1": digest_sha1.hexdigest(),
                           "sha256": digest_sha256.hexdigest()})
    except BaseException:
        shutil.rmtree(destination)
        raise
    return dumped
