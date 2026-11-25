"""Offline, allowlisted Volatility 3 subprocess adapter."""
from __future__ import annotations

import json
import shutil
from pathlib import Path

from .core import ForensicError
from .external import evidence_identity, run_bounded, verify_source_unchanged

PLUGINS = {
    "windows-processes": "windows.pslist",
    "windows-tree": "windows.pstree",
    "windows-command-line": "windows.cmdline",
    "windows-network": "windows.netscan",
    "windows-modules": "windows.dlllist",
    "windows-malfind": "windows.malfind",
    "linux-processes": "linux.pslist",
    "linux-tree": "linux.pstree",
    "linux-command-line": "linux.psaux",
    "linux-network": "linux.sockstat",
    "linux-modules": "linux.lsmod",
    "linux-module-check": "linux.check_modules",
}


def analyze_memory(path: Path, workflow: str, *, timeout_seconds: int = 300,
                   max_output: int = 4_000_000) -> dict:
    if workflow not in PLUGINS:
        raise ForensicError(f"Unsupported workflow: {workflow}")
    if timeout_seconds <= 0 or max_output < 1024:
        raise ForensicError("timeout must be positive and max-output must be at least 1024 bytes")
    path = Path(path)
    if not path.is_file() or path.is_symlink():
        raise ForensicError(f"Memory image not found or is a symlink: {path}")
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
    args = [executable, "--offline", "-r", "json", "-f", str(path), plugin]
    try:
        result, output_truncated = run_bounded(args, timeout=timeout_seconds, max_output=max_output)
    except ForensicError as exc:
        verify_source_unchanged(path, identity)
        if "timed out" in str(exc):
            raise ForensicError(f"Volatility 3 {plugin} timed out after {timeout_seconds}s") from exc
        raise
    stdout = result.stdout[:max_output].decode("utf-8", "replace")
    stderr = result.stderr[:max_output].decode("utf-8", "replace")
    if result.returncode and not output_truncated:
        verify_source_unchanged(path, identity)
        msg = stderr[-1200:]
        if "symbol" in msg.casefold() or "isf" in msg.casefold():
            reason = "symbol table unavailable or incompatible"
        elif "plugin" in msg.casefold() and ("not found" in msg.casefold() or "unable" in msg.casefold()):
            reason = "plugin unavailable in this Volatility version"
        else:
            reason = "plugin failed; image/profile may be unsupported or corrupt"
        raise ForensicError(f"Volatility 3 {plugin}: {reason}. {msg}")
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
    verify_source_unchanged(path, identity)
    return {**identity, "tool": executable, "tool_version": tool_version, "plugin": plugin,
            "workflow": workflow, "records": records,
            "raw_output": None if records is not None else stdout,
            "stderr": stderr, "output_truncated": output_truncated,
            "limitations": ["Plugin output reflects this image and local symbol availability.",
                            "Process/module presence is an observation, not a malware verdict.",
                            "Offline mode prevents remote symbol retrieval; absent symbols can make analysis unavailable."]}
