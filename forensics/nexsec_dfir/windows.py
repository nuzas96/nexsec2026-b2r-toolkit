"""Windows-only adapters for Eric Zimmerman CSV-producing parsers."""
from __future__ import annotations

import csv
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from .core import ForensicError
from .external import evidence_identity, verify_source_unchanged

TOOLS = {
    "evtx": ("EvtxECmd", "EvtxECmd.exe", "-f"),
    "prefetch": ("PECmd", "PECmd.exe", "-f"),
    "mft": ("MFTECmd", "MFTECmd.exe", "-f"),
}
RECORD_KEYS = ("EventRecordId", "RecordId", "EntryNumber", "MFTEntryNumber", "Record Number")
TIME_KEYS = ("TimeCreated", "LastRun", "LastRunTime", "Created0x10", "LastModified0x10")


def is_windows_host() -> bool:
    return os.name == "nt"


def analyze_windows(path: Path, kind: str, *, timeout_seconds: int = 300,
                    max_rows: int = 100_000) -> dict:
    if not is_windows_host():
        raise ForensicError("Windows artifact parsers require Windows; this host is unsupported")
    if kind not in TOOLS:
        raise ForensicError("Supported parser kinds: evtx, prefetch, mft")
    if timeout_seconds <= 0 or not 1 <= max_rows <= 1_000_000:
        raise ForensicError("timeout must be positive and max-rows must be in range 1..1000000")
    path = Path(path)
    if not path.is_file() or path.is_symlink():
        raise ForensicError(f"Artifact not found or is a symlink: {path}")
    name, executable, input_flag = TOOLS[kind]
    tool = shutil.which(executable) or shutil.which(name)
    if not tool:
        raise ForensicError(f"{executable} unavailable; install the matching Eric Zimmerman parser")
    identity = evidence_identity(path)
    with tempfile.TemporaryDirectory(prefix="nexsec-windows-") as temp:
        outdir = Path(temp) / "csv"
        outdir.mkdir()
        args = [tool, input_flag, str(path.resolve()), "--csv", str(outdir)]
        try:
            proc = subprocess.run(args, capture_output=True, timeout=timeout_seconds, check=False)
        except subprocess.TimeoutExpired as exc:
            verify_source_unchanged(path, identity)
            raise ForensicError(f"{executable} timed out after {timeout_seconds}s; results incomplete") from exc
        stderr = proc.stderr.decode("utf-8", "replace")[-1500:]
        if proc.returncode:
            verify_source_unchanged(path, identity)
            raise ForensicError(f"{executable} exited {proc.returncode}: {stderr}")
        exports = sorted(p for p in outdir.rglob("*.csv") if p.is_file())
        if not exports:
            verify_source_unchanged(path, identity)
            raise ForensicError(f"{executable} succeeded but produced no CSV export")
        records, source_exports, truncated = [], [], False
        for export in exports:
            source_exports.append(export.name)
            with export.open("r", encoding="utf-8-sig", newline="") as fp:
                reader = csv.DictReader(fp)
                if not reader.fieldnames:
                    continue
                for row_number, row in enumerate(reader, 2):
                    if len(records) >= max_rows:
                        truncated = True
                        break
                    record_id = next((row.get(k) for k in RECORD_KEYS if row.get(k)), None)
                    timestamp = next((row.get(k) for k in TIME_KEYS if row.get(k)), None)
                    records.append({"source_artifact": str(path.resolve()),
                                    "parser_export": export.name, "source_row": row_number,
                                    "record_id": record_id, "timestamp_raw": timestamp,
                                    "observed_value": row,
                                    "limitations": "Parser CSV field meanings and timezone depend on parser version and artifact; verify raw source record."})
            if truncated:
                break
    verify_source_unchanged(path, identity)
    return {**identity, "tool": executable, "artifact_type": kind,
            "records": records, "records_returned": len(records), "max_rows": max_rows,
            "truncated": truncated, "parser_exports": source_exports,
            "tool_stderr": stderr,
            "note": "Rows are observations from the installed parser. No execution, persistence, or user attribution conclusion is made automatically."}
