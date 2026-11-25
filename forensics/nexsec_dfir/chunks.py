"""Validate and reassemble bounded Base64 chunks from parsed JSON/HTTP records."""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
from pathlib import Path

from .core import ForensicError
from .windows_exports import iter_export
from .external import sha256_file


def _record_payload(row: dict, container_field: str | None) -> dict:
    if container_field:
        raw = row.get(container_field)
        if isinstance(raw, str):
            try:
                payload = json.loads(raw)
            except ValueError as exc:
                raise ForensicError(f"JSON payload field {container_field} is invalid JSON") from exc
            if isinstance(payload, dict):
                return {**payload, **row}
        if isinstance(raw, dict):
            return {**raw, **row}
        raise ForensicError(f"Field {container_field} does not contain a JSON object")
    for field in ("json", "payload", "body"):
        raw = row.get(field)
        if isinstance(raw, str) and raw.lstrip().startswith("{"):
            try:
                payload = json.loads(raw)
            except ValueError:
                continue
            if isinstance(payload, dict) and {"job", "part", "total", "data"}.issubset(payload):
                return {**payload, **row}
    return row


def reassemble_chunks(source: Path, output: Path, *, job: str | None = None,
                      job_field: str = "job", part_field: str = "part",
                      total_field: str = "total", data_field: str = "data",
                      container_field: str | None = None, frame_field: str = "frame.number",
                      stream_field: str = "tcp.stream", index_base: int | None = None,
                      expected_size: int | None = None, expected_sha256: str | None = None,
                      max_bytes: int = 100_000_000, max_records: int = 500_000) -> dict:
    source, output = Path(source), Path(output)
    if not source.is_file() or source.is_symlink():
        raise ForensicError(f"Chunk source not found or is a symlink: {source}")
    if output.exists() or output.is_symlink():
        raise ForensicError(f"Refusing to overwrite existing output: {output}")
    source = source.resolve()
    if source.parent in output.resolve().parents or output.resolve() == source:
        raise ForensicError("Reassembled output must be outside the evidence source directory")
    if max_bytes < 1 or max_records < 1:
        raise ForensicError("max-bytes and max-records must be positive")
    if index_base not in (None, 0, 1):
        raise ForensicError("index-base must be 0 or 1")
    if expected_size is not None and expected_size < 0:
        raise ForensicError("expected-size must be non-negative")
    if expected_sha256 and (len(expected_sha256) != 64 or any(ch not in "0123456789abcdefABCDEF" for ch in expected_sha256)):
        raise ForensicError("expected-sha256 must contain exactly 64 hexadecimal characters")
    source_hash = sha256_file(source)
    jobs: dict[str, dict] = {}
    for row_number, source_row in iter_export(source, max_records=max_records):
        row = _record_payload(source_row, container_field)
        if job is not None and str(row.get(job_field, "")) != job:
            continue
        job_id = str(row.get(job_field, "")).strip()
        if not job_id:
            continue
        try:
            part, total = int(row[part_field]), int(row[total_field])
        except (KeyError, TypeError, ValueError) as exc:
            raise ForensicError(f"Chunk source row {row_number} has invalid part/total") from exc
        if total < 1 or part < 0:
            raise ForensicError(f"Chunk source row {row_number} has out-of-range part/total")
        encoded = row.get(data_field)
        if not isinstance(encoded, str) or not encoded:
            raise ForensicError(f"Chunk source row {row_number} has empty or missing Base64 data")
        try:
            compact = "".join(encoded.split())
            if len(compact) % 4 == 1:
                raise ValueError("invalid Base64 length")
            chunk = base64.b64decode(compact + "=" * ((-len(compact)) % 4), altchars=b"-_", validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ForensicError(f"Invalid Base64 chunk at source row {row_number}: {exc}") from exc
        group = jobs.setdefault(job_id, {"total": total, "parts": {}, "size": 0,
                                         "references": [], "duplicates": []})
        if group["total"] != total:
            raise ForensicError(f"Conflicting total values for job {job_id}")
        prior = group["parts"].get(part)
        if prior is not None and prior != chunk:
            raise ForensicError(f"Conflicting duplicate chunk for job {job_id}, part {part}")
        ref = {"source_artifact": str(source), "source_sha256": source_hash, "source_row": row_number,
               "frame_number": row.get(frame_field), "tcp_stream": row.get(stream_field)}
        if prior is not None:
            group["duplicates"].append({"part": part, "source_reference": ref})
        else:
            group["parts"][part] = chunk
            group["size"] += len(chunk)
            group["references"].append(part)
            group.setdefault("part_references", {}).setdefault(part, []).append(ref)
        if group["size"] > max_bytes:
            raise ForensicError(f"Reassembled job exceeds max-bytes={max_bytes}")
    if sha256_file(source) != source_hash:
        raise ForensicError("Chunk source changed while being read")
    if not jobs:
        raise ForensicError("No matching chunk records found")
    if job is None and len(jobs) != 1:
        raise ForensicError("Multiple job IDs found; select one with --job")
    job_id = job if job is not None else next(iter(jobs))
    if job_id not in jobs:
        raise ForensicError(f"No chunks found for job {job_id}")
    group = jobs[job_id]
    base = index_base if index_base is not None else (0 if 0 in group["parts"] else 1)
    expected_parts = set(range(base, base + group["total"]))
    unexpected = sorted(set(group["parts"]) - expected_parts)
    if unexpected:
        raise ForensicError(f"Chunk part numbers outside expected range for job {job_id}: {unexpected}")
    missing = sorted(expected_parts - set(group["parts"]))
    if missing:
        raise ForensicError(f"Missing chunks for job {job_id}: {missing}")
    payload = b"".join(group["parts"][part] for part in sorted(expected_parts))
    digest = hashlib.sha256(payload).hexdigest()
    if expected_size is not None and len(payload) != expected_size:
        raise ForensicError(f"Reconstructed size mismatch: expected {expected_size}, got {len(payload)}")
    if expected_sha256 and digest.casefold() != expected_sha256.casefold():
        raise ForensicError("Reconstructed SHA-256 does not match expected value")
    if sha256_file(source) != source_hash:
        raise ForensicError("Chunk source changed before output write")
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists() or output.is_symlink():
        raise ForensicError(f"Output appeared during analysis; refusing overwrite: {output}")
    with output.open("xb") as fp:
        fp.write(payload)
    return {"job": job_id, "output_path": str(output.resolve()), "part_count": group["total"],
            "index_base": base, "duplicate_parts": group["duplicates"], "size_bytes": len(payload),
            "sha256": digest, "expected_size_verified": expected_size is not None,
            "expected_sha256_verified": expected_sha256 is not None,
            "source_artifact": str(source), "source_sha256": source_hash,
            "part_references": group.get("part_references", {}),
            "note": "Complete Base64 chunks were ordered and verified. Transfer context does not alone prove successful exfiltration."}
