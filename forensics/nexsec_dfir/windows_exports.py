"""Traceable workflows over CSV/JSONL produced by trusted Windows parsers."""
from __future__ import annotations

import csv
import json
from pathlib import Path

from .core import ForensicError, sha256_file


def iter_export(path: Path, *, max_records: int):
    if not 1 <= max_records <= 1_000_000:
        raise ForensicError("max-records must be in range 1..1000000")
    if path.suffix.casefold() == ".csv":
        with path.open("r", encoding="utf-8-sig", newline="") as fp:
            reader = csv.DictReader(fp)
            if not reader.fieldnames or len(set(reader.fieldnames)) != len(reader.fieldnames):
                raise ForensicError("CSV has missing or duplicate header fields")
            for row_num, row in enumerate(reader, 2):
                if row_num - 1 > max_records:
                    raise ForensicError(f"Input exceeds max-records={max_records}")
                yield row_num, row
    elif path.suffix.casefold() == ".jsonl":
        with path.open("r", encoding="utf-8-sig") as fp:
            for row_num, line in enumerate(fp, 1):
                if not line.strip():
                    continue
                if row_num > max_records:
                    raise ForensicError(f"Input exceeds max-records={max_records}")
                try:
                    row = json.loads(line)
                except ValueError as exc:
                    raise ForensicError(f"Invalid JSONL row {row_num}: {exc}") from exc
                if not isinstance(row, dict):
                    raise ForensicError(f"JSONL row {row_num} is not an object")
                yield row_num, row
    else:
        raise ForensicError("Input must be a CSV or JSONL parser export")


def _source(path: Path) -> tuple[Path, str]:
    path = Path(path)
    if not path.is_file() or path.is_symlink():
        raise ForensicError(f"Parser export not found or is a symlink: {path}")
    return path.resolve(), sha256_file(path)


def reconstruct_scriptblocks(path: Path, *, id_field: str = "ScriptBlockId",
                             number_field: str = "MessageNumber", total_field: str = "MessageTotal",
                             text_field: str = "ScriptBlockText", event_field: str | None = "EventId",
                             event_id: str = "4104", record_field: str = "EventRecordId",
                             payload_field: str | None = "Payload",
                             max_records: int = 100_000, write_scripts: Path | None = None) -> dict:
    path, digest = _source(Path(path))
    groups: dict[str, dict] = {}
    for row_number, row in iter_export(path, max_records=max_records):
        if event_field and row.get(event_field) not in (None, "") and str(row.get(event_field)) != str(event_id):
            continue
        payload = {}
        if payload_field and row.get(payload_field) not in (None, ""):
            raw_payload = row[payload_field]
            if isinstance(raw_payload, str):
                try:
                    payload = json.loads(raw_payload)
                except ValueError as exc:
                    raise ForensicError(f"Unsupported parser schema at row {row_number}: {payload_field} is invalid JSON") from exc
            else:
                payload = raw_payload
            if not isinstance(payload, dict):
                raise ForensicError(f"Unsupported parser schema at row {row_number}: {payload_field} must be a JSON object")
        effective = {**payload, **row}
        mapped_fields = [id_field, number_field, total_field, text_field]
        if event_field:
            mapped_fields.append(event_field)
        mapped_fields.append(record_field)
        for field in mapped_fields:
            outer, inner = row.get(field), payload.get(field)
            if outer not in (None, "") and inner not in (None, "") and str(outer) != str(inner):
                raise ForensicError(f"Conflicting top-level/Payload values for field {field} at row {row_number}")
            if outer in (None, "") and inner not in (None, ""):
                effective[field] = inner
        if event_field and effective.get(event_field) in (None, ""):
            raise ForensicError(f"Unsupported parser schema: event field {event_field!r} is missing at row {row_number}")
        if event_field and str(effective.get(event_field)) != str(event_id):
            continue
        absent = [field for field in (id_field, number_field, total_field, text_field)
                  if effective.get(field) in (None, "")]
        if absent:
            raise ForensicError(
                "Unsupported parser schema for selected Event 4104 records: missing "
                + ", ".join(repr(field) for field in absent)
                + f"; expected mapped columns or fields inside {payload_field!r}"
            )
        if effective.get(record_field) in (None, ""):
            raise ForensicError(f"Unsupported parser schema: record identifier {record_field!r} is missing at row {row_number}")
        identifier = str(effective.get(id_field, "")).strip()
        if not identifier:
            continue
        try:
            number, total = int(effective[number_field]), int(effective[total_field])
        except (KeyError, TypeError, ValueError) as exc:
            raise ForensicError(f"Script block {identifier} row {row_number} has invalid part metadata") from exc
        text = effective.get(text_field)
        if not isinstance(text, str) or not text:
            raise ForensicError(f"Script block {identifier} row {row_number} has no text")
        if total < 1 or number < 1 or number > total:
            raise ForensicError(f"Script block {identifier} has out-of-range MessageNumber/MessageTotal")
        group = groups.setdefault(identifier, {"total": total, "parts": {}, "references": [], "conflicts": []})
        if group["total"] != total:
            group["conflicts"].append({"row": row_number, "reason": "MessageTotal disagrees"})
        ref = {"source_artifact": str(path), "source_sha256": digest, "source_row": row_number,
               "record_id": str(effective.get(record_field, "") or ""),
               "timestamp_raw": str(effective.get("TimeCreated", "") or ""),
               "frame_number": str(effective.get("frame.number", effective.get("frame_number", "")) or ""),
               "tcp_stream": str(effective.get("tcp.stream", effective.get("tcp_stream", "")) or "")}
        group["references"].append(ref)
        old = group["parts"].get(number)
        if old is None:
            group["parts"][number] = text
        elif old != text:
            group["conflicts"].append({"part": number, "row": row_number, "reason": "conflicting duplicate message"})
    if sha256_file(path) != digest:
        raise ForensicError("Parser export changed while being read")
    scripts = []
    for identifier, group in sorted(groups.items()):
        missing = [number for number in range(1, group["total"] + 1) if number not in group["parts"]]
        complete = not missing and not group["conflicts"]
        scripts.append({"script_block_id": identifier, "status": "complete" if complete else "incomplete-or-conflicting",
                        "message_total": group["total"], "received_parts": len(group["parts"]),
                        "missing_parts": missing, "conflicts": group["conflicts"],
                        "script_text": "".join(group["parts"][n] for n in range(1, group["total"] + 1)) if complete else None,
                        "source_references": group["references"]})
    if write_scripts is not None:
        write_scripts = Path(write_scripts)
        if write_scripts.exists() or write_scripts.is_symlink():
            raise ForensicError(f"Refusing to reuse script output directory: {write_scripts}")
        if path.parent in write_scripts.resolve().parents:
            raise ForensicError("Script output directory must be outside the parser-export directory")
        write_scripts.mkdir(parents=True, mode=0o700)
        serial = 0
        for item in scripts:
            if item["status"] != "complete":
                continue
            serial += 1
            target = write_scripts / f"script-{serial:04d}.ps1"
            with target.open("x", encoding="utf-8", newline="") as fp:
                fp.write(item["script_text"])
            item["script_file"] = str(target.resolve())
    return {"source_artifact": str(path), "source_sha256": digest, "event_id_filter": event_id if event_field else None,
            "script_blocks": scripts,
            "note": "PowerShell 4104 text is reconstructed as inert evidence and is never executed. Verify the records against the source EVTX."}


def inspect_registry_export(path: Path, *, key_field: str = "KeyPath",
                            name_field: str = "ValueName", data_field: str = "ValueData",
                            key_contains: str | None = None, value_name: str | None = None,
                            data_contains: str | None = None, max_records: int = 100_000) -> dict:
    path, digest = _source(Path(path))
    matches = []
    for row_number, row in iter_export(path, max_records=max_records):
        key = str(row.get(key_field, "") or "")
        name = str(row.get(name_field, "") or "")
        data = str(row.get(data_field, "") or "")
        if key_contains and key_contains.casefold() not in key.casefold():
            continue
        if value_name and name.casefold() != value_name.casefold():
            continue
        if data_contains and data_contains.casefold() not in data.casefold():
            continue
        matches.append({"source_artifact": str(path), "source_sha256": digest, "source_row": row_number,
                        "key_path": key, "value_name": name, "value_data": data, "observed_row": row})
    if sha256_file(path) != digest:
        raise ForensicError("Parser export changed while being read")
    return {"source_artifact": str(path), "source_sha256": digest, "records_returned": len(matches),
            "records": matches,
            "note": "Rows are parser-export observations. Registry value presence alone does not prove execution, persistence activation, or user attribution."}
