"""Bounded, safe investigation of CSV exported by external artifact parsers."""
from __future__ import annotations

import collections
import csv
from pathlib import Path
from .core import ForensicError


def inspect_csv(path: Path, *, field: str | None = None, equals: str | None = None,
                contains: str | None = None, select: str | None = None,
                group_field: str | None = None, limit: int = 50,
                max_rows: int = 250000) -> dict:
    if not 0 <= limit <= 500:
        raise ForensicError("limit must be 0..500")
    if not 1 <= max_rows <= 2_000_000:
        raise ForensicError("max_rows must be 1..2000000")
    if (equals is not None or contains is not None) and not field:
        raise ForensicError("--equals/--contains requires --field")
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as fp:
            csvreader = csv.DictReader(fp)
            cols = csvreader.fieldnames
            if not cols:
                raise ForensicError("CSV lacks a header row")
            if len(set(cols)) != len(cols):
                raise ForensicError("CSV contains duplicate headers; cannot attribute columns reliably")
            for name in [field, group_field]:
                if name and name not in cols:
                    raise ForensicError(f"Column {name!r} absent; available columns: {cols}")
            wanted = [name.strip() for name in select.split(",")] if select else cols
            if any(name not in cols for name in wanted):
                raise ForensicError(f"--select contains columns not present; available: {cols}")
            group_counts = collections.Counter()
            output = []
            matched = 0
            count = 0
            for count, row in enumerate(csvreader, start=1):
                if count > max_rows:
                    count -= 1
                    break
                if field:
                    observed = row.get(field) or ""
                    if equals is not None and observed.casefold() != equals.casefold():
                        continue
                    if contains is not None and contains.casefold() not in observed.casefold():
                        continue
                matched += 1
                if group_field:
                    group_counts[(row.get(group_field) or "")] += 1
                if len(output) < limit:
                    output.append({"source_row": count + 1, "fields": {col: row.get(col) for col in wanted}})
            return {"source": str(path), "columns": cols, "rows_scanned": count,
                    "max_rows": max_rows, "maybe_truncated": count >= max_rows,
                    "matched_rows": matched, "selected_rows": output,
                    "group_counts": group_counts.most_common(50),
                    "note": "Read-only CSV export exploration, not validation of upstream parser or artifact."
                            " Source rows start at 2 (header row is 1)."}
    except UnicodeDecodeError as err:
        raise ForensicError(f"CSV is not UTF-8; convert a COPY with documented encoding: {err}") from err
