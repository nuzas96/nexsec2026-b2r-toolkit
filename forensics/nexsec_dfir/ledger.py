"""Case findings ledger tied to hashes and exact source references."""
from __future__ import annotations

import json
from pathlib import Path
from .core import ForensicError, read_case, utc_now, sha256_file


def record_finding(case_dir: Path, *, artifact: str, source_ref: str,
                   observed: str, interpretation: str, confidence: str,
                   question: str = "") -> dict:
    if confidence not in ("confirmed-observation", "supported-inference", "hypothesis"):
        raise ForensicError("Invalid confidence label")
    doc = read_case(case_dir)
    matches = [x for x in doc["artifacts"] if x["relative_path"] == artifact]
    if not matches:
        raise ForensicError("Artifact must match a relative_path in case manifest")
    if not all(s.strip() for s in (source_ref, observed, interpretation)):
        raise ForensicError("source-ref, observed and interpretation are required")
    root = Path(doc["original_evidence_path"])
    target = root / artifact if doc["source_is_directory"] else root
    if target.is_symlink() or not target.is_file() or sha256_file(target) != matches[0]["sha256"]:
        raise ForensicError("Artifact original missing/modified; recheck evidence integrity before recording finding")
    entry = {"recorded_at_utc": utc_now(), "question": question,
             "artifact_relative_path": artifact, "artifact_sha256_at_intake": matches[0]["sha256"],
             "source_reference": source_ref, "observed": observed,
             "interpretation": interpretation, "confidence": confidence,
             "note": "Confidence is analyst-supplied; record does not independently validate the claim."}
    ledger = case_dir / "findings.jsonl"
    with ledger.open("a", encoding="utf-8") as fp:
        fp.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return entry


def list_findings(case_dir: Path) -> list[dict]:
    read_case(case_dir)
    ledger = case_dir / "findings.jsonl"
    if not ledger.exists():
        return []
    with ledger.open(encoding="utf-8") as f:
        return [json.loads(s) for s in f if s.strip()]


def investigative_summary(case_dir: Path, unknowns: list[str] | None = None) -> dict:
    """Group analyst-entered findings without changing their confidence labels."""
    rows = list_findings(case_dir)
    groups = {"confirmed_observations": [], "supported_inferences": [], "hypotheses": []}
    keys = {"confirmed-observation": "confirmed_observations",
            "supported-inference": "supported_inferences", "hypothesis": "hypotheses"}
    for row in rows:
        groups[keys[row["confidence"]]].append(row)
    return {"case": str(case_dir), **groups, "unknowns": list(unknowns or []),
            "finding_count": len(rows),
            "note": "Categories reflect analyst-entered ledger labels; this summary does not validate evidence or infer causation."}
