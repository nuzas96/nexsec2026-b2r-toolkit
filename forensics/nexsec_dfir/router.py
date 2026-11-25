"""Transparent rule-based CTF question routing; not an AI model or an answer generator."""
from __future__ import annotations

import json
import re
from pathlib import Path


def route(question: str, rules_file: Path, *, limit: int = 5) -> dict:
    rules = json.loads(rules_file.read_text(encoding="utf-8"))
    q = question.casefold()
    matches = []
    for r in rules:
        matched = [word for word in r["keywords"] if
                   (bool(re.search(r"(?<!\w)" + re.escape(word.casefold()) + r"(?!\w)", q))
                    if len(word) <= 3 else word.casefold() in q)]
        if not matched:
            continue
        score = sum(min(4, len(word.split())) for word in matched)
        matches.append({"id": r["id"], "topic": r["topic"],
                        "matched_keywords": matched, "relevance_score": score,
                        "candidate_artifacts": r["candidate_artifacts"],
                        "tools": r["tools"], "verification": r["verification"],
                        "limits": r["limits"]})
    matches.sort(key=lambda v: (-v["relevance_score"], v["id"]))
    return {"question": question, "suggestions": matches[:limit],
            "note": "Heuristic keyword routing only. These are investigation leads, NOT answers or evidence of correctness."}
