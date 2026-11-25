"""Transparent rule-based CTF question routing; not an AI model or an answer generator."""
from __future__ import annotations

import json
import re
import shutil
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
        tools = r["tools"]
        installed = []
        for tool in tools:
            first = tool.split(":", 1)[0].split()[0]
            normalized = first.casefold()
            aliases = {"tshark": ["tshark"], "volatility": ["vol", "volatility3"],
                       "volatility3": ["vol", "volatility3"], "the": ["mmls", "fls"],
                       "evtxecmd": ["EvtxECmd", "EvtxECmd.exe"], "pecmd": ["PECmd", "PECmd.exe"],
                       "mftecmd": ["MFTECmd", "MFTECmd.exe"], "wireshark": ["wireshark"],
                       "nexsec_dfir": ["nexsec-dfir"]}
            candidates = aliases.get(normalized, [first])
            if any(shutil.which(candidate) for candidate in candidates):
                installed.append(tool)
        matches.append({"id": r["id"], "topic": r["topic"],
                        "matched_keywords": matched, "relevance_score": score,
                        "candidate_artifacts": r["candidate_artifacts"],
                        "recommended_evidence_artifacts": r["candidate_artifacts"],
                        "tools": tools, "installed_tools_detected": installed,
                        "requested_information": r.get("requested_information", r["topic"]),
                        "suggested_workflow": r.get("workflow", "Identify the artifact; hash it; inspect its signature; select the listed parser; preserve raw record references; corroborate independently."),
                        "expected_output_fields": r.get("expected_fields", ["source artifact", "source SHA-256", "record/frame reference", "raw timestamp and timezone", "observed value", "limitations"]),
                        "possible_alternative_interpretations": r.get("alternatives", ["The artifact can have benign or unrelated causes; validate against a second source."]),
                        "verification_requirements": r["verification"],
                        "troubleshooting_and_fallback": r.get("fallback", "Check file signature, parser version, tool availability, timeout and parser stderr; use a compatible specialist parser manually and preserve its original output."),
                        "limits": r["limits"]})
    matches.sort(key=lambda v: (-v["relevance_score"], v["id"]))
    return {"question": question, "suggestions": matches[:limit],
            "note": "Deterministic keyword rules only. Tool availability checks are local PATH checks. Suggestions are leads, not answers or findings."}
