"""Per-finding narrative metadata extracted from nuclei template info blocks."""
from __future__ import annotations

import json
from pathlib import Path

from .finding import fingerprint_of


def _str_list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value if v not in (None, "")]
    return []


def _cvss(value) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def extract_nuclei_narrative(outdir: Path) -> dict[str, dict]:
    """Map finding fingerprint -> description/reference/cvss/cwe from nuclei JSONL."""
    result: dict[str, dict] = {}
    for path in sorted(Path(outdir).glob("nuclei*.jsonl")):
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                j = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(j, dict):
                continue
            info = j.get("info") if isinstance(j.get("info"), dict) else {}
            cls = info.get("classification")
            if not isinstance(cls, dict):
                cls = {}
            desc = info.get("description")
            fp = fingerprint_of(j.get("template-id", ""), j.get("host", ""),
                                j.get("matched-at", ""))
            result[fp] = {
                "description": desc if isinstance(desc, str) and desc else None,
                "reference": _str_list(info.get("reference")),
                "cvss": _cvss(cls.get("cvss-score")),
                "cwe": _str_list(cls.get("cwe-id")),
            }
    return result
