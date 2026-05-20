from __future__ import annotations

from typing import Any, Dict, List

from esp32_firmguard.models.predictor import Prediction

from .types import FunctionFinding


def prediction_to_finding(
    pred: Prediction,
    func_info: Dict[str, Any],
) -> FunctionFinding:
    snippet = func_info.get("source_snippet")
    return FunctionFinding(
        func_id=pred.func_id,
        name=str(func_info.get("name") or pred.func_id),
        score=float(pred.score),
        is_vulnerable=bool(pred.is_vulnerable),
        cwe=list(pred.cwe or []),
        address=func_info.get("address"),
        source_file=func_info.get("source_file"),
        line_start=func_info.get("line_start"),
        line_end=func_info.get("line_end"),
        resolved_source_path=func_info.get("resolved_source_path")
        or (snippet.get("resolved_path") if snippet else None),
        source_snippet=snippet,
        disassembly=(func_info.get("disassembly") or "")[:32000] or None,
        llm_trace=func_info.get("llm_trace"),
    )


def rank_findings(
    predictions: List[Prediction],
    functions: Dict[str, Dict[str, Any]],
    *,
    source_only: bool = False,
    max_rows: int = 500,
) -> List[FunctionFinding]:
    """
    Sort by score descending.

    When source_only=False (desktop Test), all functions are listed;
    rows with resolved source snippets are sorted first.
    """
    rows: List[FunctionFinding] = []
    for pred in predictions:
        info = functions.get(pred.func_id) or {}
        if source_only and not info.get("has_source_mapping"):
            continue
        rows.append(prediction_to_finding(pred, info))

    def sort_key(f: FunctionFinding) -> tuple:
        has_snip = bool(f.source_snippet and f.source_snippet.get("lines"))
        has_map = bool(f.source_file)
        return (-int(has_snip), -int(has_map), -f.score)

    rows.sort(key=sort_key)
    return rows[:max_rows]
