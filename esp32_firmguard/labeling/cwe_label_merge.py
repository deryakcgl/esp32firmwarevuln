from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Sequence, Tuple

from .cwe_catalog import CweCatalog
from .cwe_excel import CweExcelRow, apply_excel_to_functions, load_cwe_excel, load_cwe_excel_auto
from .cwe_labeler import CWELabeler, LabelProgressCallback, LlmTraceCallback
from .default_cwe_allowlist import build_fallback_catalog

logger = logging.getLogger(__name__)

CweLabelMode = Literal["ollama", "excel+ollama"]


def require_cwe_excel_path(config: Dict[str, Any], override: Optional[str] = None) -> Path:
    if override:
        p = Path(override).expanduser().resolve()
        if p.is_file():
            return p
        raise FileNotFoundError(f"CWE Excel not found: {p}")
    cfg = config.get("labeling") or {}
    p = cfg.get("excel_path")
    if p:
        path = Path(p).expanduser().resolve()
        if path.is_file():
            return path
        raise FileNotFoundError(f"labeling.excel_path not found: {path}")
    raise ValueError(
        "CWE labels Excel is required. Pass cwe_excel_path or set labeling.excel_path in config.yaml."
    )


def resolve_excel_label_mode(excel_path: str | Path) -> Tuple[CweLabelMode, str]:
    kind, data = load_cwe_excel_auto(Path(excel_path))
    if kind == "catalog":
        n = len(data.labelable)
        return "ollama", f"CWE catalog: {n} rules → Ollama (Excel-driven)"
    return "excel+ollama", f"Per-function labels: {len(data)} rows → Excel + Ollama for gaps"


def label_functions(
    firmware_obj,
    config: Dict[str, Any],
    *,
    excel_path: str | Path,
    mode: Optional[CweLabelMode] = None,
    excel_rows: Optional[Sequence[CweExcelRow]] = None,
    firmware_stem: str = "",
    label_progress: Optional[LabelProgressCallback] = None,
    cwe_catalog: Optional[CweCatalog] = None,
    llm_trace_callback: Optional[LlmTraceCallback] = None,
) -> Dict[str, List[str]]:
    excel_path = Path(excel_path).resolve()
    if not excel_path.is_file():
        raise FileNotFoundError(f"CWE Excel not found: {excel_path}")

    if mode is None:
        mode, _ = resolve_excel_label_mode(excel_path)

    functions = firmware_obj.functions or {}
    stem = firmware_stem or getattr(firmware_obj, "path", "firmware")

    if cwe_catalog is None and excel_path:
        kind, data = load_cwe_excel_auto(excel_path)
        if kind == "catalog":
            cwe_catalog = data
        elif excel_rows is None:
            excel_rows = data

    excel_labels: Dict[str, List[str]] = {}
    if mode == "excel+ollama":
        rows = list(excel_rows or [])
        if not rows:
            rows = load_cwe_excel(str(excel_path))
        if rows:
            excel_labels = apply_excel_to_functions(functions, rows, stem)
            logger.info(
                "Excel CWE labels: %d/%d functions matched for %s",
                len(excel_labels),
                len(functions),
                stem,
            )

    if cwe_catalog is None:
        cwe_catalog = build_fallback_catalog(config)
        logger.info(
            "No CWE catalog in Excel; using built-in allow-list (%d CWE rules) for Ollama",
            len(cwe_catalog.labelable),
        )

    llm_cfg = dict(config.get("llm") or {})
    llm_cfg["provider"] = "ollama"
    merged_cfg = {**config, "llm": llm_cfg}
    labeler = CWELabeler(
        merged_cfg,
        cwe_catalog=cwe_catalog,
        trace_callback=llm_trace_callback,
    )

    if mode == "excel+ollama" and excel_labels:
        gap_ids = [fid for fid in functions if fid not in excel_labels or not excel_labels[fid]]
        if gap_ids:
            subset = {fid: functions[fid] for fid in gap_ids}

            class _SubFw:
                path = getattr(firmware_obj, "path", None)
                functions = subset

            auto_labels = labeler.label(
                _SubFw(),
                progress_callback=label_progress,
                trace_callback=llm_trace_callback,
            )
        else:
            auto_labels = {}
        out: Dict[str, List[str]] = {}
        for fid in functions:
            if fid in excel_labels and excel_labels[fid]:
                out[fid] = excel_labels[fid]
            else:
                out[fid] = auto_labels.get(fid, [])
        return out

    return labeler.label(
        firmware_obj,
        progress_callback=label_progress,
        trace_callback=llm_trace_callback,
    )


def load_cwe_resource(
    path: Optional[str],
) -> Tuple[Optional[CweCatalog], Optional[List[CweExcelRow]], str]:
    if not path:
        return None, None, ""
    kind, data = load_cwe_excel_auto(Path(path))
    if kind == "catalog":
        n = len(data.labelable)
        return data, None, f"CWE catalog: {n} labelable CWE rules"
    return None, data, f"Per-function labels: {len(data)} rows"
