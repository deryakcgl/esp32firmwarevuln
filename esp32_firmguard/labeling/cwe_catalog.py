from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

import pandas as pd

_CWE_RE = re.compile(r"CWE-(\d+)", re.IGNORECASE)

_CATALOG_COLUMNS = (
    "record_type",
    "cwe_id",
    "cwe_name",
    "category",
    "mapping_status",
    "abstraction_level",
    "use_as_label",
    "priority",
    "esp32_relevance",
    "esp32_components",
    "detection_signals",
    "llm_labeling_rule",
    "source_urls",
    "notes",
)


@dataclass
class CweCatalogEntry:
    cwe_id: str
    cwe_name: str = ""
    category: str = ""
    mapping_status: str = ""
    abstraction_level: str = ""
    use_as_label: bool = True
    priority: int = 100
    esp32_relevance: str = ""
    esp32_components: str = ""
    detection_signals: str = ""
    llm_labeling_rule: str = ""
    source_urls: str = ""
    notes: str = ""
    record_type: str = ""


@dataclass
class CweCatalog:
    """ESP32-focused CWE reference loaded from Excel."""

    entries: List[CweCatalogEntry] = field(default_factory=list)
    source_path: Optional[str] = None

    @property
    def labelable(self) -> List[CweCatalogEntry]:
        return [e for e in self.entries if e.use_as_label and e.cwe_id]

    @property
    def cwe_ids(self) -> List[str]:
        return [e.cwe_id for e in self.labelable]

    def normalize_cwe_id(self, raw: Any) -> Optional[str]:
        if raw is None or (isinstance(raw, float) and pd.isna(raw)):
            return None
        text = str(raw).strip()
        if not text:
            return None
        m = _CWE_RE.search(text)
        if m:
            return f"CWE-{m.group(1)}"
        if text.isdigit():
            return f"CWE-{text}"
        return None

    def prompt_block(self, max_rules: int = 30) -> str:
        """Text block injected into Ollama prompts."""
        items = sorted(self.labelable, key=lambda e: (e.priority, e.cwe_id))[:max_rules]
        if not items:
            return ""

        lines = [
            "Use ONLY the following CWE IDs when applicable (JSON array output).",
            "Apply each rule to the function's calls, strings, and disassembly:",
            "",
        ]
        for e in items:
            rule = (e.llm_labeling_rule or e.detection_signals or e.notes or "").strip()
            rel = f" [ESP32: {e.esp32_relevance}]" if e.esp32_relevance else ""
            comp = f" components={e.esp32_components}" if e.esp32_components else ""
            lines.append(f"- {e.cwe_id} {e.cwe_name}{rel}{comp}")
            if rule:
                lines.append(f"  Rule: {rule[:500]}")
            if e.detection_signals and e.detection_signals != rule:
                lines.append(f"  Signals: {e.detection_signals[:300]}")
        lines.append("")
        lines.append(f"Allowed IDs: {', '.join(e.cwe_id for e in items)}")
        return "\n".join(lines)

    def _function_haystack(self, func_info: Dict[str, Any]) -> str:
        parts = [
            str(func_info.get("name") or ""),
            " ".join(func_info.get("calls") or []),
            " ".join(func_info.get("strings") or []),
            (func_info.get("disassembly") or "")[:4000],
        ]
        snip = func_info.get("source_snippet") or {}
        for row in snip.get("lines") or []:
            parts.append(str(row.get("text") or ""))
        return " ".join(parts).lower()

    @staticmethod
    def _signal_tokens(text: str) -> List[str]:
        if not text:
            return []
        return [
            t.strip().lower()
            for t in re.split(r"[,;|\s]+", text)
            if len(t.strip()) >= 3
        ]

    def heuristic_hints(self, func_info: Dict[str, Any]) -> List[str]:
        """CWE ids whose detection_signals appear in function metadata."""
        hay = self._function_haystack(func_info)
        hints: List[str] = []
        for e in self.labelable:
            tokens = self._signal_tokens(e.detection_signals or "")
            if any(t in hay for t in tokens):
                hints.append(e.cwe_id)
        return sorted(set(hints))

    def signal_matches(self, func_info: Dict[str, Any]) -> List[str]:
        """Match catalog rules via detection_signals + llm_labeling_rule keywords."""
        hay = self._function_haystack(func_info)
        matched: List[str] = []
        for e in self.labelable:
            blob = " ".join(
                filter(
                    None,
                    (e.detection_signals, e.llm_labeling_rule, e.esp32_components, e.notes),
                )
            )
            tokens = self._signal_tokens(blob)
            if any(t in hay for t in tokens):
                matched.append(e.cwe_id)
        return sorted(set(matched))


def _norm_header(name: str) -> str:
    return str(name).strip().lower().replace(" ", "_")


def is_catalog_excel(df: pd.DataFrame) -> bool:
    cols = {_norm_header(c) for c in df.columns}
    has_catalog = "cwe_id" in cols and (
        "llm_labeling_rule" in cols or "detection_signals" in cols or "use_as_label" in cols
    )
    has_function = "function_name" in cols or "line" in cols or "address" in cols
    return bool(has_catalog and not has_function)


def _cell_str(val: Any) -> str:
    if val is None or (isinstance(val, float) and pd.isna(val)):
        return ""
    return str(val).strip()


def _cell_bool(val: Any, default: bool = True) -> bool:
    if val is None or (isinstance(val, float) and pd.isna(val)):
        return default
    if isinstance(val, (int, float)):
        return bool(int(val))
    s = str(val).strip().lower()
    if s in ("0", "false", "no", "n"):
        return False
    if s in ("1", "true", "yes", "y"):
        return True
    return default


def _cell_int(val: Any, default: int = 100) -> int:
    if val is None or (isinstance(val, float) and pd.isna(val)):
        return default
    try:
        return int(float(val))
    except (TypeError, ValueError):
        return default


def load_cwe_catalog(path: Path) -> CweCatalog:
    path = Path(path).resolve()
    df = pd.read_excel(path, engine="openpyxl")
    if df.empty:
        raise ValueError(f"CWE catalog Excel is empty: {path}")
    if not is_catalog_excel(df):
        raise ValueError(
            "File does not look like a CWE catalog. Expected columns like "
            "cwe_id, llm_labeling_rule, detection_signals, use_as_label."
        )

    col_index = {_norm_header(c): c for c in df.columns}

    def cell(row: pd.Series, key: str) -> Any:
        orig = col_index.get(key)
        return row[orig] if orig is not None else None

    catalog = CweCatalog(source_path=str(path))
    tmp = CweCatalog()  # for normalize_cwe_id helper

    for _, series in df.iterrows():
        cwe_id = tmp.normalize_cwe_id(cell(series, "cwe_id"))
        if not cwe_id:
            continue
        catalog.entries.append(
            CweCatalogEntry(
                record_type=_cell_str(cell(series, "record_type")),
                cwe_id=cwe_id,
                cwe_name=_cell_str(cell(series, "cwe_name")),
                category=_cell_str(cell(series, "category")),
                mapping_status=_cell_str(cell(series, "mapping_status")),
                abstraction_level=_cell_str(cell(series, "abstraction_level")),
                use_as_label=_cell_bool(cell(series, "use_as_label"), default=True),
                priority=_cell_int(cell(series, "priority"), default=100),
                esp32_relevance=_cell_str(cell(series, "esp32_relevance")),
                esp32_components=_cell_str(cell(series, "esp32_components")),
                detection_signals=_cell_str(cell(series, "detection_signals")),
                llm_labeling_rule=_cell_str(cell(series, "llm_labeling_rule")),
                source_urls=_cell_str(cell(series, "source_urls")),
                notes=_cell_str(cell(series, "notes")),
            )
        )

    if not catalog.entries:
        raise ValueError("No CWE catalog rows with valid cwe_id found.")
    return catalog
