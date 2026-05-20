from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

import pandas as pd

_CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)

_COLUMN_ALIASES: Dict[str, Sequence[str]] = {
    "function_name": ("function_name", "function", "symbol", "name", "func_name", "method"),
    "func_id": ("func_id", "function_id", "id"),
    "cwe": ("cwe", "cwe_ids", "cwe_labels", "labels", "cwe_id", "cwes"),
    "source_file": ("source_file", "file", "source", "path", "filename"),
    "line": ("line", "line_start", "line_number", "lineno", "start_line"),
    "address": ("address", "addr", "pc"),
    "firmware": ("firmware", "elf", "binary", "image", "project", "build"),
    "vulnerable": ("vulnerable", "is_vulnerable", "label", "class"),
}


@dataclass
class CweExcelRow:
    function_name: Optional[str] = None
    func_id: Optional[str] = None
    cwe_list: List[str] = field(default_factory=list)
    source_file: Optional[str] = None
    line: Optional[int] = None
    address: Optional[int] = None
    firmware: Optional[str] = None
    vulnerable: Optional[bool] = None


def _norm_col(name: str) -> Optional[str]:
    key = str(name).strip().lower().replace(" ", "_")
    for canonical, aliases in _COLUMN_ALIASES.items():
        if key in aliases:
            return canonical
    return None


def _parse_cwe_cell(value: Any) -> List[str]:
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return []
    text = str(value).strip()
    if not text or text.lower() in ("nan", "none", "-", ""):
        return []
    found = _CWE_RE.findall(text)
    if found:
        out: List[str] = []
        for c in found:
            m = _CWE_RE.search(c)
            if m:
                num = re.search(r"\d+", m.group(0))
                if num:
                    out.append(f"CWE-{num.group(0)}")
        return sorted(set(out))
    parts = re.split(r"[,;|\s]+", text)
    out: List[str] = []
    for p in parts:
        p = p.strip()
        if re.fullmatch(r"\d+", p):
            out.append(f"CWE-{p}")
        elif p.upper().startswith("CWE"):
            out.append(p.upper() if p.startswith("CWE") else f"CWE-{p.split('-', 1)[-1]}")
    return sorted(set(out))


def _parse_address(value: Any) -> Optional[int]:
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return None
    if isinstance(value, (int, float)) and not pd.isna(value):
        return int(value)
    s = str(value).strip().lower()
    if not s:
        return None
    try:
        return int(s, 0)
    except ValueError:
        return None


def _parse_line(value: Any) -> Optional[int]:
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return None
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def _parse_bool(value: Any) -> Optional[bool]:
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return None
    if isinstance(value, (int, float)):
        return bool(int(value))
    s = str(value).strip().lower()
    if s in ("1", "true", "yes", "y", "vuln", "vulnerable"):
        return True
    if s in ("0", "false", "no", "n", "safe", "ok"):
        return False
    return None


def load_cwe_excel(path: Path) -> List[CweExcelRow]:
    """Load per-function CWE label rows from Excel. Requires openpyxl for .xlsx."""
    path = Path(path).resolve()
    if not path.is_file():
        raise FileNotFoundError(path)

    df = pd.read_excel(path, engine="openpyxl")
    if df.empty:
        raise ValueError(f"Excel file is empty: {path}")

    from .cwe_catalog import is_catalog_excel

    if is_catalog_excel(df):
        raise ValueError(
            "This Excel file is a CWE catalog (cwe_id, llm_labeling_rule, …), not per-function labels. "
            "Use Ollama mode with this file, or use a sheet with function_name / line / cwe columns."
        )

    col_map: Dict[str, str] = {}
    for col in df.columns:
        canon = _norm_col(str(col))
        if canon:
            col_map[canon] = col

    if "cwe" not in col_map and "vulnerable" not in col_map:
        raise ValueError(
            "Excel must include a 'cwe' (or 'cwe_ids') column, or 'vulnerable' (0/1). "
            f"Found columns: {list(df.columns)}"
        )

    rows: List[CweExcelRow] = []
    for _, series in df.iterrows():
        def cell(key: str) -> Any:
            c = col_map.get(key)
            return series[c] if c is not None else None

        cwes = _parse_cwe_cell(cell("cwe"))
        vuln = _parse_bool(cell("vulnerable"))
        if vuln and not cwes:
            cwes = ["CWE-UNKNOWN"]

        row = CweExcelRow(
            function_name=str(cell("function_name")).strip()
            if cell("function_name") is not None and not pd.isna(cell("function_name"))
            else None,
            func_id=str(cell("func_id")).strip()
            if cell("func_id") is not None and not pd.isna(cell("func_id"))
            else None,
            cwe_list=cwes,
            source_file=str(cell("source_file")).strip()
            if cell("source_file") is not None and not pd.isna(cell("source_file"))
            else None,
            line=_parse_line(cell("line")),
            address=_parse_address(cell("address")),
            firmware=str(cell("firmware")).strip()
            if cell("firmware") is not None and not pd.isna(cell("firmware"))
            else None,
            vulnerable=vuln,
        )
        if row.cwe_list or row.vulnerable is not None:
            rows.append(row)

    if not rows:
        raise ValueError("No valid CWE rows found in Excel.")
    return rows


def _basename_match(a: str, b: str) -> bool:
    return Path(a).name.lower() == Path(b).name.lower()


def _row_matches_function(
    row: CweExcelRow,
    func_id: str,
    func_info: Dict[str, Any],
    firmware_stem: str,
) -> bool:
    if row.firmware:
        fw = row.firmware.lower()
        if fw not in firmware_stem.lower() and firmware_stem.lower() not in fw:
            return False

    if row.func_id and row.func_id == func_id:
        return True

    name = (func_info.get("name") or "").strip()
    if row.function_name and name and row.function_name == name:
        return True

    addr = func_info.get("address_int")
    if row.address is not None and addr is not None and row.address == int(addr):
        return True

    if row.source_file and row.line is not None:
        sf = func_info.get("source_file") or ""
        if sf and _basename_match(sf, row.source_file):
            ls = func_info.get("line_start")
            le = func_info.get("line_end") or ls
            if ls is not None:
                lo, hi = int(ls), int(le or ls)
                if lo <= row.line <= hi or abs(int(row.line) - lo) <= 2:
                    return True
    return False


def apply_excel_to_functions(
    functions: Dict[str, Dict[str, Any]],
    excel_rows: Sequence[CweExcelRow],
    firmware_stem: str,
) -> Dict[str, List[str]]:
    """
    Map Excel rows to func_id -> CWE list for one firmware image.

    First matching row wins per function.
    """
    labels: Dict[str, List[str]] = {}
    used_rows: set[int] = set()

    for func_id, info in functions.items():
        for i, row in enumerate(excel_rows):
            if i in used_rows:
                continue
            if _row_matches_function(row, func_id, info, firmware_stem):
                if row.cwe_list:
                    labels[func_id] = list(row.cwe_list)
                elif row.vulnerable:
                    labels[func_id] = ["CWE-UNKNOWN"]
                used_rows.add(i)
                break
    return labels


def load_cwe_excel_auto(path: Path):
    """
    Detect Excel format and load.

    Returns:
        ("catalog", CweCatalog) or ("function_labels", List[CweExcelRow])
    """
    from .cwe_catalog import is_catalog_excel, load_cwe_catalog

    path = Path(path).resolve()
    df = pd.read_excel(path, engine="openpyxl")
    if is_catalog_excel(df):
        return "catalog", load_cwe_catalog(path)
    return "function_labels", load_cwe_excel(path)
