from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd

from esp32_firmguard.models.predictor import Prediction

CWE_DESCRIPTIONS: Dict[str, str] = {
    "CWE-120": (
        "**CWE-120** — Buffer copy without adequate bounds checking (classic buffer overflow risk): "
        "copy/format operations without length checks can lead to memory corruption and exploitable conditions."
    ),
    "CWE-79": (
        "**CWE-79** — Cross-site scripting (XSS) style patterns: "
        "if user- or network-controlled data is emitted to HTTP, logs, or UI without escaping, script injection risk increases."
    ),
    "CWE-134": (
        "**CWE-134** — Use of externally controlled format string: "
        "passing attacker-influenced data as the format argument to the `printf` family can cause memory read/write issues."
    ),
    "CWE-190": (
        "**CWE-190** — Integer overflow: "
        "overflowed arithmetic can yield wrong sizes or indices and unsafe memory access."
    ),
    "CWE-787": (
        "**CWE-787** — Out-of-bounds write: "
        "writes past array or buffer bounds cause memory corruption and security failures."
    ),
}


def _md_escape_cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def pseudo_c_snippet(func_info: Dict[str, Any]) -> str:
    """
    Build a representative pseudo-C snippet from extraction metadata.
    This is NOT decompiled firmware source; it reflects names/calls/strings only.
    """
    name = func_info.get("name") or "unknown_function"
    calls = list(func_info.get("calls") or [])
    strings = list(func_info.get("strings") or [])
    addr = func_info.get("address", "?")
    size = func_info.get("size", "?")

    lines: List[str] = [
        "// Representative pseudo-C — not a real binary decompilation.",
        f"// Summary: address {addr}, estimated size {size} bytes",
        "",
        f"void {name}(void)",
        "{",
    ]
    if strings:
        shown = strings[:8]
        tail = " …" if len(strings) > 8 else ""
        lines.append(
            "    /* Embedded string hints: "
            + ", ".join(repr(s) for s in shown)
            + tail
            + " */"
        )
    if calls:
        lines.append("    /* Inferred call patterns (static extraction) */")
        for c in calls[:12]:
            lines.append(f"    // {c}(...);")
        if len(calls) > 12:
            lines.append(f"    // … and {len(calls) - 12} more call(s)")
    else:
        lines.append("    /* No strong library-call inference */")

    lines.extend(["", "    /* ... function body ... */", "}", ""])
    return "\n".join(lines)


def _feature_bullets(row: pd.Series) -> List[str]:
    bullets: List[str] = []
    if row is None or row.empty:
        return bullets

    def num(col: str) -> Optional[float]:
        if col not in row.index:
            return None
        v = row[col]
        try:
            return float(v)
        except (TypeError, ValueError):
            return None

    nd = num("num_dangerous_calls")
    if nd is not None and nd > 0:
        bullets.append(
            f"**Dangerous call count** is non-zero (`num_dangerous_calls={nd:.0f}`): "
            "APIs such as `strcpy`, `sprintf`, and `memcpy` increase attack surface when bounds are not enforced."
        )

    for flag, label in (
        ("has_strcpy", "`strcpy` present"),
        ("has_sprintf", "`sprintf` present"),
        ("has_memcpy", "`memcpy` present"),
    ):
        v = num(flag)
        if v is not None and v >= 0.5:
            bullets.append(
                f"**Static signal:** {label} — if buffer lengths are unchecked, this aligns with CWE-120 style issues."
            )

    ent = num("entropy")
    if ent is not None and ent > 7.0:
        bullets.append(
            f"**High entropy** (`entropy={ent:.2f}`): dense code/data or crypto/compression; "
            "combined with weak bounds logic, review and tooling become harder."
        )

    cc = num("cyclomatic_complexity")
    if cc is not None and cc > 12:
        bullets.append(
            f"**High cyclomatic complexity** (`cyclomatic_complexity={cc:.1f}`): "
            "more branches and edge cases increase the chance of mistakes in boundary handling."
        )

    iv = num("has_input_validation")
    if iv is not None and iv < 0.5:
        bullets.append(
            "**Input validation** signals look weak (`has_input_validation` low): "
            "functions consuming external data are harder to trust without explicit checks."
        )

    osan = num("has_output_sanitization")
    if osan is not None and osan < 0.5 and (num("has_sprintf") or 0) >= 0.5:
        bullets.append(
            "**Output escaping / sanitization** looks weak while formatting APIs are present: "
            "relevant for CWE-79 or format-string style concerns."
        )

    if not bullets:
        bullets.append(
            "No single standout “classic” API flag; the score may reflect several low-level features and/or rule-based weighting."
        )
    return bullets


def _risk_tier(score: float, threshold: float) -> str:
    if score >= threshold + 0.2:
        return "high"
    if score >= threshold:
        return "above_threshold"
    if score >= threshold * 0.7:
        return "medium"
    return "low"


_TIER_ORDER = ("high", "above_threshold", "medium", "low")
_TIER_TITLES = {
    "high": "High",
    "above_threshold": "At or above threshold (flagged vulnerable)",
    "medium": "Medium",
    "low": "Low",
}


def _truncate_asm_lines(asm: str, max_lines: int = 240) -> str:
    lines = asm.splitlines()
    if len(lines) <= max_lines:
        return asm
    head = "\n".join(lines[:max_lines])
    return f"{head}\n\n... ({len(lines) - max_lines} more lines omitted)"


def build_markdown_report(
    *,
    run_info: Dict[str, Any],
    functions: Dict[str, Dict[str, Any]],
    predictions: List[Prediction],
    cwe_labels: Dict[str, List[str]],
    feature_matrix: pd.DataFrame,
    threshold: float,
) -> str:
    """Assemble full Markdown document."""
    pred_by_id = {p.func_id: p for p in predictions}
    vuln_ids = [p.func_id for p in predictions if p.is_vulnerable]

    lines: List[str] = []
    lines.append("# ESP32 FirmGuard — Analysis report")
    lines.append("")
    lines.append(
        "This document supplements the JSON output with a **readable summary**, **CWE and risk groupings**, "
        "and for each flagged function **representative pseudo-C** plus **why it was marked vulnerable**."
    )
    lines.append("")
    lines.append(
        "> C blocks are inferred from metadata (name, calls, strings). "
        "Assembly comes from objdump when a debug ELF is provided."
    )
    lines.append("")

    # --- Run summary
    lines.append("## 1. Run summary")
    lines.append("")
    lines.append("| Field | Value |")
    lines.append("| --- | --- |")
    for key, val in sorted(run_info.items()):
        lines.append(f"| {_md_escape_cell(str(key))} | {_md_escape_cell(str(val))} |")
    lines.append("")

    n_v = len(vuln_ids)
    n_all = len(predictions)
    lines.append(
        f"**Summary:** predictions for **{n_all}** function(s); **{n_v}** exceed the configured threshold "
        f"(`{threshold:.2f}`) and are flagged **vulnerable**."
    )
    lines.append("")

    # --- CWE category rollup (from predictions' CWE lists)
    lines.append("## 2. CWE categories (prediction labels)")
    lines.append("")
    cwe_counts: Dict[str, int] = defaultdict(int)
    for p in predictions:
        for c in p.cwe:
            cwe_counts[c] += 1
    if cwe_counts:
        for cwe, cnt in sorted(cwe_counts.items(), key=lambda x: (-x[1], x[0])):
            desc = CWE_DESCRIPTIONS.get(cwe, "")
            lines.append(f"- **`{cwe}`** — appears on **{cnt}** function prediction(s).")
            if desc:
                lines.append(f"  - {desc}")
            lines.append("")
    else:
        lines.append("_No CWE list attached to predictions for this run (empty)._")
    lines.append("")

    # --- Risk tiers
    lines.append("## 3. Risk tiers (by score)")
    lines.append("")
    tiers: Dict[str, List[str]] = defaultdict(list)
    for p in predictions:
        tiers[_risk_tier(p.score, threshold)].append(p.func_id)
    for tier_key in _TIER_ORDER:
        ids = sorted(tiers.get(tier_key, []), key=lambda fid: pred_by_id[fid].score, reverse=True)
        if not ids:
            continue
        lines.append(f"### {_TIER_TITLES[tier_key]}")
        lines.append("")
        lines.append(", ".join(f"`{i}`" for i in ids))
        lines.append("")

    # --- Vulnerable functions detail
    lines.append("## 4. Flagged vulnerable functions — code evidence and rationale")
    lines.append("")
    vuln_sorted = sorted(
        (pred_by_id[i] for i in vuln_ids),
        key=lambda p: p.score,
        reverse=True,
    )

    for idx, pred in enumerate(vuln_sorted, start=1):
        func_id = pred.func_id
        info = functions.get(func_id, {})
        name = info.get("name", func_id)
        lines.append(f"### 4.{idx}. `{func_id}` — `{name}`")
        lines.append("")
        lines.append("| Property | Value |")
        lines.append("| --- | --- |")
        lines.append(f"| Score | **{pred.score:.4f}** |")
        lines.append(f"| Threshold | {threshold:.4f} |")
        lines.append(f"| Vulnerable | {'Yes' if pred.is_vulnerable else 'No'} |")
        if info.get("address"):
            lines.append(f"| Address | `{info.get('address')}` |")
        if info.get("size") is not None:
            lines.append(f"| Estimated size (bytes) | {info.get('size')} |")
        if info.get("instructions") is not None:
            lines.append(f"| Estimated instruction count | {info.get('instructions')} |")
        calls = info.get("calls") or []
        if calls:
            lines.append(f"| Calls | {', '.join(str(c) for c in calls)} |")
        strs = info.get("strings") or []
        if strs:
            lines.append(f"| Strings | {', '.join(str(s) for s in strs[:12])}{' …' if len(strs) > 12 else ''} |")
        labels = cwe_labels.get(func_id, pred.cwe)
        if labels:
            lines.append(f"| CWE (labeler) | {', '.join(labels)} |")
        lines.append("")

        asm = (info.get("disassembly") or "").strip()
        if asm:
            lines.append("#### Disassembly (ELF / objdump)")
            lines.append("")
            lines.append("```asm")
            lines.append(_truncate_asm_lines(asm).rstrip())
            lines.append("```")
            lines.append("")
            lines.append(
                "*This assembly is produced by your toolchain’s `objdump` on the supplied ELF (not synthetic pseudo-code).*"
            )
            lines.append("")
        else:
            lines.append("#### Representative pseudo-C")
            lines.append("")
            lines.append("```c")
            lines.append(pseudo_c_snippet(info).rstrip())
            lines.append("```")
            lines.append("")

        lines.append("#### Why it looks vulnerable")
        lines.append("")
        lines.append(
            f"- Rule/model score **{pred.score:.4f}** vs threshold **{threshold:.4f}**; "
            f"above threshold ⇒ `is_vulnerable=true`."
        )
        for cwe in pred.cwe:
            desc = CWE_DESCRIPTIONS.get(cwe)
            if desc:
                lines.append(f"- {desc}")
            else:
                lines.append(f"- Related label: `{cwe}`.")

        row = None
        if func_id in feature_matrix.index:
            row = feature_matrix.loc[func_id]
        lines.append("- **Feature-based observations:**")
        for b in _feature_bullets(row):
            lines.append(f"  - {b}")
        lines.append("")

    # --- Near-threshold non-vulnerable
    safe_high = [p for p in predictions if not p.is_vulnerable and p.score >= threshold * 0.85]
    if safe_high:
        lines.append("## 5. Just below threshold")
        lines.append("")
        lines.append(
            "These are **not** flagged vulnerable right now but have relatively high scores; "
            "consider manual review or threshold tuning."
        )
        lines.append("")
        for p in sorted(safe_high, key=lambda x: x.score, reverse=True)[:15]:
            lines.append(f"- `{p.func_id}` — score **{p.score:.4f}**")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("*Report generated automatically by ESP32 FirmGuard.*")
    lines.append("")
    return "\n".join(lines)


def default_report_path(json_output: Path) -> Path:
    """Sidecar report next to JSON: `name_report.md` for `name.json`."""
    stem = json_output.stem
    if stem.endswith("_report"):
        return json_output.with_suffix(".md")
    return json_output.with_name(f"{stem}_report.md")


def write_markdown_report(
    path: Path,
    *,
    run_info: Dict[str, Any],
    functions: Dict[str, Dict[str, Any]],
    predictions: List[Prediction],
    cwe_labels: Dict[str, List[str]],
    feature_matrix: pd.DataFrame,
    threshold: float,
) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = build_markdown_report(
        run_info=run_info,
        functions=functions,
        predictions=predictions,
        cwe_labels=cwe_labels,
        feature_matrix=feature_matrix,
        threshold=threshold,
    )
    path.write_text(text, encoding="utf-8")
    return path
