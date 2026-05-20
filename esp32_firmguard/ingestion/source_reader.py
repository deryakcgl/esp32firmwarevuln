from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

logger = logging.getLogger(__name__)


def resolve_source_path(
    source_file: str,
    search_roots: Optional[Sequence[Path]] = None,
) -> Optional[Path]:
    """Resolve DWARF path to a readable file on disk."""
    if not source_file or source_file in ("??", "?"):
        return None

    raw = Path(source_file)
    candidates: List[Path] = []
    if raw.is_file():
        candidates.append(raw.resolve())
    if search_roots:
        for root in search_roots:
            root = Path(root)
            if not root.is_dir():
                continue
            candidates.append((root / raw).resolve())
            candidates.append((root / raw.name).resolve())
            # ESP-IDF often records paths like main/foo.c
            parts = raw.parts
            if len(parts) >= 2:
                candidates.append((root / Path(*parts[-2:])).resolve())

    seen: set[str] = set()
    for p in candidates:
        key = str(p)
        if key in seen:
            continue
        seen.add(key)
        if p.is_file():
            return p
    return None


def read_source_snippet(
    source_file: str,
    line_start: int,
    line_end: int,
    *,
    context: int = 8,
    search_roots: Optional[Sequence[Path]] = None,
    highlight_start: Optional[int] = None,
    highlight_end: Optional[int] = None,
) -> Dict[str, Any]:
    """
  Read source lines with optional highlight band.

  Returns dict with resolved path, numbered lines, and highlight range.
    """
    hs = highlight_start if highlight_start is not None else line_start
    he = highlight_end if highlight_end is not None else line_end
    hs = max(1, int(hs))
    he = max(hs, int(he))

    resolved = resolve_source_path(source_file, search_roots)
    if resolved is None:
        return {
            "source_file": source_file,
            "resolved_path": None,
            "line_start": line_start,
            "line_end": line_end,
            "highlight_start": hs,
            "highlight_end": he,
            "lines": [],
            "error": "source_file_not_found",
        }

    lo = max(1, hs - context)
    hi = he + context
    lines_out: List[Dict[str, Any]] = []
    try:
        text = resolved.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        return {
            "source_file": source_file,
            "resolved_path": str(resolved),
            "line_start": line_start,
            "line_end": line_end,
            "highlight_start": hs,
            "highlight_end": he,
            "lines": [],
            "error": str(exc),
        }

    for n in range(lo, min(hi, len(text)) + 1):
        idx = n - 1
        if idx < 0 or idx >= len(text):
            continue
        lines_out.append(
            {
                "number": n,
                "text": text[idx],
                "in_function": hs <= n <= he,
                "highlight": hs <= n <= he,
            }
        )

    return {
        "source_file": source_file,
        "resolved_path": str(resolved),
        "line_start": line_start,
        "line_end": line_end,
        "highlight_start": hs,
        "highlight_end": he,
        "lines": lines_out,
        "error": None,
    }
