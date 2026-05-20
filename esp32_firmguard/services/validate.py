from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Union

from esp32_firmguard.ingestion.dwarf_mapper import elf_has_debug_info
from esp32_firmguard.ingestion.elf_extractor import is_elf
from esp32_firmguard.labeling.cwe_label_merge import require_cwe_excel_path


def validate_elf(path: Union[str, Path]) -> Path:
    p = Path(path).expanduser().resolve()
    if not p.is_file():
        raise FileNotFoundError(f"ELF not found: {p}")
    if not is_elf(p):
        raise ValueError(f"Not an ELF file: {p}")
    if not elf_has_debug_info(p):
        raise ValueError(f"{p.name} has no DWARF debug info. Rebuild with -g.")
    return p


_SOURCE_SUFFIXES = {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".ino"}


def validate_source_root(path: Union[str, Path]) -> str:
    p = Path(path).expanduser().resolve()
    if not p.is_dir():
        raise ValueError(f"Source folder does not exist: {p}")
    if not any(f.suffix.lower() in _SOURCE_SUFFIXES for f in p.rglob("*") if f.is_file()):
        raise ValueError(
            f"No source files (.c/.cpp/.ino) under {p}. "
            "For Wokwi sample use firmware_samples/test/wokwi_http_server/source "
            "(not src)."
        )
    return str(p)


def suggest_source_root(elf_path: Union[str, Path]) -> Optional[str]:
    elf_dir = Path(elf_path).expanduser().resolve().parent
    hint_file = elf_dir / "source_root.txt"
    if hint_file.is_file():
        for line in hint_file.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            candidate = (elf_dir / line).resolve()
            if candidate.is_dir():
                return str(candidate)
    for name in ("source", "src", "main"):
        candidate = (elf_dir / name).resolve()
        if candidate.is_dir() and any(
            f.suffix.lower() in _SOURCE_SUFFIXES for f in candidate.rglob("*") if f.is_file()
        ):
            return str(candidate)
    return None


def validate_source_roots_map(
    elf_paths: Sequence[Union[str, Path]],
    source_roots: Sequence[str],
) -> Dict[str, List[str]]:
    if len(elf_paths) != len(source_roots):
        raise ValueError("Each ELF must have a matching source root.")
    out: Dict[str, List[str]] = {}
    for elf_s, root_s in zip(elf_paths, source_roots):
        elf = validate_elf(elf_s)
        root = validate_source_root(root_s)
        for key in (str(elf), elf.name, elf.stem, elf.parent.name):
            out[key] = [root]
    return out


def validate_cwe_excel(config: Dict[str, Any], path: Optional[str] = None) -> Path:
    return require_cwe_excel_path(config, path)
