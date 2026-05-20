from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .source_reader import read_source_snippet

logger = logging.getLogger(__name__)

try:
    from elftools.elf.elffile import ELFFile

    ELFTOOLS_AVAILABLE = True
except ImportError:
    ELFTOOLS_AVAILABLE = False


def elf_has_debug_info(elf_path: Path) -> bool:
    """True if ELF contains DWARF debug sections."""
    if not ELFTOOLS_AVAILABLE:
        return False
    try:
        with open(elf_path, "rb") as f:
            elffile = ELFFile(f)
            for sec in elffile.iter_sections():
                if sec.name.startswith(".debug_"):
                    return True
    except OSError:
        return False
    return False


def _resolve_addr2line(config: Dict[str, Any], elf_path: Path) -> Optional[str]:
    ext = config.get("extraction") or {}
    for cand in (
        ext.get("addr2line_path"),
        os.environ.get("ADDR2LINE"),
        "xtensa-esp32-elf-addr2line",
        "xtensa-esp32s3-elf-addr2line",
        "addr2line",
    ):
        if not cand:
            continue
        p = Path(cand)
        if p.is_file() and os.access(p, os.X_OK):
            return str(p)
        found = shutil.which(Path(cand).name)
        if found:
            return found
    return None


def _addr2line_at(
    addr2line: str,
    elf_path: Path,
    address: int,
) -> Tuple[Optional[str], Optional[int], Optional[str]]:
    """Return (function_name, line, file_path) for one address."""
    try:
        proc = subprocess.run(
            [addr2line, "-e", str(elf_path), "-f", "-C", "-p", hex(address)],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (subprocess.SubprocessError, OSError) as exc:
        logger.debug("addr2line failed for 0x%x: %s", address, exc)
        return None, None, None

    if proc.returncode != 0 or not proc.stdout.strip():
        return None, None, None

    lines = [ln.strip() for ln in proc.stdout.strip().splitlines() if ln.strip()]
    if len(lines) < 2:
        return None, None, None

    func_name = lines[0]
    loc = lines[-1]
    if loc == "??" or loc == "??:0":
        return func_name, None, None

    # path:line or path:line (column)
    m = re.match(r"^(.+?):(\d+)(?::\d+)?$", loc)
    if not m:
        return func_name, None, loc
    return func_name, int(m.group(2)), m.group(1)


class _DwarfLineIndex:
    """Sorted (address -> file, line) index built once per ELF."""

    _cache: Dict[str, "_DwarfLineIndex"] = {}

    def __init__(self, elf_path: Path):
        import bisect
        import os

        self.elf_path = Path(elf_path).resolve()
        self._addrs: List[int] = []
        self._files: List[str] = []
        self._lines: List[int] = []

        with open(self.elf_path, "rb") as f:
            elffile = ELFFile(f)
            if not elffile.has_dwarf_info():
                return
            dwarfinfo = elffile.get_dwarf_info()
            for cu in dwarfinfo.iter_CUs():
                lineprog = dwarfinfo.line_program_for_CU(cu)
                header = lineprog.header
                files = header.file_entry
                dirs = header.include_directory or []
                for entry in lineprog.get_entries():
                    if entry.state is None or entry.state.end_sequence:
                        continue
                    st = entry.state
                    if st.file < 1 or st.file > len(files):
                        continue
                    fe = files[st.file - 1]
                    dir_idx = int(getattr(fe, "dir_index", 0) or 0)
                    dir_name = ""
                    if dir_idx > 0 and dir_idx - 1 < len(dirs):
                        d = dirs[dir_idx - 1]
                        dir_name = d.decode() if isinstance(d, bytes) else str(d)
                    fname = fe.name.decode() if isinstance(fe.name, bytes) else str(fe.name)
                    path = os.path.join(dir_name, fname) if dir_name else fname
                    self._addrs.append(int(st.address))
                    self._files.append(path)
                    self._lines.append(int(st.line))

        order = sorted(range(len(self._addrs)), key=lambda i: self._addrs[i])
        self._addrs = [self._addrs[i] for i in order]
        self._files = [self._files[i] for i in order]
        self._lines = [self._lines[i] for i in order]
        self._bisect = bisect

    @classmethod
    def for_elf(cls, elf_path: Path) -> "_DwarfLineIndex":
        key = str(Path(elf_path).resolve())
        cached = cls._cache.get(key)
        if cached is None or not cached._addrs:
            cls._cache[key] = cls(elf_path)
        return cls._cache[key]

    def lookup(self, address: int) -> Tuple[Optional[str], Optional[int]]:
        if not self._addrs:
            return None, None
        i = self._bisect.bisect_right(self._addrs, address) - 1
        if i < 0:
            return None, None
        return self._files[i], self._lines[i]


def _lookup_address_pyelftools(elf_path: Path, address: int) -> Tuple[Optional[str], Optional[int]]:
    """Fallback line lookup when addr2line is unavailable."""
    if not ELFTOOLS_AVAILABLE:
        return None, None
    try:
        return _DwarfLineIndex.for_elf(elf_path).lookup(address)
    except Exception as exc:
        logger.debug("pyelftools line lookup failed: %s", exc)
        return None, None


def map_function_source_lines(
    elf_path: Path,
    address: int,
    size: int,
    config: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Map a function address range to source file and line span.

    Samples entry, mid, and end addresses; picks the tightest line span found.
    """
    elf_path = Path(elf_path).resolve()
    addr2line = _resolve_addr2line(config, elf_path)

    size = max(4, int(size))
    samples = sorted({address, address + size // 2, address + max(0, size - 4)})
    files: List[str] = []
    lines: List[int] = []

    for addr in samples:
        _, line, path = (None, None, None)
        if addr2line:
            _, line, path = _addr2line_at(addr2line, elf_path, addr)
        if not path or not line:
            path, line = _lookup_address_pyelftools(elf_path, addr)
        if path and line:
            files.append(path)
            lines.append(line)

    if not files:
        return {
            "source_file": None,
            "line_start": None,
            "line_end": None,
            "has_source_mapping": False,
        }

    # Prefer most common file in samples
    from collections import Counter

    file_counts = Counter(files)
    best_file = file_counts.most_common(1)[0][0]
    matched_lines = [ln for f, ln in zip(files, lines) if f == best_file]
    return {
        "source_file": best_file,
        "line_start": min(matched_lines),
        "line_end": max(matched_lines),
        "has_source_mapping": True,
    }


def enrich_functions_with_source(
    functions: Dict[str, Dict[str, Any]],
    elf_path: Path,
    config: Dict[str, Any],
    source_roots: Optional[Sequence[Path]] = None,
    *,
    require_mapping: bool = False,
) -> Dict[str, Dict[str, Any]]:
    """Attach source_file, line_*, and source_snippet to each function dict."""
    elf_path = Path(elf_path).resolve()
    if not elf_has_debug_info(elf_path):
        msg = f"No DWARF debug sections in {elf_path.name}. Build with -g (debug symbols)."
        if require_mapping:
            raise ValueError(msg)
        logger.warning(msg)
        return functions

    mapped = 0
    for fid, info in functions.items():
        addr = int(info.get("address_int") or 0)
        size = int(info.get("size") or 4)
        loc = map_function_source_lines(elf_path, addr, size, config)
        info.update(loc)

        if loc.get("has_source_mapping") and loc.get("source_file"):
            snippet = read_source_snippet(
                loc["source_file"],
                loc["line_start"] or 1,
                loc["line_end"] or 1,
                search_roots=source_roots,
            )
            info["source_snippet"] = snippet
            info["resolved_source_path"] = snippet.get("resolved_path")
            mapped += 1

    logger.info(
        "Source mapping: %d/%d functions mapped in %s",
        mapped,
        len(functions),
        elf_path.name,
    )
    if require_mapping and mapped == 0:
        raise ValueError(
            f"Could not map any function to source lines in {elf_path.name}. "
            "Ensure debug ELF and addr2line (xtensa-esp32-elf-addr2line) are available."
        )
    return functions
