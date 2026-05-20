from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection

    ELFTOOLS_AVAILABLE = True
except ImportError:
    SymbolTableSection = object  # type: ignore
    ELFTOOLS_AVAILABLE = False

logger = logging.getLogger(__name__)

# ELF e_machine (EM_XTENSA) — Xtensa ESP32 application ELFs use this.
_EM_XTENSA = 94


def _elf_machine(elf_path: Path) -> int:
    """Read e_machine from ELF header (little-endian)."""
    with open(elf_path, "rb") as f:
        f.read(18)
        return int.from_bytes(f.read(2), "little")


def is_elf(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except OSError:
        return False


def _resolve_objdump(config: Dict[str, Any], elf_path: Optional[Path] = None) -> Optional[str]:
    ext = config.get("extraction") or {}
    em = _elf_machine(elf_path) if elf_path and elf_path.is_file() else None
    is_xtensa = em == _EM_XTENSA

    xtensa_candidates: List[str] = []
    for c in (ext.get("objdump_path"), os.environ.get("OBJDUMP")):
        if c:
            xtensa_candidates.append(str(c))
    xtensa_candidates.extend(
        [
            "xtensa-esp32-elf-objdump",
            "xtensa-esp32s3-elf-objdump",
            "xtensa-esp32s2-elf-objdump",
        ]
    )

    generic_candidates = ["llvm-objdump", "objdump"]

    if is_xtensa:
        ordered = xtensa_candidates + [c for c in generic_candidates if c not in xtensa_candidates]
    else:
        ordered = xtensa_candidates + generic_candidates

    seen: set[str] = set()
    for cand in ordered:
        if not cand or cand in seen:
            continue
        seen.add(cand)
        cp = Path(cand)
        if cp.is_file() and os.access(cp, os.X_OK):
            chosen = str(cp)
        else:
            w = shutil.which(Path(cand).name)
            chosen = w or ""
        if not chosen:
            continue
        # Xtensa ELFs: Apple/LLVM system objdump cannot target xtensa--
        if is_xtensa and "xtensa" not in Path(chosen).name.lower():
            continue
        return chosen
    return None


# ESP-IDF / Arduino Xtensa images place code in these sections (not always ".text").
_XTENSA_CODE_SECTIONS = (
    ".text",
    ".flash.text",
    ".iram0.text",
)


def _xtensa_code_ranges(elffile: Any) -> List[Tuple[int, int]]:
    """Return sorted non-overlapping-ish (lo, hi) ranges for executable text on ESP32 ELF."""
    ranges: List[Tuple[int, int]] = []
    for sec in elffile.iter_sections():
        if sec.name not in _XTENSA_CODE_SECTIONS:
            continue
        size = int(sec["sh_size"])
        if size <= 0:
            continue
        lo = int(sec["sh_addr"])
        hi = lo + size
        ranges.append((lo, hi))
    ranges.sort(key=lambda x: x[0])
    return ranges


def _addr_in_code_ranges(addr: int, ranges: List[Tuple[int, int]]) -> bool:
    for lo, hi in ranges:
        if lo <= addr < hi:
            return True
    return False


def _iter_function_symbols(elffile: Any) -> List[Tuple[int, int, str]]:
    ranges = _xtensa_code_ranges(elffile)
    if not ranges:
        return []
    out: List[Tuple[int, int, str]] = []
    for sec in elffile.iter_sections():
        if not isinstance(sec, SymbolTableSection):
            continue
        for sym in sec.iter_symbols():
            if sym["st_info"]["type"] != "STT_FUNC":
                continue
            shndx = sym["st_shndx"]
            if shndx in ("SHN_UNDEF", 0):
                continue
            addr = int(sym["st_value"])
            size = int(sym["st_size"])
            name = sym.name or ""
            if size <= 0 or not name:
                continue
            if not _addr_in_code_ranges(addr, ranges):
                continue
            out.append((addr, size, name))
    out.sort(key=lambda x: x[0])
    # Deduplicate by address (keep largest size)
    dedup: Dict[int, Tuple[int, str]] = {}
    for addr, size, name in out:
        if addr not in dedup or dedup[addr][0] < size:
            dedup[addr] = (size, name)
    return sorted(((a, dedup[a][0], dedup[a][1]) for a in dedup), key=lambda x: x[0])


def _disassemble_range(
    objdump: str,
    elf_path: Path,
    start: int,
    stop: int,
    max_lines: int = 260,
) -> str:
    """Disassemble [start, stop) using objdump/llvm-objdump."""
    is_llvm = "llvm-objdump" in objdump
    base_cmd = [objdump, "-d"]
    if not is_llvm:
        base_cmd.append("--no-show-raw-insn")
    range_args = [
        f"--start-address=0x{start:x}",
        f"--stop-address=0x{stop:x}",
        str(elf_path),
    ]

    attempts: List[List[str]] = [base_cmd + range_args]
    if not is_llvm:
        # Some toolchains omit --no-show-raw-insn
        attempts.append([objdump, "-d"] + range_args)

    last_err = ""
    for cmd in attempts:
        try:
            r = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.warning("objdump failed: %s", e)
            return ""
        if r.returncode == 0 and r.stdout.strip():
            lines = r.stdout.splitlines()
            if len(lines) > max_lines:
                lines = lines[:max_lines] + [f"... ({len(r.stdout.splitlines()) - max_lines} more lines truncated)"]
            return "\n".join(lines)
        last_err = (r.stderr or r.stdout or "")[:400]
    if last_err:
        logger.debug("objdump could not disassemble range 0x%x-0x%x: %s", start, stop, last_err)
    return ""


def _calls_from_asm(asm: str) -> List[str]:
    if not asm:
        return []
    found = set()
    for m in re.finditer(r"\bcall\d*\s+([^\s,]+)", asm, re.IGNORECASE):
        t = m.group(1).strip("<>")
        if t and not t.startswith("0x"):
            found.add(t)
    for m in re.finditer(r"\bjal\s+([^\s,]+)", asm, re.IGNORECASE):
        t = m.group(1).strip("<>")
        if t:
            found.add(t)
    # Xtensa/GNU objdump often:  call8  0x40001234 <memcpy>  — pick symbols inside angle brackets.
    for line in asm.splitlines():
        if not re.search(r"\bcall\d*\b", line, re.IGNORECASE):
            continue
        for m in re.finditer(r"<([A-Za-z_][\w.]*)>", line):
            sym = m.group(1).split("+")[0].strip()
            if sym and not sym.startswith("0x"):
                found.add(sym)
    # Plain-text mentions (weak signal when call parsing misses)
    low = asm.lower()
    for token in (
        "strcpy",
        "strcat",
        "sprintf",
        "vsprintf",
        "memcpy",
        "memmove",
        "scanf",
        "gets",
        "snprintf",
    ):
        if token in low:
            found.add(token)
    return sorted(found)[:64]


def _hints_from_symbol_name(name: str) -> List[str]:
    """If the symbol name embeds libc-like tokens, surface them as synthetic 'calls' for heuristics."""
    if not name:
        return []
    n = name.lower()
    out = []
    for token in (
        "strcpy",
        "strcat",
        "sprintf",
        "memcpy",
        "scanf",
        "httpd",
        "uri",
        "parse",
        "json",
        "wifi",
    ):
        if token in n and token not in out:
            out.append(token)
    return out[:16]


def extract_functions_from_elf(
    elf_path: Path,
    config: Dict[str, Any],
    *,
    source_roots: Optional[List[Path]] = None,
    require_source_mapping: bool = False,
) -> Dict[str, Dict[str, Any]]:
    """
    Build func_id -> metadata including real disassembly when objdump is available.

    func_ids are func_001, func_002, ... in address order (matches feature matrix ordering
    from structural extractor iteration order over dict — note: Python 3.7+ preserves insertion order).
    """
    if not ELFTOOLS_AVAILABLE:
        raise RuntimeError("pyelftools is required for ELF extraction. Install: pip install pyelftools")

    elf_path = Path(elf_path).resolve()
    if not elf_path.is_file():
        raise FileNotFoundError(elf_path)

    ext_cfg = config.get("extraction") or {}
    max_funcs = int(ext_cfg.get("elf_max_functions", 400))
    max_asm_bytes = int(ext_cfg.get("elf_max_disasm_bytes", 8192))

    with open(elf_path, "rb") as f:
        elffile = ELFFile(f)
        sym_rows = _iter_function_symbols(elffile)

    if not sym_rows:
        raise RuntimeError("No STT_FUNC symbols found in .text (check ELF has debug/symbol table).")

    objdump = _resolve_objdump(config, elf_path)
    if not objdump:
        logger.warning("No suitable objdump for this ELF (Xtensa ELFs need xtensa-*-elf-objdump on PATH).")

    functions: Dict[str, Dict[str, Any]] = {}
    for i, (addr, size, name) in enumerate(sym_rows[:max_funcs], start=1):
        fid = f"func_{i:03d}"
        stop = addr + max(4, min(size, max_asm_bytes))
        asm = ""
        if objdump:
            asm = _disassemble_range(objdump, elf_path, addr, stop)
        calls = _calls_from_asm(asm)
        for h in _hints_from_symbol_name(name):
            if h not in calls:
                calls.append(h)
        instr_lines = [ln for ln in asm.splitlines() if ln.strip() and not ln.strip().startswith(".")]
        functions[fid] = {
            "name": name,
            "address": f"0x{addr:08X}",
            "address_int": addr,
            "size": int(size),
            "instructions": max(1, len(instr_lines)),
            "calls": calls,
            "strings": [],
            "entropy": 6.5,
            "disassembly": asm,
            "source": "elf_objdump",
        }

    from .dwarf_mapper import enrich_functions_with_source

    enrich_functions_with_source(
        functions,
        elf_path,
        config,
        source_roots=source_roots,
        require_mapping=require_source_mapping,
    )

    logger.info("ELF extraction: %s functions from %s (objdump=%s)", len(functions), elf_path, objdump)
    return functions


def asm_danger_label(disassembly: str) -> int:
    """
    Weak supervised label: 1 if disassembly mentions risky libc-style symbols.
    Used only to bootstrap training — not a formal verification oracle.
    """
    if not disassembly:
        return 0
    d = disassembly.lower()
    needles = (
        "strcpy",
        "sprintf",
        "gets",
        "strcat",
        "scanf",
        "vsprintf",
        "strncpy",  # still boundary-sensitive
        "memcpy",
    )
    return 1 if any(n in d for n in needles) else 0
