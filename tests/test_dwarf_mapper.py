"""Tests for DWARF source line mapping."""

from pathlib import Path

import pytest

from esp32_firmguard.ingestion.dwarf_mapper import (
    _DwarfLineIndex,
    elf_has_debug_info,
    map_function_source_lines,
)


@pytest.fixture
def wokwi_elf() -> Path:
    p = Path("firmware_samples/test/wokwi_http_server/firmware.elf")
    if not p.is_file():
        pytest.skip("Wokwi sample ELF not present")
    return p


def test_elf_has_debug(wokwi_elf: Path):
    assert elf_has_debug_info(wokwi_elf)


def test_line_index_lookup(wokwi_elf: Path):
    _DwarfLineIndex._cache.clear()
    idx = _DwarfLineIndex.for_elf(wokwi_elf)
    assert len(idx._addrs) > 1000
    path, line = idx.lookup(0x40081290)
    assert path
    assert line and line > 0


def test_map_function(wokwi_elf: Path):
    from esp32_firmguard.utils import load_config

    loc = map_function_source_lines(wokwi_elf, 0x40081290, 64, load_config())
    assert loc["has_source_mapping"]
    assert loc["source_file"]
    assert loc["line_start"] is not None
