from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from .elf_extractor import extract_functions_from_elf, is_elf
from .metadata import FirmwareMetadata, extract_metadata

logger = logging.getLogger(__name__)


@dataclass
class FirmwareObject:
    path: Path
    disassembly_dir: Path
    meta: FirmwareMetadata
    extracted_files: Dict[str, Path] = None
    functions: Dict[str, Dict[str, Any]] = None

    def __post_init__(self):
        if self.extracted_files is None:
            self.extracted_files = {}
        if self.functions is None:
            self.functions = {}


class FirmwareExtractor:
    def __init__(self, config: Dict[str, Any]):
        self.config = config

    def extract(
        self,
        firmware_path: str,
        source: str = "unknown",
        elf_path: Optional[str] = None,
        source_roots: Optional[List[str]] = None,
        require_source_mapping: bool = False,
    ) -> FirmwareObject:
        elf_resolved = Path(elf_path or firmware_path).resolve()
        if not elf_resolved.is_file() or not is_elf(elf_resolved):
            raise ValueError(f"A debug ELF file is required: {firmware_path}")
        if not source_roots:
            raise ValueError("source_roots is required (project source folder).")

        roots = [Path(r) for r in source_roots]
        logger.info("Extracting ELF: %s", elf_resolved)
        meta = extract_metadata(elf_resolved, source)
        functions = extract_functions_from_elf(
            elf_resolved,
            self.config,
            source_roots=roots,
            require_source_mapping=require_source_mapping,
        )
        return FirmwareObject(
            path=elf_resolved,
            disassembly_dir=elf_resolved.parent,
            meta=meta,
            extracted_files={},
            functions=functions,
        )
