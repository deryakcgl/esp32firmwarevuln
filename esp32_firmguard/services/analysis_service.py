from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union

LlmTraceCallback = Callable[[Dict[str, Any]], None]

from esp32_firmguard.ingestion.dwarf_mapper import elf_has_debug_info
from esp32_firmguard.ingestion.elf_extractor import is_elf
from esp32_firmguard.pipeline import FirmwareSecurityPipeline

from esp32_firmguard.labeling.cwe_label_merge import (
    load_cwe_resource,
    require_cwe_excel_path,
    resolve_excel_label_mode,
)

from .findings import rank_findings
from .progress import ProgressCallback
from .types import AnalysisResult

logger = logging.getLogger(__name__)


class AnalysisService:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.pipeline = FirmwareSecurityPipeline(config)

    def analyze(
        self,
        elf_path: Union[str, Path],
        *,
        model_path: Optional[Union[str, Path]] = None,
        source_roots: Optional[List[str]] = None,
        source_tag: str = "test",
        require_source_mapping: bool = True,
        findings_source_only: bool = False,
        on_progress: Optional[ProgressCallback] = None,
        cwe_excel_path: Optional[str] = None,
        ollama_model: Optional[str] = None,
        ollama_url: Optional[str] = None,
        on_llm_trace: Optional[LlmTraceCallback] = None,
    ) -> AnalysisResult:
        elf = Path(elf_path).resolve()
        if not elf.is_file() or not is_elf(elf):
            raise ValueError(f"Expected a debug ELF file: {elf}")
        if not elf_has_debug_info(elf):
            raise ValueError(
                f"{elf.name} has no DWARF debug info. Build firmware with -g before testing."
            )
        if not source_roots:
            raise ValueError("source_roots is required (project source folder).")

        if model_path:
            self.pipeline.predictor.load_model(Path(model_path))

        if ollama_model or ollama_url:
            llm = self.config.setdefault("llm", {})
            if ollama_model:
                llm["model"] = ollama_model
            if ollama_url:
                llm["ollama_url"] = ollama_url

        wall0 = time.perf_counter()
        excel = str(require_cwe_excel_path(self.config, cwe_excel_path))
        _, mode_desc = resolve_excel_label_mode(excel)
        cwe_catalog, _, desc = load_cwe_resource(excel)
        if on_progress:
            on_progress(0, f"Starting analysis… ({mode_desc or desc})")

        fw, _, predictions, _ = self.pipeline.run_static_stage(
            str(elf),
            list(source_roots),
            cwe_excel_path=excel,
            cwe_catalog=cwe_catalog,
            on_progress=on_progress,
            on_llm_trace=on_llm_trace,
        )

        if on_progress:
            on_progress(92, "Ranking findings…")
        functions = fw.functions or {}
        mapped = sum(1 for f in functions.values() if f.get("has_source_mapping"))
        findings = rank_findings(
            predictions,
            functions,
            source_only=findings_source_only,
        )

        if require_source_mapping and mapped == 0:
            raise ValueError(
                "No functions could be mapped to source lines. "
                "Check the source folder (e.g. …/wokwi_http_server/source, not src). "
                "Ensure xtensa-esp32-elf-addr2line is on PATH."
            )
        if not findings:
            raise ValueError(
                "No predictions produced. Check that the model file matches this firmware."
            )

        vuln = sum(1 for f in findings if f.is_vulnerable)

        if on_progress:
            on_progress(100, "Analysis complete")

        return AnalysisResult(
            firmware_path=str(elf),
            elf_path=str(elf),
            model_path=str(model_path) if model_path else None,
            findings=findings,
            timings={"static_seconds": round(time.perf_counter() - wall0, 3)},
            functions_with_source=mapped,
            functions_total=len(functions),
            vulnerable_count=vuln,
        )
