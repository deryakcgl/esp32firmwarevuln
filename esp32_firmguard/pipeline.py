from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import pandas as pd

from esp32_firmguard.features.embeddings import EmbeddingFeatureExtractor
from esp32_firmguard.features.peripheral import PeripheralFeatureExtractor
from esp32_firmguard.features.structural import StructuralFeatureExtractor
from esp32_firmguard.ingestion.extractor import FirmwareExtractor
from esp32_firmguard.labeling.cwe_label_merge import (
    label_functions,
    load_cwe_resource,
    require_cwe_excel_path,
    resolve_excel_label_mode,
)
from esp32_firmguard.models.dataset import DatasetBuilder
from esp32_firmguard.models.predictor import Prediction, VulnerabilityPredictor

logger = logging.getLogger(__name__)


class FirmwareSecurityPipeline:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.extractor = FirmwareExtractor(config)
        self.struct_feat = StructuralFeatureExtractor(config)
        self.periph_feat = PeripheralFeatureExtractor(config)
        self.embed_feat = EmbeddingFeatureExtractor(config)
        self.dataset_builder = DatasetBuilder(config)
        self.predictor = VulnerabilityPredictor(config)

    def run_static_stage(
        self,
        elf_path: str,
        source_roots: List[str],
        *,
        cwe_excel_path: Optional[str] = None,
        cwe_catalog: Optional[Any] = None,
        on_progress: Optional[Callable[[int, str], None]] = None,
        on_llm_trace: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> Tuple[Any, pd.DataFrame, List[Prediction], Dict[str, List[str]]]:
        if not source_roots:
            raise ValueError("source_roots is required (project source folder).")

        def report(pct: int, msg: str) -> None:
            if on_progress:
                on_progress(max(0, min(100, pct)), msg)

        report(2, "Loading ELF…")
        fw = self.extractor.extract(
            elf_path,
            "elf",
            elf_path=elf_path,
            source_roots=source_roots,
            require_source_mapping=True,
        )
        report(12, f"{len(fw.functions)} functions")

        report(18, "Features…")
        structural = self.struct_feat.extract(fw)
        peripheral = self.periph_feat.extract(fw)
        embeddings = self.embed_feat.extract(fw)

        report(32, "CWE labeling (Excel + Ollama)…")

        def label_progress(done: int, total: int, msg: str) -> None:
            if total <= 0:
                return
            report(32 + int(48 * done / max(1, total)), msg)

        excel = require_cwe_excel_path(self.config, cwe_excel_path)
        mode = resolve_excel_label_mode(excel)[0]
        if cwe_catalog is None:
            catalog, _, _ = load_cwe_resource(str(excel))
            if catalog is not None:
                cwe_catalog = catalog

        cwe_labels = label_functions(
            fw,
            self.config,
            excel_path=excel,
            mode=mode,
            firmware_stem=Path(elf_path).stem,
            label_progress=label_progress,
            cwe_catalog=cwe_catalog,
            llm_trace_callback=on_llm_trace,
        )

        report(82, "Building dataset…")
        feature_matrix = self.dataset_builder.build_feature_matrix(
            structural, peripheral, embeddings, cwe_labels
        )

        report(88, "Scoring…")
        self.predictor.load_model()
        predictions = self.predictor.predict(feature_matrix, cwe_labels)
        report(100, "Done")

        return fw, feature_matrix, predictions, cwe_labels
