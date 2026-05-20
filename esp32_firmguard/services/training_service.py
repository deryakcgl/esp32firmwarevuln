from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Union

LlmTraceCallback = Callable[[Dict[str, Any]], None]

import pandas as pd

from esp32_firmguard.ingestion.dwarf_mapper import elf_has_debug_info
from esp32_firmguard.labeling.cwe_label_merge import (
    load_cwe_resource,
    require_cwe_excel_path,
    resolve_excel_label_mode,
)
from esp32_firmguard.ingestion.elf_extractor import is_elf
from esp32_firmguard.models.dataset import DatasetBuilder
from esp32_firmguard.models.trainer import ModelTrainer
from esp32_firmguard.pipeline import FirmwareSecurityPipeline
from esp32_firmguard.utils import ensure_dir

from .progress import ProgressCallback, chain_progress
from .split import split_by_firmware
from .types import TrainingResult

logger = logging.getLogger(__name__)


def _resolve_source_roots(
    elf: Path,
    source_roots_map: Optional[Dict[str, List[str]]],
) -> Optional[List[str]]:
    """Match ELF to source roots (full path, parent folder slug, stem)."""
    if not source_roots_map:
        return None
    keys = (
        str(elf.resolve()),
        str(elf),
        elf.name,
        elf.stem,
        elf.parent.name,
    )
    for key in keys:
        if key in source_roots_map and source_roots_map[key]:
            return list(source_roots_map[key])
    return None


class TrainingService:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.pipeline = FirmwareSecurityPipeline(config)
        self.dataset_builder = DatasetBuilder(config)
        paths = config.get("paths", {})
        self.dataset_output = Path(paths.get("dataset_output", "./output/datasets"))
        self.model_output = Path(paths.get("model_output", "./output/models"))
        ensure_dir(self.dataset_output)
        ensure_dir(self.model_output)

    def _validate_elf(self, path: Path) -> None:
        if not path.is_file():
            raise FileNotFoundError(path)
        if not is_elf(path):
            raise ValueError(f"Not an ELF file: {path}")
        if not elf_has_debug_info(path):
            raise ValueError(
                f"{path.name} has no debug symbols. Rebuild with -g (CONFIG_COMPILER_OPTIMIZATION_DEBUG)."
            )

    def build_dataset_from_elfs(
        self,
        elf_paths: Sequence[Union[str, Path]],
        source_roots_map: Optional[Dict[str, List[str]]] = None,
        *,
        cwe_excel_path: Optional[str] = None,
        cwe_catalog=None,
        on_progress: Optional[ProgressCallback] = None,
        on_llm_trace: Optional[LlmTraceCallback] = None,
    ) -> tuple[pd.DataFrame, pd.Series, Dict[str, List[str]]]:
        """Run static extraction on each ELF and merge into one dataset."""
        excel = str(require_cwe_excel_path(self.config, cwe_excel_path))
        catalog = cwe_catalog
        if catalog is None:
            catalog, _, _ = load_cwe_resource(excel)
        all_structural: List[pd.DataFrame] = []
        all_peripheral: List[pd.DataFrame] = []
        all_embeddings: List[pd.DataFrame] = []
        all_cwe: Dict[str, List[str]] = {}

        elf_list = [Path(p).resolve() for p in elf_paths]
        n_elf = len(elf_list)

        for elf_idx, elf in enumerate(elf_list):
            self._validate_elf(elf)
            prefix = f"{elf.stem}_"
            span = int(72 / max(1, n_elf))
            base = int(72 * elf_idx / max(1, n_elf))
            if on_progress:
                on_progress(base, f"Firmware {elf_idx + 1}/{n_elf}: {elf.name}")
            stage_cb = chain_progress(on_progress, base, span) if on_progress else None
            roots = _resolve_source_roots(elf, source_roots_map)
            if not roots:
                raise ValueError(
                    f"No source folder for {elf.name}. Map each ELF to its project source root."
                )

            fw, _, _, cwe_labels = self.pipeline.run_static_stage(
                str(elf),
                roots,
                cwe_excel_path=excel,
                cwe_catalog=catalog,
                on_progress=stage_cb,
                on_llm_trace=on_llm_trace,
            )

            structural = self.pipeline.struct_feat.extract(fw)
            peripheral = self.pipeline.periph_feat.extract(fw)
            embeddings = self.pipeline.embed_feat.extract(fw)

            for df in (structural, peripheral, embeddings):
                df.index = [prefix + str(i) for i in df.index]
            prefixed_cwe = {prefix + k: v for k, v in cwe_labels.items()}
            all_structural.append(structural)
            all_peripheral.append(peripheral)
            all_embeddings.append(embeddings)
            all_cwe.update(prefixed_cwe)

        if not all_structural:
            raise ValueError("No features extracted from training ELFs.")

        feature_matrix = self.dataset_builder.build_feature_matrix(
            pd.concat(all_structural),
            pd.concat(all_peripheral) if all_peripheral else pd.DataFrame(),
            pd.concat(all_embeddings) if all_embeddings else pd.DataFrame(),
            all_cwe,
        )
        if feature_matrix.index.duplicated().any():
            feature_matrix = feature_matrix[~feature_matrix.index.duplicated(keep="first")]

        labels = self.dataset_builder.create_labels(all_cwe, feature_matrix.index)
        return feature_matrix, labels, all_cwe

    def train(
        self,
        elf_paths: Sequence[Union[str, Path]],
        *,
        model_name: str = "user_model.pkl",
        validation_split: float = 0.2,
        source_roots_map: Optional[Dict[str, List[str]]] = None,
        dataset_name: str = "user_training",
        cwe_excel_path: Optional[str] = None,
        ollama_model: Optional[str] = None,
        ollama_url: Optional[str] = None,
        on_progress: Optional[ProgressCallback] = None,
        on_llm_trace: Optional[LlmTraceCallback] = None,
    ) -> TrainingResult:
        """Build dataset from ELFs, firmware-level split, train and save model."""
        elf_list = [Path(p).resolve() for p in elf_paths]
        if len(elf_list) < 1:
            raise ValueError("Upload at least one debug ELF for training.")

        for elf in elf_list:
            self._validate_elf(elf)

        excel = str(require_cwe_excel_path(self.config, cwe_excel_path))
        cwe_label_mode, mode_desc = resolve_excel_label_mode(excel)

        if ollama_model or ollama_url:
            llm = self.config.setdefault("llm", {})
            if ollama_model:
                llm["model"] = ollama_model
            if ollama_url:
                llm["ollama_url"] = ollama_url

        catalog, _rows, desc = load_cwe_resource(excel)
        if on_progress:
            on_progress(0, f"Starting training… ({mode_desc or desc})")

        feature_matrix, labels, all_cwe = self.build_dataset_from_elfs(
            elf_list,
            source_roots_map=source_roots_map,
            cwe_excel_path=excel,
            cwe_catalog=catalog,
            on_progress=on_progress,
            on_llm_trace=on_llm_trace,
        )

        if on_progress:
            on_progress(74, "Splitting train/validation…")
        tr_x, tr_y, va_x, va_y, train_fw, val_fw = split_by_firmware(
            feature_matrix, labels, validation_split=validation_split
        )

        out_dir = self.dataset_output / dataset_name
        ensure_dir(out_dir)
        self.dataset_builder.save_dataset(feature_matrix, labels, out_dir)
        with open(out_dir / "cwe_labels.json", "w") as f:
            json.dump(all_cwe, f, indent=2)

        if on_progress:
            on_progress(82, "Training XGBoost model…")
        trainer = ModelTrainer(self.config)
        metrics = trainer.train_on_splits(tr_x, tr_y, va_x, va_y)
        if on_progress:
            on_progress(95, "Saving model…")
        model_path = trainer.save_model(model_name)
        if on_progress:
            on_progress(100, "Training complete")

        return TrainingResult(
            model_path=str(model_path),
            metrics=metrics,
            dataset_dir=str(out_dir),
            firmware_count=len(elf_list),
            function_count=len(feature_matrix),
            train_firmwares=train_fw,
            val_firmwares=val_fw,
        )
