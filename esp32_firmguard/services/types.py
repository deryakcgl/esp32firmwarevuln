from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class FunctionFinding:
    func_id: str
    name: str
    score: float
    is_vulnerable: bool
    cwe: List[str]
    address: Optional[str] = None
    source_file: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    resolved_source_path: Optional[str] = None
    source_snippet: Optional[Dict[str, Any]] = None
    disassembly: Optional[str] = None
    llm_trace: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "func_id": self.func_id,
            "name": self.name,
            "score": self.score,
            "is_vulnerable": self.is_vulnerable,
            "cwe": self.cwe,
            "address": self.address,
            "source_file": self.source_file,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "resolved_source_path": self.resolved_source_path,
            "source_snippet": self.source_snippet,
            "disassembly": self.disassembly,
            "llm_trace": self.llm_trace,
        }


@dataclass
class AnalysisResult:
    firmware_path: str
    elf_path: str
    model_path: Optional[str]
    findings: List[FunctionFinding]
    timings: Dict[str, Any] = field(default_factory=dict)
    functions_with_source: int = 0
    functions_total: int = 0
    vulnerable_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "firmware_path": self.firmware_path,
            "elf_path": self.elf_path,
            "model_path": self.model_path,
            "functions_with_source": self.functions_with_source,
            "functions_total": self.functions_total,
            "vulnerable_count": self.vulnerable_count,
            "timings": self.timings,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class TrainingResult:
    model_path: str
    metrics: Dict[str, float]
    dataset_dir: str
    firmware_count: int
    function_count: int
    train_firmwares: List[str] = field(default_factory=list)
    val_firmwares: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "model_path": self.model_path,
            "metrics": self.metrics,
            "dataset_dir": self.dataset_dir,
            "firmware_count": self.firmware_count,
            "function_count": self.function_count,
            "train_firmwares": self.train_firmwares,
            "val_firmwares": self.val_firmwares,
        }
