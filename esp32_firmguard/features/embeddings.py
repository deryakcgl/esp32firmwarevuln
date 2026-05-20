import logging
from typing import Any, Dict

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

_PATTERNS = {
    "buffer_overflow": ["strcpy", "memcpy", "sprintf", "buffer", "copy"],
    "injection": ["strcpy", "sprintf", "input", "parse", "execute"],
    "memory_corruption": ["malloc", "free", "memcpy", "pointer"],
    "race_condition": ["thread", "mutex", "lock", "shared"],
    "use_after_free": ["free", "malloc", "pointer", "dereference"],
}


class EmbeddingFeatureExtractor:
    def __init__(self, config: Dict[str, Any]):
        self.config = config

    def extract(self, firmware_obj) -> pd.DataFrame:
        functions = firmware_obj.functions or {}
        if not functions:
            return pd.DataFrame()

        rows = []
        for func_id, info in functions.items():
            row: Dict[str, Any] = {"func_id": func_id}
            emb = self._embedding_vector(info)
            for i, v in enumerate(emb):
                row[f"embedding_{i}"] = v
            for name, keywords in _PATTERNS.items():
                row[f"similarity_{name}"] = self._pattern_score(info, keywords)
            row["semantic_complexity"] = len(info.get("calls") or []) * 0.1 + len(
                info.get("strings") or []
            ) * 0.05
            rows.append(row)

        df = pd.DataFrame(rows).set_index("func_id")
        logger.info("Embedding features: %d functions", len(df))
        return df

    def _embedding_vector(self, func_info: Dict[str, Any]) -> np.ndarray:
        name = func_info.get("name", "")
        size = float(func_info.get("size") or 0)
        instructions = float(func_info.get("instructions") or 0)
        calls = len(func_info.get("calls") or [])
        np.random.seed(hash(name) % 2**32)
        v = np.random.randn(16)
        v[0] += size / 1000.0
        v[1] += instructions / 100.0
        v[2] += calls / 10.0
        norm = np.linalg.norm(v) + 1e-8
        return v / norm

    def _pattern_score(self, func_info: Dict[str, Any], keywords: list) -> float:
        name = (func_info.get("name") or "").lower()
        calls = [c.lower() for c in func_info.get("calls") or []]
        hits = sum(1 for kw in keywords if kw in name or any(kw in c for c in calls))
        return min(hits / max(len(keywords), 1), 1.0)
