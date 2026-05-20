import logging
from typing import Any, Dict, List

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)


class StructuralFeatureExtractor:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.feature_config = config.get("features", {}).get("structural", {})

    def extract(self, firmware_obj) -> pd.DataFrame:
        functions = firmware_obj.functions
        if not functions:
            logger.warning("No functions found in firmware object")
            return pd.DataFrame()

        features = []
        for func_id, func_info in functions.items():
            features.append(self._extract_function_features(func_id, func_info))

        df = pd.DataFrame(features)
        df.set_index("func_id", inplace=True)
        logger.info("Structural features: %d functions", len(features))
        return df

    def _extract_function_features(self, func_id: str, func_info: Dict[str, Any]) -> Dict[str, Any]:
        size = func_info.get("size", 0)
        instructions = func_info.get("instructions", 0)
        calls = list(func_info.get("calls") or [])
        strings = func_info.get("strings", [])
        asm_lc = (func_info.get("disassembly") or "").lower()
        if asm_lc:
            for tok in (
                "strcpy",
                "strcat",
                "sprintf",
                "vsprintf",
                "snprintf",
                "memcpy",
                "memmove",
                "strncpy",
                "scanf",
                "gets",
                "sscanf",
            ):
                if tok in asm_lc and not any((c or "").lower() == tok for c in calls):
                    calls.append(tok)

        dangerous_functions = ["strcpy", "sprintf", "gets", "scanf", "memcpy", "strcat"]
        func_name_lower = func_info.get("name", "").lower()
        input_validation_keywords = ["check", "validate", "verify", "sanitize", "filter"]
        output_sanitization_keywords = ["sanitize", "escape", "encode", "filter"]
        format_string_indicators = ["%s", "%d", "%x", "sprintf", "printf", "fprintf"]
        secret_patterns = ["password", "secret", "key", "token", "api_key", "auth"]
        conditional_keywords = ["if", "else", "switch", "case", "while", "for"]
        buffer_ops = ["memcpy", "memset", "memmove", "strcpy", "strncpy", "strcat"]
        alloc_ops = ["malloc", "calloc", "realloc", "free", "new", "delete"]

        features: Dict[str, Any] = {
            "func_id": func_id,
            "function_size": size,
            "instruction_count": instructions,
            "bytes_per_instruction": size / max(instructions, 1),
            "num_calls": len(calls),
            "num_unique_calls": len(set(calls)),
            "num_dangerous_calls": sum(1 for c in calls if c in dangerous_functions),
            "has_strcpy": 1 if "strcpy" in calls else 0,
            "has_sprintf": 1 if "sprintf" in calls else 0,
            "has_memcpy": 1 if "memcpy" in calls else 0,
            "num_strings": len(strings),
            "avg_string_length": np.mean([len(s) for s in strings]) if strings else 0,
            "entropy": self._calculate_entropy(func_info),
            "cyclomatic_complexity": self._estimate_cyclomatic_complexity(func_info),
            "num_branches": max(instructions // 10, 1),
            "num_loops": max(instructions // 20, 0),
            "call_graph_depth": self._estimate_call_graph_depth(calls),
            "has_input_validation": 1
            if any(
                kw in func_name_lower or any(kw in s.lower() for s in strings)
                for kw in input_validation_keywords
            )
            else 0,
            "has_output_sanitization": 1
            if any(
                kw in func_name_lower or any(kw in s.lower() for s in strings)
                for kw in output_sanitization_keywords
            )
            else 0,
            "has_format_strings": 1
            if any(
                any(indicator in s for s in strings) or any(indicator in c for c in calls)
                for indicator in format_string_indicators
            )
            else 0,
            "has_hardcoded_secrets": 1
            if any(pattern in s.lower() for s in strings for pattern in secret_patterns)
            else 0,
            "num_conditionals": sum(
                1 for c in calls if any(kw in c.lower() for kw in conditional_keywords)
            ),
            "num_buffer_ops": sum(1 for c in calls if any(op in c.lower() for op in buffer_ops)),
            "num_allocations": sum(1 for c in calls if any(op in c.lower() for op in alloc_ops)),
        }
        features["nesting_depth"] = min(features["cyclomatic_complexity"] // 3, 5)
        features["has_memory_management"] = 1 if features["num_allocations"] > 0 else 0
        return features

    def _estimate_call_graph_depth(self, calls: List[str]) -> int:
        n = len(calls)
        if n == 0:
            return 0
        if n < 3:
            return 1
        if n < 6:
            return 2
        if n < 10:
            return 3
        return 4

    def _calculate_entropy(self, func_info: Dict[str, Any]) -> float:
        if "entropy" in func_info:
            return func_info["entropy"]
        size = func_info.get("size", 0)
        instructions = func_info.get("instructions", 0)
        calls = func_info.get("calls", [])
        base_entropy = 3.5
        size_factor = min(size / 1000.0, 2.0) * 0.5
        instruction_factor = min(instructions / 100.0, 2.0) * 0.3
        call_factor = min(len(calls) / 10.0, 1.0) * 0.2
        return min(base_entropy + size_factor + instruction_factor + call_factor, 8.0)

    def _estimate_cyclomatic_complexity(self, func_info: Dict[str, Any]) -> int:
        instructions = func_info.get("instructions", 0)
        calls = func_info.get("calls", [])
        return int(1 + len(calls) * 0.5 + instructions // 15)
