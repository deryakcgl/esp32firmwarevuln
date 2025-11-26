"""Structural feature extraction (entropy, CFG metrics, etc.)"""

import logging
import math
from typing import Dict, Any, List
import pandas as pd
import numpy as np

logger = logging.getLogger(__name__)


class StructuralFeatureExtractor:
    """Extract structural features from firmware functions"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.feature_config = config.get("features", {}).get("structural", {})
    
    def extract(self, firmware_obj) -> pd.DataFrame:
        """
        Extract structural features for each function.
        
        Returns:
            DataFrame with rows=functions, columns=structural features
        """
        functions = firmware_obj.functions
        if not functions:
            logger.warning("No functions found in firmware object")
            return pd.DataFrame()
        
        features = []
        
        for func_id, func_info in functions.items():
            func_features = self._extract_function_features(func_id, func_info)
            features.append(func_features)
        
        df = pd.DataFrame(features)
        df.set_index('func_id', inplace=True)
        
        logger.info(f"Extracted structural features for {len(features)} functions")
        return df
    
    def _extract_function_features(self, func_id: str, func_info: Dict[str, Any]) -> Dict[str, Any]:
        """Extract features for a single function"""
        size = func_info.get("size", 0)
        instructions = func_info.get("instructions", 0)
        calls = func_info.get("calls", [])
        strings = func_info.get("strings", [])
        
        # Basic size metrics
        features = {
            "func_id": func_id,
            "function_size": size,
            "instruction_count": instructions,
            "bytes_per_instruction": size / max(instructions, 1),
        }
        
        # Call metrics
        features["num_calls"] = len(calls)
        features["num_unique_calls"] = len(set(calls))
        
        # Dangerous function indicators
        dangerous_functions = ["strcpy", "sprintf", "gets", "scanf", "memcpy", "strcat"]
        features["num_dangerous_calls"] = sum(1 for c in calls if c in dangerous_functions)
        features["has_strcpy"] = 1 if "strcpy" in calls else 0
        features["has_sprintf"] = 1 if "sprintf" in calls else 0
        features["has_memcpy"] = 1 if "memcpy" in calls else 0
        
        # String metrics
        features["num_strings"] = len(strings)
        features["avg_string_length"] = np.mean([len(s) for s in strings]) if strings else 0
        
        # Entropy (mock calculation - in real implementation, use actual binary data)
        features["entropy"] = self._calculate_entropy(func_info)
        
        # Cyclomatic complexity (simplified approximation)
        features["cyclomatic_complexity"] = self._estimate_cyclomatic_complexity(func_info)
        
        # Control flow metrics (mock)
        features["num_branches"] = max(instructions // 10, 1)  # Rough estimate
        features["num_loops"] = max(instructions // 20, 0)
        
        return features
    
    def _calculate_entropy(self, func_info: Dict[str, Any]) -> float:
        """Calculate Shannon entropy from function binary data"""
        # Try to get entropy from function info (if extracted from real tools)
        if "entropy" in func_info:
            return func_info["entropy"]
        
        # Fallback: calculate from function characteristics
        # This is used when real binary data is not available
        size = func_info.get("size", 0)
        instructions = func_info.get("instructions", 0)
        calls = func_info.get("calls", [])
        
        # Estimate entropy based on function characteristics
        # More complex functions (more calls, larger size) tend to have higher entropy
        base_entropy = 3.5
        size_factor = min(size / 1000.0, 2.0) * 0.5
        instruction_factor = min(instructions / 100.0, 2.0) * 0.3
        call_factor = min(len(calls) / 10.0, 1.0) * 0.2
        
        entropy = base_entropy + size_factor + instruction_factor + call_factor
        return min(entropy, 8.0)  # Cap at 8.0 (max entropy for bytes)
    
    def _estimate_cyclomatic_complexity(self, func_info: Dict[str, Any]) -> int:
        """Estimate cyclomatic complexity (simplified)"""
        instructions = func_info.get("instructions", 0)
        calls = func_info.get("calls", [])
        
        # Rough estimate: base complexity + calls + instruction-based branches
        base = 1
        call_complexity = len(calls) * 0.5
        branch_complexity = instructions // 15
        
        return int(base + call_complexity + branch_complexity)

