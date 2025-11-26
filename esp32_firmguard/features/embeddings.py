"""LLM-based embedding and semantic feature extraction"""

import logging
from typing import Dict, Any, List
import pandas as pd
import numpy as np

logger = logging.getLogger(__name__)


class EmbeddingFeatureExtractor:
    """Extract semantic features using LLM embeddings"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.feature_config = config.get("features", {}).get("embeddings", {})
        self.model_name = self.feature_config.get("model_name", "gpt-4")
    
    def extract(self, firmware_obj) -> pd.DataFrame:
        """
        Extract embedding-based features for each function.
        
        In real implementation, this would call LLM API to get embeddings.
        For now, we generate mock embeddings based on function characteristics.
        
        Returns:
            DataFrame with rows=functions, columns=embedding features
        """
        functions = firmware_obj.functions
        if not functions:
            logger.warning("No functions found in firmware object")
            return pd.DataFrame()
        
        features = []
        
        for func_id, func_info in functions.items():
            func_features = self._extract_embedding_features(func_id, func_info)
            features.append(func_features)
        
        df = pd.DataFrame(features)
        df.set_index('func_id', inplace=True)
        
        logger.info(f"Extracted embedding features for {len(features)} functions")
        return df
    
    def _extract_embedding_features(self, func_id: str, func_info: Dict[str, Any]) -> Dict[str, Any]:
        """Extract embedding features for a single function"""
        func_name = func_info.get("name", "")
        calls = func_info.get("calls", [])
        strings = func_info.get("strings", [])
        
        features = {"func_id": func_id}
        
        # Mock embedding dimensions (in real implementation, these would come from LLM)
        # We'll create 16-dimensional mock embeddings
        embedding_dim = 16
        
        # Generate mock embeddings based on function characteristics
        # In real implementation, this would be: embedding = llm_client.get_embedding(function_code)
        mock_embedding = self._generate_mock_embedding(func_info)
        
        for i in range(embedding_dim):
            features[f"embedding_{i}"] = mock_embedding[i]
        
        # Semantic similarity scores to common vulnerability patterns (mock)
        vulnerability_patterns = [
            "buffer_overflow",
            "injection",
            "memory_corruption",
            "race_condition",
            "use_after_free"
        ]
        
        for pattern in vulnerability_patterns:
            # Mock similarity score (0-1)
            score = self._calculate_mock_similarity(func_info, pattern)
            features[f"similarity_{pattern}"] = score
        
        # Code complexity indicators from embeddings
        features["semantic_complexity"] = len(calls) * 0.1 + len(strings) * 0.05
        
        return features
    
    def _generate_mock_embedding(self, func_info: Dict[str, Any]) -> np.ndarray:
        """Generate mock embedding vector based on function characteristics"""
        # In real implementation, this would call LLM API
        # For now, create deterministic mock embeddings
        
        func_name = func_info.get("name", "")
        size = func_info.get("size", 0)
        instructions = func_info.get("instructions", 0)
        calls = func_info.get("calls", [])
        
        # Create deterministic embedding based on function characteristics
        np.random.seed(hash(func_name) % 2**32)
        embedding = np.random.randn(16)
        
        # Normalize
        embedding = embedding / (np.linalg.norm(embedding) + 1e-8)
        
        # Adjust based on function characteristics
        embedding[0] += size / 1000.0
        embedding[1] += instructions / 100.0
        embedding[2] += len(calls) / 10.0
        
        # Renormalize
        embedding = embedding / (np.linalg.norm(embedding) + 1e-8)
        
        return embedding
    
    def _calculate_mock_similarity(self, func_info: Dict[str, Any], pattern: str) -> float:
        """Calculate mock similarity to vulnerability pattern"""
        func_name = func_info.get("name", "").lower()
        calls = [c.lower() for c in func_info.get("calls", [])]
        
        # Check for pattern-related indicators
        pattern_keywords = {
            "buffer_overflow": ["strcpy", "memcpy", "sprintf", "buffer", "copy"],
            "injection": ["strcpy", "sprintf", "input", "parse", "execute"],
            "memory_corruption": ["malloc", "free", "memcpy", "pointer"],
            "race_condition": ["thread", "mutex", "lock", "shared"],
            "use_after_free": ["free", "malloc", "pointer", "dereference"]
        }
        
        keywords = pattern_keywords.get(pattern, [])
        matches = sum(1 for kw in keywords if kw in func_name or any(kw in c for c in calls))
        
        # Return similarity score (0-1)
        return min(matches / max(len(keywords), 1), 1.0)


