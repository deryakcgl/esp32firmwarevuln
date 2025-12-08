"""LLM-based embedding and semantic feature extraction"""

import logging
from typing import Dict, Any, List
import pandas as pd
import numpy as np
import os

logger = logging.getLogger(__name__)


class EmbeddingFeatureExtractor:
    """Extract semantic features using LLM embeddings"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.feature_config = config.get("features", {}).get("embeddings", {})
        self.model_name = self.feature_config.get("model_name", "text-embedding-3-small")
        
        # Get LLM config for API access
        self.llm_config = config.get("llm", {})
        self.provider = self.llm_config.get("provider", "ollama")
        self.ollama_url = self.llm_config.get("ollama_url", "http://localhost:11434")
        
        if self.provider == "openai":
            self.api_key = os.getenv("OPENAI_API_KEY") or self.llm_config.get("api_key")
        elif self.provider == "anthropic":
            self.api_key = os.getenv("ANTHROPIC_API_KEY") or self.llm_config.get("api_key")
        elif self.provider == "ollama":
            self.api_key = None
        else:
            self.api_key = self.llm_config.get("api_key")
    
    def extract(self, firmware_obj) -> pd.DataFrame:
        """
        Extract embedding-based features for each function using LLM embeddings.
        
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
        
        embedding_dim = 16
        embedding = self._generate_embedding(func_info)
        
        for i in range(embedding_dim):
            features[f"embedding_{i}"] = embedding[i]
        
        vulnerability_patterns = [
            "buffer_overflow",
            "injection",
            "memory_corruption",
            "race_condition",
            "use_after_free"
        ]
        
        for pattern in vulnerability_patterns:
            score = self._calculate_similarity(func_info, pattern)
            features[f"similarity_{pattern}"] = score
        
        # Code complexity indicators from embeddings
        features["semantic_complexity"] = len(calls) * 0.1 + len(strings) * 0.05
        
        return features
    
    def _generate_embedding(self, func_info: Dict[str, Any]) -> np.ndarray:
        """Generate embedding vector using LLM API"""
        func_name = func_info.get("name", "")
        func_code = func_info.get("code", "")
        calls = func_info.get("calls", [])
        strings = func_info.get("strings", [])
        
        # Build text representation of function
        text_parts = [func_name]
        if calls:
            text_parts.append("Calls: " + ", ".join(calls[:10]))  # Limit calls
        if strings:
            text_parts.append("Strings: " + ", ".join(strings[:5]))  # Limit strings
        if func_code:
            text_parts.append(func_code[:500])  # Limit code length
        
        text = " ".join(text_parts)
        
        use_llm = self.feature_config.get("use_llm_embeddings", False)
        
        if use_llm:
            try:
                if self.provider == "openai" and self.api_key:
                    return self._get_openai_embedding(text)
                elif self.provider == "ollama":
                    return self._get_ollama_embedding(text)
                else:
                    return self._get_deterministic_embedding(func_info)
            except Exception as e:
                logger.warning(f"LLM embedding failed: {e}. Using deterministic embedding.")
                return self._get_deterministic_embedding(func_info)
        else:
            return self._get_deterministic_embedding(func_info)
    
    def _get_openai_embedding(self, text: str) -> np.ndarray:
        """Get embedding from OpenAI API"""
        try:
            from openai import OpenAI
            client = OpenAI(api_key=self.api_key)
            
            # Use embedding model
            embedding_model = "text-embedding-3-small" if "embedding" not in self.model_name.lower() else self.model_name
            
            response = client.embeddings.create(
                model=embedding_model,
                input=text
            )
            embedding = np.array(response.data[0].embedding)
            
            # Resize to 16 dimensions if needed
            if len(embedding) > 16:
                # Use PCA-like approach: take first 16 dimensions
                embedding = embedding[:16]
            elif len(embedding) < 16:
                # Pad with zeros
                embedding = np.pad(embedding, (0, 16 - len(embedding)), mode='constant')
            
            return embedding
        except ImportError:
            raise ImportError("OpenAI library not installed. Install with: pip install openai")
        except Exception as e:
            raise Exception(f"OpenAI embedding API error: {e}")
    
    def _get_ollama_embedding(self, text: str) -> np.ndarray:
        """Get embedding from Ollama API"""
        try:
            import requests
            
            # Ollama embedding model (nomic-embed-text is good for embeddings)
            embedding_model = "nomic-embed-text"
            
            # Try /api/embeddings endpoint first
            try:
                response = requests.post(
                    f"{self.ollama_url}/api/embeddings",
                    json={
                        "model": embedding_model,
                        "prompt": text
                    },
                    timeout=30
                )
                response.raise_for_status()
                result = response.json()
                embedding = np.array(result.get("embedding", []))
            except requests.exceptions.HTTPError:
                # Fallback: use deterministic embedding (faster)
                raise Exception("Ollama embedding model not available, using deterministic embedding")
            
            # Resize to 16 dimensions if needed
            if len(embedding) > 16:
                embedding = embedding[:16]
            elif len(embedding) < 16:
                embedding = np.pad(embedding, (0, 16 - len(embedding)), mode='constant')
            
            return embedding
        except ImportError:
            raise ImportError("Requests library not installed. Install with: pip install requests")
        except requests.exceptions.ConnectionError:
            raise Exception(f"Ollama connection error. Make sure Ollama is running: ollama serve")
        except Exception as e:
            raise Exception(f"Ollama embedding API error: {e}")
    
    def _get_deterministic_embedding(self, func_info: Dict[str, Any]) -> np.ndarray:
        """Generate deterministic embedding based on function characteristics"""
        func_name = func_info.get("name", "")
        size = func_info.get("size", 0)
        instructions = func_info.get("instructions", 0)
        calls = func_info.get("calls", [])
        
        # Create deterministic embedding based on function characteristics
        np.random.seed(hash(func_name) % 2**32)
        embedding = np.random.randn(16)
        embedding = embedding / (np.linalg.norm(embedding) + 1e-8)
        embedding[0] += size / 1000.0
        embedding[1] += instructions / 100.0
        embedding[2] += len(calls) / 10.0
        embedding = embedding / (np.linalg.norm(embedding) + 1e-8)
        
        return embedding
    
    def _calculate_similarity(self, func_info: Dict[str, Any], pattern: str) -> float:
        """Calculate similarity to vulnerability pattern"""
        func_name = func_info.get("name", "").lower()
        calls = [c.lower() for c in func_info.get("calls", [])]
        
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


