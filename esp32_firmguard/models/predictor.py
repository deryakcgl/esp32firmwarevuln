"""Vulnerability prediction using trained models"""

import logging
from dataclasses import dataclass
from typing import List, Dict, Any, Optional
import pandas as pd
import numpy as np
from pathlib import Path

logger = logging.getLogger(__name__)

try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False


@dataclass
class Prediction:
    """Single vulnerability prediction"""
    func_id: str
    score: float  # Vulnerability probability (0-1)
    cwe: List[str]  # Associated CWE categories
    is_vulnerable: bool  # Binary prediction based on threshold


class VulnerabilityPredictor:
    """Predict vulnerabilities using trained models"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.model_config = config.get("model", {})
        self.threshold = self.model_config.get("threshold", 0.7)
        self.model = None
        self.model_loaded = False
    
    def load_model(self, model_path: Optional[Path] = None) -> None:
        """Load trained model"""
        if model_path is None:
            model_output_dir = Path(self.config.get("paths", {}).get("model_output", "./output/models"))
            model_path = model_output_dir / "vulnerability_model.pkl"
        
        if not model_path.exists():
            logger.warning(f"Model not found at {model_path}. Using mock predictions.")
            self.model = None
            self.model_loaded = False
            return
        
        try:
            if XGBOOST_AVAILABLE:
                try:
                    self.model = xgb.XGBClassifier()
                    self.model.load_model(str(model_path))
                    self.model_loaded = True
                    logger.info(f"Loaded XGBoost model from {model_path}")
                    return
                except:
                    pass
            
            # Try loading as pickle
            import pickle
            with open(model_path, 'rb') as f:
                self.model = pickle.load(f)
                self.model_loaded = isinstance(self.model, dict) or hasattr(self.model, 'predict_proba')
                logger.info(f"Loaded model from {model_path}")
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            self.model = None
            self.model_loaded = False
    
    def predict(self, feature_matrix: pd.DataFrame, cwe_labels: Optional[Dict[str, List[str]]] = None) -> List[Prediction]:
        """
        Predict vulnerabilities for functions.
        
        Args:
            feature_matrix: Feature matrix (functions x features)
            cwe_labels: Optional CWE labels dictionary
        
        Returns:
            List of Prediction objects
        """
        if feature_matrix.empty:
            logger.warning("Empty feature matrix provided")
            return []
        
        if not self.model_loaded:
            self.load_model()
        
        # Get predictions
        if self.model_loaded and self.model is not None:
            if hasattr(self.model, 'predict_proba'):
                probabilities = self.model.predict_proba(feature_matrix)[:, 1]
            else:
                probabilities = self._rule_based_predict_proba(feature_matrix)
        else:
            probabilities = self._rule_based_predict_proba(feature_matrix)
        
        # Create predictions
        predictions = []
        for func_id, prob in zip(feature_matrix.index, probabilities):
            cwe_list = cwe_labels.get(func_id, []) if cwe_labels else []
            predictions.append(Prediction(
                func_id=func_id,
                score=float(prob),
                cwe=cwe_list,
                is_vulnerable=prob >= self.threshold
            ))
        
        logger.info(f"Made predictions for {len(predictions)} functions. "
                   f"{sum(p.is_vulnerable for p in predictions)} flagged as vulnerable.")
        
        return predictions
    
    def _rule_based_predict_proba(self, feature_matrix: pd.DataFrame) -> np.ndarray:
        """Generate rule-based prediction probabilities using feature heuristics"""
        probabilities = np.zeros(len(feature_matrix))
        
        # Weighted feature-based scoring
        feature_weights = {
            'has_strcpy': 0.25,
            'has_sprintf': 0.20,
            'has_memcpy': 0.15,
            'num_dangerous_calls': 0.20,
            'entropy': 0.10,
            'cyclomatic_complexity': 0.10
        }
        
        # Apply feature weights
        for feature, weight in feature_weights.items():
            if feature in feature_matrix.columns:
                # Normalize feature values to [0, 1] range
                feat_values = feature_matrix[feature].values
                if feat_values.max() > feat_values.min():
                    feat_normalized = (feat_values - feat_values.min()) / (feat_values.max() - feat_values.min())
                else:
                    feat_normalized = feat_values
                probabilities += feat_normalized * weight
        
        # Check for CWE labels (strong indicator)
        cwe_cols = [col for col in feature_matrix.columns if col.startswith('CWE-')]
        if cwe_cols:
            cwe_score = feature_matrix[cwe_cols].sum(axis=1).values
            probabilities += np.minimum(cwe_score * 0.3, 0.5)  # Cap CWE contribution
        
        # High entropy + dangerous calls = higher risk
        if 'entropy' in feature_matrix.columns and 'num_dangerous_calls' in feature_matrix.columns:
            high_entropy = (feature_matrix['entropy'] > 7.0).astype(float)
            has_dangerous = (feature_matrix['num_dangerous_calls'] > 0).astype(float)
            probabilities += (high_entropy * has_dangerous).values * 0.15
        
        # Normalize to [0, 1] using sigmoid
        probabilities = 1 / (1 + np.exp(-probabilities * 2))  # Scale factor for better distribution
        
        # Ensure probabilities are in valid range
        probabilities = np.clip(probabilities, 0.0, 1.0)
        
        return probabilities

