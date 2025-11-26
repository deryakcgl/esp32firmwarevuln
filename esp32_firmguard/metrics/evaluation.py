"""Evaluation metrics (Precision, Recall, F1, VCR, SRI)"""

import logging
from typing import Dict, Any, List, Optional
import numpy as np
from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score

from ..models.predictor import Prediction
from ..validation.fuzzing import FuzzingResult
from ..validation.hw_power import PowerTraceResult

logger = logging.getLogger(__name__)


class EvaluationMetrics:
    """Compute evaluation metrics for vulnerability prediction"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.metrics_config = config.get("metrics", {})
        self.compute_vcr = self.metrics_config.get("compute_vcr", True)
        self.compute_sri = self.metrics_config.get("compute_sri", True)
        self.sri_weights = self.metrics_config.get("sri_weights", {
            "precision": 0.25,
            "recall": 0.25,
            "f1": 0.30,
            "vcr": 0.20
        })
    
    def compute_all(
        self,
        ground_truth: Dict[str, int],
        predictions: List[Prediction],
        fuzz_results: Optional[Dict[str, FuzzingResult]] = None,
        hw_results: Optional[Dict[str, PowerTraceResult]] = None
    ) -> Dict[str, float]:
        """
        Compute all evaluation metrics.
        
        Args:
            ground_truth: Dictionary mapping func_id -> 0/1 (0=safe, 1=vulnerable)
            predictions: List of Prediction objects
            fuzz_results: Optional fuzzing validation results
            hw_results: Optional hardware power validation results
        
        Returns:
            Dictionary with all computed metrics
        """
        # Convert predictions to binary labels
        y_true, y_pred = self._prepare_labels(ground_truth, predictions)
        
        if len(y_true) == 0 or len(y_pred) == 0:
            logger.warning("Empty labels provided for evaluation")
            return self._empty_metrics()
        
        # Basic classification metrics
        precision = precision_score(y_true, y_pred, zero_division=0)
        recall = recall_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)
        accuracy = accuracy_score(y_true, y_pred)
        
        metrics = {
            "precision": float(precision),
            "recall": float(recall),
            "f1_score": float(f1),
            "accuracy": float(accuracy),
            "true_positives": int(np.sum((y_true == 1) & (y_pred == 1))),
            "false_positives": int(np.sum((y_true == 0) & (y_pred == 1))),
            "true_negatives": int(np.sum((y_true == 0) & (y_pred == 0))),
            "false_negatives": int(np.sum((y_true == 1) & (y_pred == 0)))
        }
        
        # Validation Consistency Ratio (VCR)
        if self.compute_vcr:
            vcr = self._compute_vcr(predictions, fuzz_results, hw_results)
            metrics["vcr"] = float(vcr)
        else:
            metrics["vcr"] = 0.0
        
        # Security Reliability Index (SRI)
        if self.compute_sri:
            sri = self._compute_sri(
                metrics["precision"],
                metrics["recall"],
                metrics["f1_score"],
                metrics["vcr"]
            )
            metrics["sri"] = float(sri)
        else:
            metrics["sri"] = 0.0
        
        logger.info(f"Computed metrics: P={precision:.3f}, R={recall:.3f}, F1={f1:.3f}, VCR={metrics['vcr']:.3f}, SRI={metrics['sri']:.3f}")
        
        return metrics
    
    def _prepare_labels(
        self,
        ground_truth: Dict[str, int],
        predictions: List[Prediction]
    ) -> tuple[np.ndarray, np.ndarray]:
        """Prepare ground truth and predicted labels"""
        # Get common function IDs
        pred_dict = {p.func_id: p.is_vulnerable for p in predictions}
        common_ids = set(ground_truth.keys()) & set(pred_dict.keys())
        
        if not common_ids:
            logger.warning("No common function IDs between ground truth and predictions")
            return np.array([]), np.array([])
        
        y_true = np.array([ground_truth[func_id] for func_id in sorted(common_ids)])
        y_pred = np.array([int(pred_dict[func_id]) for func_id in sorted(common_ids)])
        
        return y_true, y_pred
    
    def _compute_vcr(
        self,
        predictions: List[Prediction],
        fuzz_results: Optional[Dict[str, FuzzingResult]] = None,
        hw_results: Optional[Dict[str, PowerTraceResult]] = None
    ) -> float:
        """
        Compute Validation Consistency Ratio.
        
        VCR = Nc / Np
        where:
        - Nc = number of predictions confirmed by validation (fuzzing or hardware)
        - Np = total number of positive predictions
        """
        if not predictions:
            return 0.0
        
        # Get high-risk predictions (vulnerable functions)
        high_risk_preds = [p for p in predictions if p.is_vulnerable]
        Np = len(high_risk_preds)
        
        if Np == 0:
            return 0.0
        
        # Count confirmed predictions
        Nc = 0
        
        for pred in high_risk_preds:
            confirmed = False
            
            # Check fuzzing results
            if fuzz_results and pred.func_id in fuzz_results:
                fuzz_result = fuzz_results[pred.func_id]
                if fuzz_result.crashes_found > 0:
                    confirmed = True
            
            # Check hardware results
            if not confirmed and hw_results and pred.func_id in hw_results:
                hw_result = hw_results[pred.func_id]
                if hw_result.is_anomaly:
                    confirmed = True
            
            if confirmed:
                Nc += 1
        
        vcr = Nc / Np if Np > 0 else 0.0
        return vcr
    
    def _compute_sri(self, precision: float, recall: float, f1: float, vcr: float) -> float:
        """
        Compute Security Reliability Index.
        
        SRI = w1*P + w2*R + w3*F1 + w4*VCR
        """
        weights = self.sri_weights
        sri = (
            weights.get("precision", 0.25) * precision +
            weights.get("recall", 0.25) * recall +
            weights.get("f1", 0.30) * f1 +
            weights.get("vcr", 0.20) * vcr
        )
        return sri
    
    def _empty_metrics(self) -> Dict[str, float]:
        """Return empty metrics dictionary"""
        return {
            "precision": 0.0,
            "recall": 0.0,
            "f1_score": 0.0,
            "accuracy": 0.0,
            "vcr": 0.0,
            "sri": 0.0,
            "true_positives": 0,
            "false_positives": 0,
            "true_negatives": 0,
            "false_negatives": 0
        }


