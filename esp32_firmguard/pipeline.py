"""Main pipeline orchestrator for ESP32 firmware security analysis"""

import logging
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path
import pandas as pd

from esp32_firmguard.ingestion.extractor import FirmwareExtractor
from esp32_firmguard.features.structural import StructuralFeatureExtractor
from esp32_firmguard.features.peripheral import PeripheralFeatureExtractor
from esp32_firmguard.features.embeddings import EmbeddingFeatureExtractor
from esp32_firmguard.labeling.cwe_labeler import CWELabeler
from esp32_firmguard.models.dataset import DatasetBuilder
from esp32_firmguard.models.predictor import VulnerabilityPredictor, Prediction
from esp32_firmguard.validation.fuzzing import FuzzingValidator, FuzzingResult
from esp32_firmguard.validation.hw_power import HardwarePowerValidator, PowerTraceResult
from esp32_firmguard.metrics.evaluation import EvaluationMetrics

logger = logging.getLogger(__name__)


class FirmwareSecurityPipeline:
    """
    End-to-end pipeline for firmware security analysis:
    
    1. Firmware extraction
    2. Feature extraction (structural, peripheral, embeddings)
    3. LLM-based CWE labeling
    4. Risk prediction
    5. Dynamic validation (fuzzing)
    6. Physical validation (hardware power analysis)
    7. Metrics evaluation
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        
        # Initialize all components
        self.extractor = FirmwareExtractor(config)
        self.struct_feat = StructuralFeatureExtractor(config)
        self.periph_feat = PeripheralFeatureExtractor(config)
        self.embed_feat = EmbeddingFeatureExtractor(config)
        self.cwe_labeler = CWELabeler(config)
        self.dataset_builder = DatasetBuilder(config)
        self.predictor = VulnerabilityPredictor(config)
        self.fuzz_validator = FuzzingValidator(config)
        self.hw_validator = HardwarePowerValidator(config)
        self.metrics = EvaluationMetrics(config)
        
        logger.info("Initialized FirmwareSecurityPipeline")
    
    def run_static_stage(self, firmware_path: str, source: str = "unknown") -> Tuple[Any, pd.DataFrame, List[Prediction], Dict[str, List[str]]]:
        """
        Run static analysis stage:
        - Extract firmware
        - Extract features
        - Label with CWE categories
        - Predict vulnerabilities
        
        Args:
            firmware_path: Path to firmware binary
            source: Source of firmware (e.g., "tasmota", "esp-idf")
        
        Returns:
            Tuple of (firmware_obj, feature_matrix, predictions, cwe_labels)
        """
        logger.info("=" * 60)
        logger.info("Starting static analysis stage")
        logger.info("=" * 60)
        
        # 1. Extract firmware
        logger.info("Step 1: Extracting firmware...")
        fw = self.extractor.extract(firmware_path, source)
        logger.info(f"Extracted {len(fw.functions)} functions")
        
        # 2. Extract features
        logger.info("Step 2: Extracting structural features...")
        structural = self.struct_feat.extract(fw)
        
        logger.info("Step 3: Extracting peripheral features...")
        peripheral = self.periph_feat.extract(fw)
        
        logger.info("Step 4: Extracting embedding features...")
        embeddings = self.embed_feat.extract(fw)
        
        # 3. Label with CWE categories
        logger.info("Step 5: Labeling functions with CWE categories...")
        cwe_labels = self.cwe_labeler.label(fw)
        
        # 4. Build feature matrix
        logger.info("Step 6: Building feature matrix...")
        feature_matrix = self.dataset_builder.build_feature_matrix(
            structural, peripheral, embeddings, cwe_labels
        )
        
        # 5. Predict vulnerabilities
        logger.info("Step 7: Predicting vulnerabilities...")
        self.predictor.load_model()  # Load model if available
        predictions = self.predictor.predict(feature_matrix, cwe_labels)
        
        logger.info("=" * 60)
        logger.info("Static analysis stage complete")
        logger.info(f"Found {sum(p.is_vulnerable for p in predictions)} vulnerable functions")
        logger.info("=" * 60)
        
        return fw, feature_matrix, predictions, cwe_labels
    
    def run_validation_stage(
        self,
        fw: Any,
        predictions: List[Prediction],
        threshold: Optional[float] = None
    ) -> Tuple[Dict[str, FuzzingResult], Dict[str, PowerTraceResult]]:
        """
        Run validation stage:
        - Select high-risk functions
        - Run fuzzing validation
        - Run hardware power validation
        
        Args:
            fw: FirmwareObject
            predictions: List of predictions from static stage
            threshold: Risk threshold (default from config)
        
        Returns:
            Tuple of (fuzz_results, hw_results)
        """
        logger.info("=" * 60)
        logger.info("Starting validation stage")
        logger.info("=" * 60)
        
        # Select high-risk functions
        if threshold is None:
            threshold = self.config.get("model", {}).get("threshold", 0.7)
        
        high_risk_funcs = self._select_high_risk(predictions, threshold)
        logger.info(f"Selected {len(high_risk_funcs)} high-risk functions for validation")
        
        # Run fuzzing validation
        logger.info("Step 1: Running fuzzing validation...")
        fuzz_results = self.fuzz_validator.run(fw, high_risk_funcs)
        
        # Run hardware power validation
        logger.info("Step 2: Running hardware power validation...")
        hw_results = self.hw_validator.run(fw, high_risk_funcs)
        
        logger.info("=" * 60)
        logger.info("Validation stage complete")
        logger.info(f"Fuzzing: {len(fuzz_results)} functions analyzed")
        logger.info(f"Hardware: {len(hw_results)} functions analyzed")
        logger.info("=" * 60)
        
        return fuzz_results, hw_results
    
    def evaluate(
        self,
        ground_truth: Dict[str, int],
        predictions: List[Prediction],
        fuzz_results: Optional[Dict[str, FuzzingResult]] = None,
        hw_results: Optional[Dict[str, PowerTraceResult]] = None
    ) -> Dict[str, float]:
        """
        Evaluate predictions against ground truth.
        
        Args:
            ground_truth: Dictionary mapping func_id -> 0/1
            predictions: List of predictions
            fuzz_results: Optional fuzzing results
            hw_results: Optional hardware power results
        
        Returns:
            Dictionary with evaluation metrics
        """
        logger.info("=" * 60)
        logger.info("Computing evaluation metrics")
        logger.info("=" * 60)
        
        metrics = self.metrics.compute_all(
            ground_truth=ground_truth,
            predictions=predictions,
            fuzz_results=fuzz_results,
            hw_results=hw_results
        )
        
        logger.info("=" * 60)
        logger.info("Evaluation complete")
        logger.info(f"Precision: {metrics['precision']:.3f}")
        logger.info(f"Recall: {metrics['recall']:.3f}")
        logger.info(f"F1-Score: {metrics['f1_score']:.3f}")
        logger.info(f"VCR: {metrics['vcr']:.3f}")
        logger.info(f"SRI: {metrics['sri']:.3f}")
        logger.info("=" * 60)
        
        return metrics
    
    def run_full_pipeline(
        self,
        firmware_path: str,
        source: str = "unknown",
        ground_truth: Optional[Dict[str, int]] = None,
        run_validation: bool = True,
        run_evaluation: bool = False
    ) -> Dict[str, Any]:
        """
        Run the complete pipeline from start to finish.
        
        Args:
            firmware_path: Path to firmware binary
            source: Source of firmware
            ground_truth: Optional ground truth labels for evaluation
            run_validation: Whether to run validation stage
            run_evaluation: Whether to run evaluation (requires ground_truth)
        
        Returns:
            Dictionary with all results
        """
        logger.info("=" * 80)
        logger.info("Starting full pipeline execution")
        logger.info("=" * 80)
        
        results = {}
        
        # Static analysis stage
        fw, feature_matrix, predictions, cwe_labels = self.run_static_stage(firmware_path, source)
        results["firmware"] = fw
        results["feature_matrix"] = feature_matrix
        results["predictions"] = predictions
        results["cwe_labels"] = cwe_labels
        
        # Validation stage
        if run_validation:
            fuzz_results, hw_results = self.run_validation_stage(fw, predictions)
            results["fuzz_results"] = fuzz_results
            results["hw_results"] = hw_results
        else:
            results["fuzz_results"] = {}
            results["hw_results"] = {}
        
        # Evaluation stage
        if run_evaluation and ground_truth:
            metrics = self.evaluate(
                ground_truth=ground_truth,
                predictions=predictions,
                fuzz_results=results.get("fuzz_results"),
                hw_results=results.get("hw_results")
            )
            results["metrics"] = metrics
        else:
            results["metrics"] = None
        
        logger.info("=" * 80)
        logger.info("Full pipeline execution complete")
        logger.info("=" * 80)
        
        return results
    
    def _select_high_risk(self, predictions: List[Prediction], threshold: float) -> List[str]:
        """Select high-risk functions based on prediction scores"""
        return [p.func_id for p in predictions if p.score >= threshold]


