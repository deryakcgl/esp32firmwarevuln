#!/usr/bin/env python3
"""Baseline comparison: Compare with other methods and models"""

import sys
from pathlib import Path
import json
import pandas as pd
import numpy as np
from typing import Dict, List, Any, Optional
import argparse
import time

sys.path.insert(0, str(Path(__file__).parent.parent))

from esp32_firmguard.utils import load_config, setup_logging
from esp32_firmguard.pipeline import FirmwareSecurityPipeline
from esp32_firmguard.models.trainer import ModelTrainer
from esp32_firmguard.models.predictor import VulnerabilityPredictor
from esp32_firmguard.metrics.evaluation import EvaluationMetrics
from esp32_firmguard.models.dataset import DatasetBuilder


class BaselineComparator:
    """Compare different models and methods"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.metrics = EvaluationMetrics(config)
    
    def compare_models(
        self,
        feature_matrix: pd.DataFrame,
        labels: pd.Series,
        test_feature_matrix: pd.DataFrame,
        test_labels: pd.Series
    ) -> Dict[str, Dict[str, float]]:
        """Compare different ML models"""
        results = {}
        
        models_to_test = [
            ("xgboost", "XGBoost"),
            ("random_forest", "Random Forest"),
            ("rule_based", "Rule-Based")
        ]
        
        for model_type, model_name in models_to_test:
            print(f"Training {model_name}...")
            
            try:
                # Train model
                trainer = ModelTrainer(self.config)
                trainer.model_type = model_type
                train_metrics = trainer.train(feature_matrix, labels, validation_split=0.2)
                
                # Predict on test set
                predictor = VulnerabilityPredictor(self.config)
                predictor.model = trainer.model
                predictor.model_loaded = True
                
                predictions = predictor.predict(test_feature_matrix)
                
                # Convert to binary labels
                y_true = test_labels.values
                y_pred = [1 if p.is_vulnerable else 0 for p in predictions]
                
                # Compute metrics
                from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score
                
                precision = precision_score(y_true, y_pred, zero_division=0)
                recall = recall_score(y_true, y_pred, zero_division=0)
                f1 = f1_score(y_true, y_pred, zero_division=0)
                accuracy = accuracy_score(y_true, y_pred)
                
                results[model_name] = {
                    "precision": float(precision),
                    "recall": float(recall),
                    "f1_score": float(f1),
                    "accuracy": float(accuracy),
                    "train_metrics": train_metrics
                }
                
                print(f"  {model_name}: F1={f1:.3f}, Precision={precision:.3f}, Recall={recall:.3f}")
                
            except Exception as e:
                print(f"  Error training {model_name}: {e}")
                results[model_name] = {"error": str(e)}
        
        return results
    
    def compare_feature_sets(
        self,
        firmware_path: str,
        ground_truth: Dict[str, int]
    ) -> Dict[str, Dict[str, float]]:
        """Compare different feature combinations (ablation study)"""
        results = {}
        
        # Initialize pipeline
        pipeline = FirmwareSecurityPipeline(self.config)
        
        # Extract all features
        fw = pipeline.extractor.extract(firmware_path, "test")
        
        structural = pipeline.struct_feat.extract(fw)
        peripheral = pipeline.periph_feat.extract(fw)
        embeddings = pipeline.embed_feat.extract(fw)
        cwe_labels = pipeline.cwe_labeler.label(fw)
        
        dataset_builder = DatasetBuilder(self.config)
        
        # Test different feature combinations
        feature_combinations = [
            ("structural_only", [structural], None, None),
            ("structural_peripheral", [structural, peripheral], None, None),
            ("structural_embeddings", [structural], None, embeddings),
            ("structural_peripheral_embeddings", [structural, peripheral], None, embeddings),
            ("full_pipeline", [structural, peripheral], cwe_labels, embeddings)
        ]
        
        for combo_name, struct_list, cwe, emb in feature_combinations:
            print(f"Testing {combo_name}...")
            
            try:
                # Build feature matrix
                if len(struct_list) == 1:
                    struct = struct_list[0]
                    periph = pd.DataFrame() if "peripheral" not in combo_name else peripheral
                else:
                    struct = struct_list[0]
                    periph = struct_list[1]
                
                feature_matrix = dataset_builder.build_feature_matrix(
                    struct, periph, emb if emb is not None else pd.DataFrame(), cwe if cwe else {}
                )
                
                # Predict
                pipeline.predictor.load_model()
                predictions = pipeline.predictor.predict(feature_matrix, cwe if cwe else {})
                
                # Evaluate
                metrics = pipeline.evaluate(ground_truth, predictions)
                
                results[combo_name] = {
                    "precision": metrics["precision"],
                    "recall": metrics["recall"],
                    "f1_score": metrics["f1_score"],
                    "accuracy": metrics["accuracy"],
                    "num_features": len(feature_matrix.columns)
                }
                
                print(f"  {combo_name}: F1={metrics['f1_score']:.3f}, Features={len(feature_matrix.columns)}")
                
            except Exception as e:
                print(f"  Error with {combo_name}: {e}")
                results[combo_name] = {"error": str(e)}
        
        return results
    
    def compare_llm_providers(
        self,
        firmware_path: str,
        ground_truth: Dict[str, int]
    ) -> Dict[str, Dict[str, float]]:
        """Compare different LLM providers for CWE labeling"""
        results = {}
        
        providers = ["pattern", "ollama", "openai"]
        
        original_provider = self.config.get("llm", {}).get("provider", "pattern")
        
        for provider in providers:
            if provider == "openai" and not self.config.get("llm", {}).get("api_key"):
                print(f"Skipping {provider} (no API key)")
                continue
            
            print(f"Testing LLM provider: {provider}...")
            
            try:
                # Update config
                self.config["llm"]["provider"] = provider
                
                # Reinitialize pipeline with new provider
                pipeline = FirmwareSecurityPipeline(self.config)
                
                # Run static analysis
                fw, feature_matrix, predictions, cwe_labels = pipeline.run_static_stage(
                    firmware_path,
                    source="test"
                )
                
                # Evaluate
                metrics = pipeline.evaluate(ground_truth, predictions)
                
                results[provider] = {
                    "precision": metrics["precision"],
                    "recall": metrics["recall"],
                    "f1_score": metrics["f1_score"],
                    "accuracy": metrics["accuracy"],
                    "num_cwe_labels": sum(len(cwes) for cwes in cwe_labels.values())
                }
                
                print(f"  {provider}: F1={metrics['f1_score']:.3f}, CWE labels={results[provider]['num_cwe_labels']}")
                
            except Exception as e:
                print(f"  Error with {provider}: {e}")
                results[provider] = {"error": str(e)}
        
        # Restore original provider
        self.config["llm"]["provider"] = original_provider
        
        return results


def main():
    parser = argparse.ArgumentParser(description="Baseline comparison and ablation studies")
    parser.add_argument(
        "firmware",
        type=str,
        help="Firmware binary file or directory"
    )
    parser.add_argument(
        "-c", "--config",
        type=str,
        default="configs/config.yaml",
        help="Config file path"
    )
    parser.add_argument(
        "-g", "--ground-truth",
        type=str,
        help="Ground truth JSON file"
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        default="./output/evaluation/baseline_comparison.json",
        help="Output JSON file"
    )
    parser.add_argument(
        "--compare-models",
        action="store_true",
        help="Compare different ML models"
    )
    parser.add_argument(
        "--compare-features",
        action="store_true",
        help="Compare different feature combinations (ablation study)"
    )
    parser.add_argument(
        "--compare-llm",
        action="store_true",
        help="Compare different LLM providers"
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Run all comparisons"
    )
    parser.add_argument(
        "--log-level",
        type=str,
        default="ERROR",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"]
    )
    
    args = parser.parse_args()
    
    # Setup
    config = load_config(args.config)
    setup_logging(args.log_level)
    
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Load ground truth
    ground_truth = {}
    if args.ground_truth:
        with open(args.ground_truth, 'r') as f:
            ground_truth = json.load(f)
    
    # Initialize comparator
    comparator = BaselineComparator(config)
    
    results = {
        "firmware": args.firmware,
        "ground_truth": args.ground_truth,
        "comparisons": {}
    }
    
    firmware_path = Path(args.firmware)
    
    # Run comparisons
    if args.all or args.compare_features:
        print("="*80)
        print("FEATURE COMBINATION COMPARISON (Ablation Study)")
        print("="*80)
        feature_results = comparator.compare_feature_sets(str(firmware_path), ground_truth)
        results["comparisons"]["feature_combinations"] = feature_results
    
    if args.all or args.compare_llm:
        print("\n" + "="*80)
        print("LLM PROVIDER COMPARISON")
        print("="*80)
        llm_results = comparator.compare_llm_providers(str(firmware_path), ground_truth)
        results["comparisons"]["llm_providers"] = llm_results
    
    if args.all or args.compare_models:
        print("\n" + "="*80)
        print("MODEL COMPARISON")
        print("="*80)
        # For model comparison, we need training data
        # This would require a dataset - for now, skip or use single firmware
        print("Model comparison requires training dataset. Skipping...")
        print("  (Use prepare_training_data_from_firmware.py to create dataset first)")
    
    # Save results
    with open(output_path, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\nResults saved to: {output_path}")
    
    # Print summary
    print("\n" + "="*80)
    print("SUMMARY")
    print("="*80)
    
    if "feature_combinations" in results["comparisons"]:
        print("\nFeature Combinations:")
        for name, metrics in results["comparisons"]["feature_combinations"].items():
            if "error" not in metrics:
                print(f"  {name:30s}: F1={metrics['f1_score']:.3f}, Precision={metrics['precision']:.3f}, Recall={metrics['recall']:.3f}")
    
    if "llm_providers" in results["comparisons"]:
        print("\nLLM Providers:")
        for name, metrics in results["comparisons"]["llm_providers"].items():
            if "error" not in metrics:
                print(f"  {name:30s}: F1={metrics['f1_score']:.3f}, CWE labels={metrics['num_cwe_labels']}")


if __name__ == "__main__":
    main()

