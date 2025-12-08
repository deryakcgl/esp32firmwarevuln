#!/usr/bin/env python3
"""Detailed ablation study: Feature importance and component contribution"""

import sys
from pathlib import Path
import json
import pandas as pd
import numpy as np
from typing import Dict, List, Any, Optional
import argparse
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend
import matplotlib.pyplot as plt
import seaborn as sns

sys.path.insert(0, str(Path(__file__).parent.parent))

from esp32_firmguard.utils import load_config, setup_logging
from esp32_firmguard.pipeline import FirmwareSecurityPipeline
from esp32_firmguard.metrics.evaluation import EvaluationMetrics
from esp32_firmguard.models.dataset import DatasetBuilder


class AblationStudy:
    """Perform detailed ablation studies"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.metrics = EvaluationMetrics(config)
    
    def feature_importance_analysis(
        self,
        feature_matrix: pd.DataFrame,
        labels: pd.Series
    ) -> Dict[str, float]:
        """Analyze feature importance using correlation and model-based methods"""
        importance = {}
        
        # 1. Correlation with labels
        correlations = {}
        for col in feature_matrix.columns:
            try:
                corr = np.corrcoef(feature_matrix[col].fillna(0), labels)[0, 1]
                correlations[col] = abs(corr) if not np.isnan(corr) else 0
            except:
                correlations[col] = 0
        
        # 2. Model-based importance (if XGBoost available)
        try:
            import xgboost as xgb
            model = xgb.XGBClassifier(n_estimators=50, max_depth=3, random_state=42)
            model.fit(feature_matrix.fillna(0), labels)
            
            if hasattr(model, 'feature_importances_'):
                feature_importances = model.feature_importances_
                for i, col in enumerate(feature_matrix.columns):
                    importance[col] = {
                        "correlation": correlations.get(col, 0),
                        "xgboost_importance": float(feature_importances[i]) if i < len(feature_importances) else 0
                    }
        except:
            # Fallback to correlation only
            for col in feature_matrix.columns:
                importance[col] = {
                    "correlation": correlations.get(col, 0),
                    "xgboost_importance": 0
                }
        
        # Sort by combined importance
        for col in importance:
            importance[col]["combined"] = (
                importance[col]["correlation"] * 0.5 +
                importance[col]["xgboost_importance"] * 0.5
            )
        
        return importance
    
    def component_contribution_analysis(
        self,
        firmware_path: str,
        ground_truth: Dict[str, int]
    ) -> Dict[str, Dict[str, float]]:
        """Analyze contribution of each pipeline component"""
        results = {}
        
        pipeline = FirmwareSecurityPipeline(self.config)
        
        # Extract all components
        fw = pipeline.extractor.extract(firmware_path, "test")
        structural = pipeline.struct_feat.extract(fw)
        peripheral = pipeline.periph_feat.extract(fw)
        embeddings = pipeline.embed_feat.extract(fw)
        cwe_labels = pipeline.cwe_labeler.label(fw)
        
        dataset_builder = DatasetBuilder(self.config)
        
        # Test each component incrementally
        configurations = [
            {
                "name": "baseline_structural",
                "structural": structural,
                "peripheral": pd.DataFrame(),
                "embeddings": pd.DataFrame(),
                "cwe_labels": {}
            },
            {
                "name": "+peripheral",
                "structural": structural,
                "peripheral": peripheral,
                "embeddings": pd.DataFrame(),
                "cwe_labels": {}
            },
            {
                "name": "+embeddings",
                "structural": structural,
                "peripheral": peripheral,
                "embeddings": embeddings,
                "cwe_labels": {}
            },
            {
                "name": "+cwe_labels",
                "structural": structural,
                "peripheral": peripheral,
                "embeddings": embeddings,
                "cwe_labels": cwe_labels
            }
        ]
        
        baseline_metrics = None
        
        for config in configurations:
            print(f"Testing: {config['name']}...")
            
            try:
                feature_matrix = dataset_builder.build_feature_matrix(
                    config["structural"],
                    config["peripheral"],
                    config["embeddings"],
                    config["cwe_labels"]
                )
                
                pipeline.predictor.load_model()
                predictions = pipeline.predictor.predict(feature_matrix, config["cwe_labels"])
                
                metrics = pipeline.evaluate(ground_truth, predictions)
                
                # Calculate improvement over baseline
                improvement = {}
                if baseline_metrics:
                    for key in ["precision", "recall", "f1_score", "accuracy"]:
                        improvement[key] = metrics[key] - baseline_metrics[key]
                else:
                    baseline_metrics = metrics.copy()
                    for key in ["precision", "recall", "f1_score", "accuracy"]:
                        improvement[key] = 0.0
                
                results[config["name"]] = {
                    "metrics": metrics,
                    "improvement": improvement,
                    "num_features": len(feature_matrix.columns)
                }
                
                print(f"  F1: {metrics['f1_score']:.3f} (improvement: {improvement['f1_score']:+.3f})")
                
            except Exception as e:
                print(f"  Error: {e}")
                results[config["name"]] = {"error": str(e)}
        
        return results
    
    def embedding_dimension_analysis(
        self,
        firmware_path: str,
        ground_truth: Dict[str, int]
    ) -> Dict[str, Dict[str, float]]:
        """Analyze impact of embedding dimensions"""
        results = {}
        
        # Note: This would require modifying the embedding extractor
        # For now, we'll test with current embedding dimensions
        print("Embedding dimension analysis requires code modification.")
        print("Current embedding dimensions: 16")
        
        return results
    
    def threshold_sensitivity_analysis(
        self,
        feature_matrix: pd.DataFrame,
        ground_truth: Dict[str, int],
        predictions: List
    ) -> Dict[str, Dict[str, float]]:
        """Analyze sensitivity to prediction threshold"""
        results = {}
        
        thresholds = [0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]
        
        y_true = [ground_truth.get(p.func_id, 0) for p in predictions]
        
        for threshold in thresholds:
            y_pred = [1 if p.score >= threshold else 0 for p in predictions]
            
            from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score
            
            results[f"threshold_{threshold}"] = {
                "precision": float(precision_score(y_true, y_pred, zero_division=0)),
                "recall": float(recall_score(y_true, y_pred, zero_division=0)),
                "f1_score": float(f1_score(y_true, y_pred, zero_division=0)),
                "accuracy": float(accuracy_score(y_true, y_pred))
            }
        
        return results


def create_visualizations(results: Dict[str, Any], output_dir: Path):
    """Create visualization plots for ablation study results"""
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # 1. Component contribution plot
    if "component_contribution" in results:
        fig, ax = plt.subplots(figsize=(10, 6))
        
        components = []
        f1_scores = []
        
        for name, data in results["component_contribution"].items():
            if "error" not in data and "metrics" in data:
                components.append(name)
                f1_scores.append(data["metrics"]["f1_score"])
        
        if components:
            ax.bar(components, f1_scores)
            ax.set_ylabel("F1-Score")
            ax.set_xlabel("Configuration")
            ax.set_title("Component Contribution Analysis")
            ax.set_ylim([0, 1])
            plt.xticks(rotation=45, ha='right')
            plt.tight_layout()
            plt.savefig(output_dir / "component_contribution.png", dpi=300)
            plt.close()
    
    # 2. Feature importance plot
    if "feature_importance" in results:
        importance_data = results["feature_importance"]
        
        # Get top 20 features
        sorted_features = sorted(
            importance_data.items(),
            key=lambda x: x[1].get("combined", 0),
            reverse=True
        )[:20]
        
        if sorted_features:
            fig, ax = plt.subplots(figsize=(12, 8))
            
            features = [f[0] for f in sorted_features]
            importances = [f[1].get("combined", 0) for f in sorted_features]
            
            ax.barh(features, importances)
            ax.set_xlabel("Importance Score")
            ax.set_title("Top 20 Feature Importance")
            plt.tight_layout()
            plt.savefig(output_dir / "feature_importance.png", dpi=300)
            plt.close()
    
    # 3. Threshold sensitivity plot
    if "threshold_sensitivity" in results:
        fig, ax = plt.subplots(figsize=(10, 6))
        
        thresholds = []
        precisions = []
        recalls = []
        f1_scores = []
        
        for name, data in sorted(results["threshold_sensitivity"].items()):
            threshold = float(name.split("_")[1])
            thresholds.append(threshold)
            precisions.append(data["precision"])
            recalls.append(data["recall"])
            f1_scores.append(data["f1_score"])
        
        ax.plot(thresholds, precisions, marker='o', label='Precision')
        ax.plot(thresholds, recalls, marker='s', label='Recall')
        ax.plot(thresholds, f1_scores, marker='^', label='F1-Score')
        ax.set_xlabel("Threshold")
        ax.set_ylabel("Score")
        ax.set_title("Threshold Sensitivity Analysis")
        ax.legend()
        ax.grid(True, alpha=0.3)
        plt.tight_layout()
        plt.savefig(output_dir / "threshold_sensitivity.png", dpi=300)
        plt.close()


def main():
    parser = argparse.ArgumentParser(description="Detailed ablation study")
    parser.add_argument(
        "firmware",
        type=str,
        help="Firmware binary file"
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
        required=True,
        help="Ground truth JSON file"
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        default="./output/evaluation/ablation_study",
        help="Output directory"
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
    
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Load ground truth
    with open(args.ground_truth, 'r') as f:
        ground_truth = json.load(f)
    
    # Initialize study
    study = AblationStudy(config)
    pipeline = FirmwareSecurityPipeline(config)
    
    results = {
        "firmware": args.firmware,
        "ground_truth": args.ground_truth
    }
    
    # Run static analysis
    print("Running static analysis...")
    fw, feature_matrix, predictions, cwe_labels = pipeline.run_static_stage(
        args.firmware,
        source="test"
    )
    
    # 1. Component contribution
    print("\n" + "="*80)
    print("COMPONENT CONTRIBUTION ANALYSIS")
    print("="*80)
    component_results = study.component_contribution_analysis(args.firmware, ground_truth)
    results["component_contribution"] = component_results
    
    # 2. Feature importance
    print("\n" + "="*80)
    print("FEATURE IMPORTANCE ANALYSIS")
    print("="*80)
    labels = pd.Series([ground_truth.get(p.func_id, 0) for p in predictions])
    importance_results = study.feature_importance_analysis(feature_matrix, labels)
    results["feature_importance"] = importance_results
    
    # Print top 10 features
    sorted_features = sorted(
        importance_results.items(),
        key=lambda x: x[1].get("combined", 0),
        reverse=True
    )[:10]
    print("\nTop 10 Features:")
    for i, (feature, data) in enumerate(sorted_features, 1):
        print(f"  {i:2d}. {feature:30s}: {data.get('combined', 0):.4f}")
    
    # 3. Threshold sensitivity
    print("\n" + "="*80)
    print("THRESHOLD SENSITIVITY ANALYSIS")
    print("="*80)
    threshold_results = study.threshold_sensitivity_analysis(feature_matrix, ground_truth, predictions)
    results["threshold_sensitivity"] = threshold_results
    
    # Save results
    output_json = output_dir / "ablation_study_results.json"
    with open(output_json, 'w') as f:
        json.dump(results, f, indent=2)
    
    # Create visualizations
    print("\nCreating visualizations...")
    create_visualizations(results, output_dir)
    
    print(f"\nResults saved to: {output_dir}")


if __name__ == "__main__":
    main()

