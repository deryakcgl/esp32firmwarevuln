#!/usr/bin/env python3
"""Optimize prediction threshold for best F1 score"""

import sys
from pathlib import Path
import json
import numpy as np
import pandas as pd
from typing import Dict, Any, List, Tuple
import argparse

sys.path.insert(0, str(Path(__file__).parent.parent))

from esp32_firmguard.utils import load_config, setup_logging
from esp32_firmguard.models.dataset import DatasetBuilder
from esp32_firmguard.models.predictor import VulnerabilityPredictor
from esp32_firmguard.pipeline import FirmwareSecurityPipeline
from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score


def find_optimal_threshold(
    predictions: List[Dict[str, Any]],
    ground_truth: Dict[str, int],
    threshold_range: Tuple[float, float] = (0.0, 1.0),
    step: float = 0.01
) -> Dict[str, Any]:
    """
    Find optimal threshold that maximizes F1 score.
    
    Args:
        predictions: List of predictions with 'func_id' and 'score'
        ground_truth: Dictionary mapping func_id to label (0 or 1)
        threshold_range: (min, max) threshold range
        step: Step size for threshold search
    
    Returns:
        Dictionary with optimal threshold and metrics
    """
    # Convert predictions to arrays
    func_ids = [p['func_id'] for p in predictions]
    scores = np.array([p['score'] for p in predictions])
    
    # Get ground truth labels
    y_true = np.array([ground_truth.get(fid, 0) for fid in func_ids])
    
    # Search for optimal threshold
    best_threshold = 0.5
    best_f1 = 0.0
    best_metrics = {
        'threshold': 0.5,
        'precision': 0.0,
        'recall': 0.0,
        'f1': 0.0,
        'accuracy': 0.0,
        'tp': 0,
        'fp': 0,
        'tn': 0,
        'fn': 0
    }
    
    thresholds = np.arange(threshold_range[0], threshold_range[1] + step, step)
    results = []
    
    for threshold in thresholds:
        y_pred = (scores >= threshold).astype(int)
        
        # Calculate metrics
        precision = precision_score(y_true, y_pred, zero_division=0)
        recall = recall_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)
        accuracy = accuracy_score(y_true, y_pred)
        
        tp = np.sum((y_true == 1) & (y_pred == 1))
        fp = np.sum((y_true == 0) & (y_pred == 1))
        tn = np.sum((y_true == 0) & (y_pred == 0))
        fn = np.sum((y_true == 1) & (y_pred == 0))
        
        result = {
            'threshold': float(threshold),
            'precision': float(precision),
            'recall': float(recall),
            'f1': float(f1),
            'accuracy': float(accuracy),
            'tp': int(tp),
            'fp': int(fp),
            'tn': int(tn),
            'fn': int(fn)
        }
        results.append(result)
        
        # Update best if F1 is better
        if f1 > best_f1:
            best_f1 = f1
            best_threshold = threshold
            best_metrics = result.copy()
    
    return {
        'optimal': best_metrics,
        'all_results': results
    }


def evaluate_with_threshold(
    pipeline: FirmwareSecurityPipeline,
    firmware_path: Path,
    ground_truth: Dict[str, int],
    threshold: float
) -> Dict[str, Any]:
    """Evaluate pipeline with specific threshold"""
    # Run pipeline
    fw = pipeline.run_ingestion_stage(firmware_path)
    features = pipeline.run_feature_extraction_stage(fw)
    cwe_labels = pipeline.run_labeling_stage(fw, features)
    predictions = pipeline.run_prediction_stage(fw, features, cwe_labels)
    
    # Apply threshold
    for pred in predictions:
        pred.is_vulnerable = pred.score >= threshold
    
    # Calculate metrics
    func_ids = [p.func_id for p in predictions]
    y_true = np.array([ground_truth.get(fid, 0) for fid in func_ids])
    y_pred = np.array([1 if p.is_vulnerable else 0 for p in predictions])
    
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    accuracy = accuracy_score(y_true, y_pred)
    
    tp = np.sum((y_true == 1) & (y_pred == 1))
    fp = np.sum((y_true == 0) & (y_pred == 1))
    tn = np.sum((y_true == 0) & (y_pred == 0))
    fn = np.sum((y_true == 1) & (y_pred == 0))
    
    return {
        'threshold': threshold,
        'precision': float(precision),
        'recall': float(recall),
        'f1': float(f1),
        'accuracy': float(accuracy),
        'tp': int(tp),
        'fp': int(fp),
        'tn': int(tn),
        'fn': int(fn)
    }


def main():
    parser = argparse.ArgumentParser(description="Optimize prediction threshold")
    parser.add_argument("dataset", type=str, help="Path to dataset directory")
    parser.add_argument("-c", "--config", type=str, default="configs/config.yaml",
                       help="Path to config file")
    parser.add_argument("-g", "--ground-truth", type=str,
                       help="Path to ground truth directory")
    parser.add_argument("-o", "--output", type=str, default="output/models/optimal_threshold.json",
                       help="Output JSON file")
    parser.add_argument("--min-threshold", type=float, default=0.0,
                       help="Minimum threshold to test")
    parser.add_argument("--max-threshold", type=float, default=1.0,
                       help="Maximum threshold to test")
    parser.add_argument("--step", type=float, default=0.01,
                       help="Step size for threshold search")
    parser.add_argument("--log-level", type=str, default="ERROR",
                       choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    
    args = parser.parse_args()
    
    config = load_config(args.config)
    setup_logging(args.log_level)
    
    # Load dataset
    dataset_builder = DatasetBuilder(config)
    feature_matrix, labels = dataset_builder.load_dataset(Path(args.dataset))
    
    print("=" * 80)
    print("THRESHOLD OPTIMIZATION")
    print("=" * 80)
    print()
    print(f"Dataset: {len(feature_matrix)} samples")
    print(f"Label distribution: {(labels == 1).sum()} positive, {(labels == 0).sum()} negative")
    print()
    
    # Load model and make predictions
    pipeline = FirmwareSecurityPipeline(config)
    predictor = VulnerabilityPredictor(config)
    predictor.load_model()
    
    # Get predictions on training data
    print("Generating predictions on training data...")
    predictions_list = predictor.predict(feature_matrix)
    
    # Convert to dict format
    predictions = [
        {'func_id': p.func_id, 'score': p.score}
        for p in predictions_list
    ]
    
    # Create ground truth dict
    ground_truth = {
        f'func_{i+1:03d}': int(label)
        for i, label in enumerate(labels)
    }
    
    print(f"Searching for optimal threshold in [{args.min_threshold}, {args.max_threshold}]...")
    print()
    
    # Find optimal threshold
    results = find_optimal_threshold(
        predictions,
        ground_truth,
        threshold_range=(args.min_threshold, args.max_threshold),
        step=args.step
    )
    
    optimal = results['optimal']
    
    print("=" * 80)
    print("OPTIMAL THRESHOLD")
    print("=" * 80)
    print(f"Threshold: {optimal['threshold']:.4f}")
    print(f"Precision: {optimal['precision']:.4f}")
    print(f"Recall: {optimal['recall']:.4f}")
    print(f"F1 Score: {optimal['f1']:.4f}")
    print(f"Accuracy: {optimal['accuracy']:.4f}")
    print()
    print(f"Confusion Matrix:")
    print(f"  TP: {optimal['tp']}, FP: {optimal['fp']}")
    print(f"  TN: {optimal['tn']}, FN: {optimal['fn']}")
    print("=" * 80)
    
    # Save results
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\nResults saved to: {output_path}")
    
    # Show top 10 thresholds by F1
    print("\nTop 10 thresholds by F1 score:")
    sorted_results = sorted(results['all_results'], key=lambda x: x['f1'], reverse=True)[:10]
    for i, r in enumerate(sorted_results, 1):
        print(f"{i:2d}. Threshold={r['threshold']:.4f}: "
              f"Precision={r['precision']:.4f}, Recall={r['recall']:.4f}, F1={r['f1']:.4f}")


if __name__ == "__main__":
    main()

