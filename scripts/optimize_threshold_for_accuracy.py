#!/usr/bin/env python3
"""Optimize threshold for best accuracy while maintaining good F1"""

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
from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score


def find_optimal_threshold_balanced(
    predictions: List[Dict[str, Any]],
    ground_truth: Dict[str, int],
    threshold_range: Tuple[float, float] = (0.0, 1.0),
    step: float = 0.01,
    weight_accuracy: float = 0.5,
    weight_f1: float = 0.5
) -> Dict[str, Any]:
    """
    Find optimal threshold that balances accuracy and F1 score.
    
    Args:
        predictions: List of predictions with 'func_id' and 'score'
        ground_truth: Dictionary mapping func_id to label (0 or 1)
        threshold_range: (min, max) threshold range
        step: Step size for threshold search
        weight_accuracy: Weight for accuracy in combined score
        weight_f1: Weight for F1 in combined score
    
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
    best_score = 0.0
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
        
        # Combined score: weighted average of accuracy and F1
        combined_score = weight_accuracy * accuracy + weight_f1 * f1
        
        result = {
            'threshold': float(threshold),
            'precision': float(precision),
            'recall': float(recall),
            'f1': float(f1),
            'accuracy': float(accuracy),
            'combined_score': float(combined_score),
            'tp': int(tp),
            'fp': int(fp),
            'tn': int(tn),
            'fn': int(fn)
        }
        results.append(result)
        
        # Update best if combined score is better
        if combined_score > best_score:
            best_score = combined_score
            best_threshold = threshold
            best_metrics = result.copy()
    
    return {
        'optimal': best_metrics,
        'all_results': results
    }


def main():
    parser = argparse.ArgumentParser(description="Optimize threshold for accuracy")
    parser.add_argument("dataset", type=str, help="Path to dataset directory")
    parser.add_argument("-c", "--config", type=str, default="configs/config.yaml",
                       help="Path to config file")
    parser.add_argument("-o", "--output", type=str, default="output/models/optimal_threshold_accuracy.json",
                       help="Output JSON file")
    parser.add_argument("--min-threshold", type=float, default=0.0,
                       help="Minimum threshold to test")
    parser.add_argument("--max-threshold", type=float, default=1.0,
                       help="Maximum threshold to test")
    parser.add_argument("--step", type=float, default=0.01,
                       help="Step size for threshold search")
    parser.add_argument("--weight-accuracy", type=float, default=0.6,
                       help="Weight for accuracy in combined score")
    parser.add_argument("--weight-f1", type=float, default=0.4,
                       help="Weight for F1 in combined score")
    parser.add_argument("--log-level", type=str, default="ERROR",
                       choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    
    args = parser.parse_args()
    
    config = load_config(args.config)
    setup_logging(args.log_level)
    
    # Load dataset
    dataset_builder = DatasetBuilder(config)
    feature_matrix, labels = dataset_builder.load_dataset(Path(args.dataset))
    
    print("=" * 80)
    print("THRESHOLD OPTIMIZATION FOR ACCURACY")
    print("=" * 80)
    print()
    print(f"Dataset: {len(feature_matrix)} samples")
    print(f"Label distribution: {(labels == 1).sum()} positive, {(labels == 0).sum()} negative")
    print(f"Weights: Accuracy={args.weight_accuracy}, F1={args.weight_f1}")
    print()
    
    # Load model and make predictions
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
    results = find_optimal_threshold_balanced(
        predictions,
        ground_truth,
        threshold_range=(args.min_threshold, args.max_threshold),
        step=args.step,
        weight_accuracy=args.weight_accuracy,
        weight_f1=args.weight_f1
    )
    
    optimal = results['optimal']
    
    print("=" * 80)
    print("OPTIMAL THRESHOLD (BALANCED)")
    print("=" * 80)
    print(f"Threshold: {optimal['threshold']:.4f}")
    print(f"Precision: {optimal['precision']:.4f}")
    print(f"Recall: {optimal['recall']:.4f}")
    print(f"F1 Score: {optimal['f1']:.4f}")
    print(f"Accuracy: {optimal['accuracy']:.4f}")
    print(f"Combined Score: {optimal['combined_score']:.4f}")
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
    
    # Show top 10 thresholds by combined score
    print("\nTop 10 thresholds by combined score (Accuracy + F1):")
    sorted_results = sorted(results['all_results'], key=lambda x: x['combined_score'], reverse=True)[:10]
    for i, r in enumerate(sorted_results, 1):
        print(f"{i:2d}. Threshold={r['threshold']:.4f}: "
              f"Accuracy={r['accuracy']:.4f}, F1={r['f1']:.4f}, "
              f"Precision={r['precision']:.4f}, Recall={r['recall']:.4f}, "
              f"Combined={r['combined_score']:.4f}")


if __name__ == "__main__":
    main()

