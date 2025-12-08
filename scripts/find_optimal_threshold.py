#!/usr/bin/env python3
"""Find optimal threshold for vulnerability prediction"""

import sys
from pathlib import Path
import json
import numpy as np
import pandas as pd
from typing import Dict, List, Tuple
import argparse

sys.path.insert(0, str(Path(__file__).parent.parent))

from esp32_firmguard.metrics.evaluation import EvaluationMetrics


def calculate_metrics_at_threshold(
    predictions: List[Dict],
    ground_truth: Dict[str, int],
    threshold: float
) -> Dict[str, float]:
    """Calculate metrics at a specific threshold"""
    y_true = []
    y_pred = []
    
    for pred in predictions:
        func_id = pred["func_id"]
        score = pred["score"]
        
        if func_id in ground_truth:
            y_true.append(ground_truth[func_id])
            y_pred.append(1 if score >= threshold else 0)
    
    if len(y_true) == 0:
        return {
            "precision": 0.0,
            "recall": 0.0,
            "f1_score": 0.0,
            "accuracy": 0.0,
            "true_positives": 0,
            "false_positives": 0,
            "true_negatives": 0,
            "false_negatives": 0
        }
    
    y_true = np.array(y_true)
    y_pred = np.array(y_pred)
    
    tp = np.sum((y_true == 1) & (y_pred == 1))
    fp = np.sum((y_true == 0) & (y_pred == 1))
    tn = np.sum((y_true == 0) & (y_pred == 0))
    fn = np.sum((y_true == 1) & (y_pred == 0))
    
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / (tp + fp + tn + fn) if (tp + fp + tn + fn) > 0 else 0.0
    
    return {
        "precision": float(precision),
        "recall": float(recall),
        "f1_score": float(f1),
        "accuracy": float(accuracy),
        "true_positives": int(tp),
        "false_positives": int(fp),
        "true_negatives": int(tn),
        "false_negatives": int(fn)
    }


def find_optimal_threshold(
    results_file: Path,
    ground_truth_dir: Path,
    metric: str = "f1_score"
) -> Dict:
    """Find optimal threshold across all firmware"""
    
    # Load evaluation results
    with open(results_file, 'r') as f:
        data = json.load(f)
    
    # Aggregate all predictions and ground truth
    all_predictions = []
    all_ground_truth = {}
    
    for result in data["results"]:
        if not result["success"]:
            continue
        
        firmware_name = result["firmware_name"]
        predictions = result["predictions"]
        
        # Load ground truth
        gt_file = ground_truth_dir / f"{firmware_name}_ground_truth.json"
        if not gt_file.exists():
            # Try alternative names
            for alt_file in ground_truth_dir.glob(f"*{firmware_name}*"):
                gt_file = alt_file
                break
        
        if gt_file.exists():
            with open(gt_file, 'r') as f:
                gt = json.load(f)
                all_ground_truth.update(gt)
        
        all_predictions.extend(predictions)
    
    print(f"Total predictions: {len(all_predictions)}")
    print(f"Total ground truth labels: {len(all_ground_truth)}")
    print()
    
    # Test different thresholds
    thresholds = np.arange(0.1, 1.0, 0.05)
    results = []
    
    print("Testing thresholds...")
    print(f"{'Threshold':<12} {'Precision':<12} {'Recall':<12} {'F1':<12} {'Accuracy':<12}")
    print("-" * 60)
    
    for threshold in thresholds:
        metrics = calculate_metrics_at_threshold(all_predictions, all_ground_truth, threshold)
        results.append({
            "threshold": float(threshold),
            **metrics
        })
        
        print(f"{threshold:<12.2f} {metrics['precision']:<12.4f} {metrics['recall']:<12.4f} "
              f"{metrics['f1_score']:<12.4f} {metrics['accuracy']:<12.4f}")
    
    # Find optimal threshold
    df = pd.DataFrame(results)
    optimal_idx = df[metric].idxmax()
    optimal = df.iloc[optimal_idx]
    
    print()
    print("=" * 60)
    print("OPTIMAL THRESHOLD")
    print("=" * 60)
    print(f"Metric: {metric}")
    print(f"Optimal threshold: {optimal['threshold']:.3f}")
    print(f"Precision: {optimal['precision']:.4f}")
    print(f"Recall: {optimal['recall']:.4f}")
    print(f"F1-Score: {optimal['f1_score']:.4f}")
    print(f"Accuracy: {optimal['accuracy']:.4f}")
    print()
    print(f"Confusion Matrix:")
    print(f"  TP: {optimal['true_positives']}")
    print(f"  FP: {optimal['false_positives']}")
    print(f"  TN: {optimal['true_negatives']}")
    print(f"  FN: {optimal['false_negatives']}")
    
    # Also find threshold that maximizes accuracy
    optimal_acc_idx = df["accuracy"].idxmax()
    optimal_acc = df.iloc[optimal_acc_idx]
    
    print()
    print("=" * 60)
    print("THRESHOLD FOR MAXIMUM ACCURACY")
    print("=" * 60)
    print(f"Optimal threshold: {optimal_acc['threshold']:.3f}")
    print(f"Precision: {optimal_acc['precision']:.4f}")
    print(f"Recall: {optimal_acc['recall']:.4f}")
    print(f"F1-Score: {optimal_acc['f1_score']:.4f}")
    print(f"Accuracy: {optimal_acc['accuracy']:.4f}")
    
    return {
        "optimal_f1": {
            "threshold": float(optimal['threshold']),
            "metrics": optimal.to_dict()
        },
        "optimal_accuracy": {
            "threshold": float(optimal_acc['threshold']),
            "metrics": optimal_acc.to_dict()
        },
        "all_results": results
    }


def main():
    parser = argparse.ArgumentParser(description="Find optimal threshold")
    parser.add_argument("results_file", type=str,
                       help="Path to evaluation results JSON")
    parser.add_argument("-g", "--ground-truth-dir", type=str,
                       default="./firmware_samples/ground_truth",
                       help="Directory containing ground truth files")
    parser.add_argument("-m", "--metric", type=str, default="f1_score",
                       choices=["f1_score", "accuracy", "precision", "recall"],
                       help="Metric to optimize")
    parser.add_argument("-o", "--output", type=str,
                       help="Output JSON file for results")
    
    args = parser.parse_args()
    
    results = find_optimal_threshold(
        Path(args.results_file),
        Path(args.ground_truth_dir),
        args.metric
    )
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\nResults saved to: {args.output}")


if __name__ == "__main__":
    main()

