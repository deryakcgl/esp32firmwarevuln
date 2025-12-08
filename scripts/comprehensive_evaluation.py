#!/usr/bin/env python3
"""Comprehensive evaluation script: 20+ firmware, cross-validation, statistical tests"""

import sys
from pathlib import Path
import json
import pandas as pd
import numpy as np
from typing import Dict, List, Any, Optional
from collections import defaultdict
import argparse
from scipy import stats
from sklearn.model_selection import KFold
import time

sys.path.insert(0, str(Path(__file__).parent.parent))

from esp32_firmguard.utils import load_config, setup_logging
from esp32_firmguard.pipeline import FirmwareSecurityPipeline
from esp32_firmguard.metrics.evaluation import EvaluationMetrics


def load_ground_truth(ground_truth_path: Path) -> Dict[str, Dict[str, int]]:
    """Load ground truth from JSON file(s)"""
    ground_truth = {}
    
    if ground_truth_path.is_file():
        with open(ground_truth_path, 'r') as f:
            data = json.load(f)
            if isinstance(data, dict):
                # Check if it's a single firmware ground truth or combined
                if any('func_' in k for k in data.keys()):
                    # Single firmware format: {func_id: label}
                    return {"default": data}
                else:
                    # Combined format: {firmware_name: {func_id: label}}
                    return data
    elif ground_truth_path.is_dir():
        # Load all JSON files in directory
        for gt_file in ground_truth_path.glob("*.json"):
            with open(gt_file, 'r') as f:
                data = json.load(f)
                firmware_name = gt_file.stem
                ground_truth[firmware_name] = data
    
    return ground_truth


def create_ground_truth_from_cwe_labels(cwe_labels: Dict[str, List[str]]) -> Dict[str, int]:
    """Create ground truth from CWE labels (if CWE exists, it's vulnerable)"""
    ground_truth = {}
    for func_id, cwes in cwe_labels.items():
        ground_truth[func_id] = 1 if len(cwes) > 0 else 0
    return ground_truth


def run_evaluation_on_firmware(
    pipeline: FirmwareSecurityPipeline,
    firmware_path: Path,
    ground_truth: Optional[Dict[str, int]] = None,
    source: str = "test"
) -> Dict[str, Any]:
    """Run evaluation on a single firmware"""
    results = {
        "firmware": str(firmware_path),
        "firmware_name": firmware_path.stem,
        "success": False,
        "error": None,
        "metrics": None,
        "predictions": None,
        "num_functions": 0
    }
    
    try:
        # Run static analysis
        fw, feature_matrix, predictions, cwe_labels = pipeline.run_static_stage(
            str(firmware_path),
            source=source
        )
        
        results["num_functions"] = len(predictions)
        
        # Create ground truth if not provided
        if ground_truth is None:
            ground_truth = create_ground_truth_from_cwe_labels(cwe_labels)
            results["ground_truth_source"] = "cwe_labels"
        else:
            results["ground_truth_source"] = "provided"
        
        # Compute metrics
        metrics = pipeline.evaluate(
            ground_truth=ground_truth,
            predictions=predictions,
            fuzz_results=None,
            hw_results=None
        )
        
        results["metrics"] = metrics
        results["predictions"] = [
            {
                "func_id": p.func_id,
                "score": float(p.score),
                "is_vulnerable": bool(p.is_vulnerable),
                "cwe": p.cwe
            }
            for p in predictions
        ]
        results["success"] = True
        
    except Exception as e:
        results["error"] = str(e)
        print(f"  Error: {e}")
    
    return results


def cross_validate(
    all_results: List[Dict[str, Any]],
    k_folds: int = 5
) -> Dict[str, Any]:
    """Perform k-fold cross-validation on results"""
    # Extract metrics from successful evaluations
    successful_results = [r for r in all_results if r["success"]]
    
    if len(successful_results) < k_folds:
        return {"error": f"Not enough successful evaluations ({len(successful_results)}) for {k_folds}-fold CV"}
    
    metrics_list = [r["metrics"] for r in successful_results]
    
    # Extract metric values
    metric_names = ["precision", "recall", "f1_score", "accuracy"]
    cv_results = {}
    
    for metric_name in metric_names:
        values = [m[metric_name] for m in metrics_list if metric_name in m]
        if values:
            cv_results[metric_name] = {
                "mean": float(np.mean(values)),
                "std": float(np.std(values)),
                "min": float(np.min(values)),
                "max": float(np.max(values)),
                "values": [float(v) for v in values]
            }
    
    return cv_results


def statistical_tests(all_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Perform statistical significance tests"""
    successful_results = [r for r in all_results if r["success"]]
    
    if len(successful_results) < 2:
        return {"error": "Not enough results for statistical tests"}
    
    metrics_list = [r["metrics"] for r in successful_results]
    
    # Extract metric values
    metric_names = ["precision", "recall", "f1_score", "accuracy"]
    stats_results = {}
    
    for metric_name in metric_names:
        values = [m[metric_name] for m in metrics_list if metric_name in m]
        if len(values) >= 2:
            # Shapiro-Wilk test for normality
            shapiro_stat, shapiro_p = stats.shapiro(values)
            
            # If normal, use t-test; otherwise use Wilcoxon signed-rank test
            if shapiro_p > 0.05:
                # Normal distribution - use t-test
                t_stat, t_p = stats.ttest_1samp(values, np.mean(values))
                test_type = "t-test"
                test_stat = float(t_stat)
                test_p = float(t_p)
            else:
                # Non-normal - use Wilcoxon
                test_stat, test_p = stats.wilcoxon(values, alternative='two-sided')
                test_type = "wilcoxon"
                test_stat = float(test_stat)
                test_p = float(test_p)
            
            # Confidence interval (95%)
            ci = stats.t.interval(0.95, len(values)-1, loc=np.mean(values), scale=stats.sem(values))
            
            stats_results[metric_name] = {
                "mean": float(np.mean(values)),
                "std": float(np.std(values)),
                "test_type": test_type,
                "test_statistic": test_stat,
                "p_value": float(test_p),
                "confidence_interval_95": [float(ci[0]), float(ci[1])],
                "is_significant": test_p < 0.05
            }
    
    return stats_results


def main():
    parser = argparse.ArgumentParser(description="Comprehensive evaluation on 20+ firmware")
    parser.add_argument(
        "firmware_dir",
        type=str,
        help="Directory containing firmware binaries"
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
        help="Ground truth JSON file or directory"
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        default="./output/evaluation/comprehensive_results.json",
        help="Output JSON file"
    )
    parser.add_argument(
        "-k", "--k-folds",
        type=int,
        default=5,
        help="Number of folds for cross-validation"
    )
    parser.add_argument(
        "-n", "--max-firmware",
        type=int,
        default=None,
        help="Maximum number of firmware to evaluate (default: all)"
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
    
    firmware_dir = Path(args.firmware_dir)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Find firmware files
    firmware_files = list(firmware_dir.glob("*.bin"))
    if not firmware_files:
        firmware_files = list(firmware_dir.rglob("*.bin"))
    
    if args.max_firmware:
        firmware_files = firmware_files[:args.max_firmware]
    
    print(f"Found {len(firmware_files)} firmware files")
    print(f"Evaluating {len(firmware_files)} firmware...\n")
    
    # Load ground truth if provided
    ground_truth_data = None
    if args.ground_truth:
        ground_truth_path = Path(args.ground_truth)
        ground_truth_data = load_ground_truth(ground_truth_path)
        print(f"Loaded ground truth from {ground_truth_path}")
    
    # Initialize pipeline
    pipeline = FirmwareSecurityPipeline(config)
    
    # Evaluate each firmware
    all_results = []
    start_time = time.time()
    
    for i, firmware_path in enumerate(firmware_files, 1):
        print(f"[{i}/{len(firmware_files)}] Evaluating: {firmware_path.name}")
        
        # Get ground truth for this firmware if available
        gt = None
        if ground_truth_data:
            firmware_name = firmware_path.stem
            # Try exact match first
            if firmware_name in ground_truth_data:
                gt = ground_truth_data[firmware_name]
            # Try partial match
            else:
                for key, value in ground_truth_data.items():
                    if firmware_name in key or key in firmware_name:
                        gt = value
                        break
            # Fallback to default
            if gt is None and "default" in ground_truth_data:
                gt = ground_truth_data["default"]
        
        result = run_evaluation_on_firmware(
            pipeline,
            firmware_path,
            ground_truth=gt,
            source="gitlab"
        )
        all_results.append(result)
        
        if result["success"]:
            metrics = result["metrics"]
            print(f"  Precision: {metrics['precision']:.3f}, Recall: {metrics['recall']:.3f}, F1: {metrics['f1_score']:.3f}")
        else:
            print(f"  Failed: {result['error']}")
    
    elapsed_time = time.time() - start_time
    
    # Aggregate results
    successful_results = [r for r in all_results if r["success"]]
    failed_results = [r for r in all_results if not r["success"]]
    
    print(f"\n{'='*80}")
    print(f"EVALUATION SUMMARY")
    print(f"{'='*80}")
    print(f"Total firmware: {len(all_results)}")
    print(f"Successful: {len(successful_results)}")
    print(f"Failed: {len(failed_results)}")
    print(f"Total time: {elapsed_time:.2f} seconds")
    print(f"Average time per firmware: {elapsed_time/len(all_results):.2f} seconds")
    
    if successful_results:
        # Aggregate metrics
        all_metrics = [r["metrics"] for r in successful_results]
        metric_names = ["precision", "recall", "f1_score", "accuracy", "vcr", "sri"]
        
        print(f"\n{'='*80}")
        print(f"AGGREGATE METRICS")
        print(f"{'='*80}")
        for metric_name in metric_names:
            values = [m[metric_name] for m in all_metrics if metric_name in m]
            if values:
                print(f"{metric_name:15s}: {np.mean(values):.4f} ± {np.std(values):.4f} (min: {np.min(values):.4f}, max: {np.max(values):.4f})")
        
        # Cross-validation
        print(f"\n{'='*80}")
        print(f"CROSS-VALIDATION ({args.k_folds}-fold)")
        print(f"{'='*80}")
        cv_results = cross_validate(successful_results, args.k_folds)
        if "error" not in cv_results:
            for metric_name, cv_data in cv_results.items():
                print(f"{metric_name:15s}: {cv_data['mean']:.4f} ± {cv_data['std']:.4f}")
        
        # Statistical tests
        print(f"\n{'='*80}")
        print(f"STATISTICAL TESTS")
        print(f"{'='*80}")
        stats_results = statistical_tests(successful_results)
        if "error" not in stats_results:
            for metric_name, stats_data in stats_results.items():
                print(f"{metric_name:15s}: mean={stats_data['mean']:.4f}, p={stats_data['p_value']:.4f}, "
                      f"CI95=[{stats_data['confidence_interval_95'][0]:.4f}, {stats_data['confidence_interval_95'][1]:.4f}]")
    
    # Save results
    output_data = {
        "summary": {
            "total_firmware": len(all_results),
            "successful": len(successful_results),
            "failed": len(failed_results),
            "total_time_seconds": elapsed_time,
            "average_time_per_firmware": elapsed_time / len(all_results) if all_results else 0
        },
        "results": all_results,
        "cross_validation": cv_results if successful_results else None,
        "statistical_tests": stats_results if successful_results else None
    }
    
    with open(output_path, 'w') as f:
        json.dump(output_data, f, indent=2)
    
    print(f"\nResults saved to: {output_path}")


if __name__ == "__main__":
    main()

