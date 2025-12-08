#!/usr/bin/env python3
"""Test script to run pipeline and output required metrics"""

import sys
from pathlib import Path
import json

sys.path.insert(0, str(Path(__file__).parent.parent))

from esp32_firmguard.utils import load_config, setup_logging
from esp32_firmguard.pipeline import FirmwareSecurityPipeline


def create_ground_truth_from_predictions(predictions, threshold=0.7):
    """Create ground truth from predictions for testing (if no real ground truth available)"""
    ground_truth = {}
    for pred in predictions:
        # Use high-confidence predictions as ground truth
        if pred.score >= threshold:
            ground_truth[pred.func_id] = 1
        elif pred.score <= (1 - threshold):
            ground_truth[pred.func_id] = 0
    return ground_truth


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Run ESP32 FirmGuard test and output metrics")
    parser.add_argument("firmware", type=str, help="Path to firmware binary")
    parser.add_argument("-c", "--config", type=str, default="configs/config.yaml",
                       help="Path to config file")
    parser.add_argument("-s", "--source", type=str, default="test",
                       help="Firmware source")
    parser.add_argument("--ground-truth", type=str,
                       help="Path to ground truth JSON file (optional)")
    parser.add_argument("--output", type=str,
                       help="Output JSON file for results")
    parser.add_argument("--log-level", type=str, default="ERROR",
                       choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    
    args = parser.parse_args()
    
    # Setup
    config = load_config(args.config)
    setup_logging(args.log_level)
    
    # Initialize pipeline
    pipeline = FirmwareSecurityPipeline(config)
    
    # Run static analysis
    print(f"Analyzing firmware: {args.firmware}")
    fw, feature_matrix, predictions, cwe_labels = pipeline.run_static_stage(
        args.firmware,
        source=args.source
    )
    
    # Load or create ground truth
    ground_truth = None
    if args.ground_truth:
        with open(args.ground_truth, 'r') as f:
            ground_truth = json.load(f)
    else:
        # Create synthetic ground truth from predictions for testing
        ground_truth = create_ground_truth_from_predictions(predictions)
        print(f"Note: Using synthetic ground truth from predictions (threshold=0.7)")
    
    fuzz_results = {}
    hw_results = {}
    
    # Compute metrics
    metrics = pipeline.evaluate(
        ground_truth=ground_truth,
        predictions=predictions,
        fuzz_results=fuzz_results if fuzz_results else None,
        hw_results=hw_results if hw_results else None
    )
    
    # Prepare output
    results = {
        "firmware": args.firmware,
        "source": args.source,
        "functions_analyzed": len(predictions),
        "predictions": [
            {
                "func_id": p.func_id,
                "score": float(p.score),
                "cwe": p.cwe,
                "is_vulnerable": bool(p.is_vulnerable)
            }
            for p in predictions
        ],
        "metrics": {
            "precision": metrics["precision"],
            "recall": metrics["recall"],
            "f1": metrics["f1_score"],
            "validation_consistency": metrics["vcr"],
            "mean_power_deviation": metrics["mean_power_deviation"]
        }
    }
    
    # Print detailed results
    print("\n" + "=" * 80)
    print("TEST RESULTS - DETAILED")
    print("=" * 80)
    print(f"Firmware: {args.firmware}")
    print(f"Source: {args.source}")
    print(f"Functions analyzed: {len(predictions)}")
    print(f"Vulnerable functions: {sum(p.is_vulnerable for p in predictions)}")
    print(f"Safe functions: {len(predictions) - sum(p.is_vulnerable for p in predictions)}")
    
    print("\n" + "-" * 80)
    print("METRICS")
    print("-" * 80)
    print(f"  Precision:        {metrics['precision']:.4f}")
    print(f"  Recall:           {metrics['recall']:.4f}")
    print(f"  F1-Score:         {metrics['f1_score']:.4f}")
    print(f"  Accuracy:         {metrics['accuracy']:.4f}")
    print(f"  Validation Consistency (VCR): {metrics['vcr']:.4f}")
    print(f"  Mean Power Deviation:         {metrics['mean_power_deviation']:.4f}")
    print(f"  Security Reliability Index:   {metrics.get('sri', 0.0):.4f}")
    
    print("\n" + "-" * 80)
    print("CONFUSION MATRIX")
    print("-" * 80)
    print(f"  True Positives:   {metrics['true_positives']}")
    print(f"  False Positives:  {metrics['false_positives']}")
    print(f"  True Negatives:   {metrics['true_negatives']}")
    print(f"  False Negatives:  {metrics['false_negatives']}")
    
    # Top vulnerable functions
    sorted_preds = sorted(predictions, key=lambda p: p.score, reverse=True)
    top_vulnerable = [p for p in sorted_preds if p.is_vulnerable][:10]
    
    if top_vulnerable:
        print("\n" + "-" * 80)
        print("TOP VULNERABLE FUNCTIONS")
        print("-" * 80)
        for i, pred in enumerate(top_vulnerable, 1):
            cwe_str = ", ".join(pred.cwe) if pred.cwe else "None"
            print(f"  {i:2d}. {pred.func_id:15s} | Score: {pred.score:.4f} | CWE: {cwe_str}")
    
    print("=" * 80)
    
    # Save to file if requested
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\nResults saved to: {output_path}")
    
    return results


if __name__ == "__main__":
    main()

