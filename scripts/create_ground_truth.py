#!/usr/bin/env python3
"""Create ground truth labels from firmware analysis"""

import sys
from pathlib import Path
import json

sys.path.insert(0, str(Path(__file__).parent.parent))

from esp32_firmguard.utils import load_config, setup_logging
from esp32_firmguard.pipeline import FirmwareSecurityPipeline


def create_ground_truth_hybrid(firmware_path: str, config: dict, output_path: Path):
    """
    Create ground truth using hybrid method:
    1. CWE labels (CWE present = vulnerable)
    2. High-confidence predictions
    3. Combine and save
    """
    pipeline = FirmwareSecurityPipeline(config)
    
    # Run static analysis
    print(f"Analyzing firmware: {firmware_path}")
    fw, feature_matrix, predictions, cwe_labels = pipeline.run_static_stage(
        firmware_path,
        source="ground_truth"
    )
    
    ground_truth = {}
    
    # Method 1: CWE-based (CWE present = vulnerable)
    cwe_based = {}
    for func_id, cwes in cwe_labels.items():
        cwe_based[func_id] = 1 if len(cwes) > 0 else 0
    
    # Method 2: High-confidence predictions
    prediction_based = {}
    for pred in predictions:
        if pred.score >= 0.7:
            prediction_based[pred.func_id] = 1
        elif pred.score <= 0.3:
            prediction_based[pred.func_id] = 0
        # Middle scores (0.3-0.7) are uncertain, skip
    
    # Combine: If either method says vulnerable, mark as vulnerable
    # If both say safe, mark as safe
    # If uncertain, use CWE-based (more conservative)
    all_func_ids = set(cwe_based.keys()) | set(prediction_based.keys())
    
    for func_id in all_func_ids:
        cwe_label = cwe_based.get(func_id, 0)
        pred_label = prediction_based.get(func_id, None)
        
        if pred_label is not None:
            # Use prediction if available (higher confidence)
            ground_truth[func_id] = pred_label
        else:
            # Fall back to CWE-based
            ground_truth[func_id] = cwe_label
    
    # Save ground truth
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(ground_truth, f, indent=2)
    
    vulnerable_count = sum(1 for v in ground_truth.values() if v == 1)
    safe_count = len(ground_truth) - vulnerable_count
    
    print(f"\nGround truth created:")
    print(f"  Total functions: {len(ground_truth)}")
    print(f"  Vulnerable: {vulnerable_count}")
    print(f"  Safe: {safe_count}")
    print(f"  Saved to: {output_path}")
    
    return ground_truth


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Create ground truth labels from firmware")
    parser.add_argument("firmware", type=str, help="Path to firmware binary")
    parser.add_argument("-o", "--output", type=str, required=True,
                       help="Output JSON file for ground truth")
    parser.add_argument("-c", "--config", type=str, default="configs/config.yaml",
                       help="Path to config file")
    parser.add_argument("--log-level", type=str, default="ERROR",
                       choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    
    args = parser.parse_args()
    
    config = load_config(args.config)
    setup_logging(args.log_level)
    
    create_ground_truth_hybrid(
        args.firmware,
        config,
        Path(args.output)
    )


if __name__ == "__main__":
    main()

