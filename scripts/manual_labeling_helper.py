#!/usr/bin/env python3
"""Interactive helper for manual ground truth labeling"""

import sys
from pathlib import Path
import json
import argparse

sys.path.insert(0, str(Path(__file__).parent.parent))

from esp32_firmguard.utils import load_config, setup_logging
from esp32_firmguard.pipeline import FirmwareSecurityPipeline


def create_function_list(firmware_path: str, config: dict) -> list:
    """Create list of functions for manual labeling"""
    pipeline = FirmwareSecurityPipeline(config)
    
    # Run static analysis
    fw, feature_matrix, predictions, cwe_labels = pipeline.run_static_stage(
        firmware_path,
        source="manual_labeling"
    )
    
    function_list = []
    for func_id, func_info in fw.functions.items():
        function_list.append({
            "func_id": func_id,
            "name": func_info.get("name", ""),
            "address": func_info.get("address", ""),
            "size": func_info.get("size", 0),
            "calls": func_info.get("calls", []),
            "strings": func_info.get("strings", []),
            "cwe_labels": cwe_labels.get(func_id, []),
            "prediction_score": next((p.score for p in predictions if p.func_id == func_id), 0.0)
        })
    
    return function_list


def interactive_labeling(function_list: list, firmware_name: str) -> dict:
    """Interactive labeling interface"""
    ground_truth = {}
    
    print("=" * 80)
    print(f"MANUAL LABELING: {firmware_name}")
    print("=" * 80)
    print("\nInstructions:")
    print("  1 = Vulnerable (has security vulnerability)")
    print("  0 = Safe (no vulnerability)")
    print("  s = Skip (uncertain, don't label)")
    print("  q = Quit and save")
    print("  b = Go back to previous function")
    print()
    
    i = 0
    history = []  # For 'back' functionality
    
    while i < len(function_list):
        func = function_list[i]
        func_id = func["func_id"]
        
        # Skip if already labeled
        if func_id in ground_truth:
            i += 1
            continue
        
        print(f"\n[{i+1}/{len(function_list)}] Function: {func_id}")
        print(f"  Name: {func['name']}")
        print(f"  Address: {func['address']}")
        print(f"  Size: {func['size']} bytes")
        print(f"  Calls: {', '.join(func['calls'][:10])}")
        if func['strings']:
            print(f"  Strings: {', '.join(func['strings'][:5])}")
        if func['cwe_labels']:
            print(f"  CWE Labels: {', '.join(func['cwe_labels'])}")
        print(f"  Prediction Score: {func['prediction_score']:.3f}")
        print()
        
        label = input("Label (1/0/s/q/b): ").strip().lower()
        
        if label == 'q':
            break
        elif label == 'b':
            if history:
                i = history.pop()
                # Remove last label
                last_func_id = function_list[i]["func_id"]
                if last_func_id in ground_truth:
                    del ground_truth[last_func_id]
                continue
            else:
                print("  Cannot go back further")
                continue
        elif label == '1':
            ground_truth[func_id] = 1
            history.append(i)
            i += 1
        elif label == '0':
            ground_truth[func_id] = 0
            history.append(i)
            i += 1
        elif label == 's':
            # Skip, don't label
            i += 1
        else:
            print("  Invalid input. Please enter 1, 0, s, q, or b")
    
    return ground_truth


def main():
    parser = argparse.ArgumentParser(description="Interactive manual ground truth labeling")
    parser.add_argument("firmware", type=str, help="Path to firmware binary")
    parser.add_argument("-o", "--output", type=str, required=True,
                       help="Output JSON file for ground truth")
    parser.add_argument("-c", "--config", type=str, default="configs/config.yaml",
                       help="Path to config file")
    parser.add_argument("--load-existing", type=str,
                       help="Load existing ground truth to continue labeling")
    parser.add_argument("--log-level", type=str, default="ERROR",
                       choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    
    args = parser.parse_args()
    
    config = load_config(args.config)
    setup_logging(args.log_level)
    
    # Load existing ground truth if provided
    existing_gt = {}
    if args.load_existing:
        with open(args.load_existing, 'r') as f:
            existing_gt = json.load(f)
        print(f"Loaded existing ground truth: {len(existing_gt)} labels")
    
    # Create function list
    print("Analyzing firmware...")
    function_list = create_function_list(args.firmware, config)
    print(f"Found {len(function_list)} functions")
    
    # Interactive labeling
    new_gt = interactive_labeling(function_list, Path(args.firmware).stem)
    
    # Merge with existing
    ground_truth = {**existing_gt, **new_gt}
    
    # Save
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(ground_truth, f, indent=2)
    
    vulnerable_count = sum(1 for v in ground_truth.values() if v == 1)
    safe_count = sum(1 for v in ground_truth.values() if v == 0)
    total_labeled = len(ground_truth)
    
    print(f"\n{'=' * 80}")
    print("LABELING COMPLETE")
    print(f"{'=' * 80}")
    print(f"Total functions: {len(function_list)}")
    print(f"Labeled: {total_labeled} ({total_labeled/len(function_list)*100:.1f}%)")
    print(f"Vulnerable: {vulnerable_count}")
    print(f"Safe: {safe_count}")
    print(f"Saved to: {output_path}")


if __name__ == "__main__":
    main()

