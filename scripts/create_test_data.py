#!/usr/bin/env python3
"""Script to create test data for ESP32 FirmGuard"""

import json
from pathlib import Path
import argparse


def create_firmware_samples(output_dir: Path, num_samples: int = 5):
    """Create multiple firmware sample files"""
    output_dir.mkdir(parents=True, exist_ok=True)
    
    for i in range(1, num_samples + 1):
        firmware_path = output_dir / f"test_firmware_{i}.bin"
        # Create firmware with different sizes
        size = 1024 * (i + 1)  # 2KB, 3KB, 4KB, 5KB, 6KB
        firmware_path.write_bytes(b"\x00" * size)
        print(f"Created {firmware_path} ({size} bytes)")


def create_ground_truth_files(output_dir: Path):
    """Create ground truth files for test firmware"""
    ground_truth_dir = output_dir / "ground_truth"
    ground_truth_dir.mkdir(parents=True, exist_ok=True)
    
    # Standard function IDs that extractor creates
    standard_funcs = ["func_001", "func_002", "func_003", "func_004", "func_005"]
    
    # Create ground truth for example_firmware.bin
    example_gt = {
        "func_001": 1,  # process_uart_input - vulnerable
        "func_002": 1,  # handle_wifi_config - vulnerable
        "func_003": 0,  # parse_json - safe
        "func_004": 0,  # safe_memory_copy - safe
        "func_005": 1   # process_http_request - vulnerable
    }
    
    with open(ground_truth_dir / "example_firmware_ground_truth.json", 'w') as f:
        json.dump(example_gt, f, indent=2)
    print(f"Created {ground_truth_dir / 'example_firmware_ground_truth.json'}")
    
    # Create ground truth for test firmware samples
    for i in range(1, 6):
        prefix = f"test_firmware_{i}_"
        gt = {}
        # Randomly assign vulnerabilities (for testing)
        for j, func_id in enumerate(standard_funcs):
            # Make some functions vulnerable based on index
            gt[prefix + func_id] = 1 if j % 2 == 0 else 0
        
        gt_path = ground_truth_dir / f"test_firmware_{i}_ground_truth.json"
        with open(gt_path, 'w') as f:
            json.dump(gt, f, indent=2)
        print(f"Created {gt_path}")


def create_combined_ground_truth(output_dir: Path):
    """Create a combined ground truth file for all samples"""
    ground_truth_dir = output_dir / "ground_truth"
    combined_gt = {}
    
    # Load all individual ground truth files
    for gt_file in ground_truth_dir.glob("*_ground_truth.json"):
        if "combined" in gt_file.name:
            continue
        
        with open(gt_file, 'r') as f:
            gt = json.load(f)
            combined_gt.update(gt)
    
    # Save combined ground truth
    combined_path = ground_truth_dir / "combined_ground_truth.json"
    with open(combined_path, 'w') as f:
        json.dump(combined_gt, f, indent=2)
    
    print(f"Created combined ground truth: {combined_path}")
    print(f"Total functions: {len(combined_gt)}")
    print(f"Vulnerable functions: {sum(combined_gt.values())}")


def main():
    parser = argparse.ArgumentParser(description="Create test data for ESP32 FirmGuard")
    parser.add_argument(
        "-o", "--output",
        type=str,
        default="firmware_samples",
        help="Output directory for test data"
    )
    parser.add_argument(
        "-n", "--num-samples",
        type=int,
        default=5,
        help="Number of firmware samples to create"
    )
    parser.add_argument(
        "--firmware-only",
        action="store_true",
        help="Only create firmware files, not ground truth"
    )
    parser.add_argument(
        "--ground-truth-only",
        action="store_true",
        help="Only create ground truth files"
    )
    
    args = parser.parse_args()
    output_dir = Path(args.output)
    
    if not args.ground_truth_only:
        print("Creating firmware samples...")
        create_firmware_samples(output_dir, args.num_samples)
    
    if not args.firmware_only:
        print("\nCreating ground truth files...")
        create_ground_truth_files(output_dir)
        print("\nCreating combined ground truth...")
        create_combined_ground_truth(output_dir)
    
    print("\nTest data creation complete!")


if __name__ == "__main__":
    main()


