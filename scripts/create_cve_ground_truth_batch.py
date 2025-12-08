#!/usr/bin/env python3
"""Batch create CVE-based ground truth for multiple firmware"""

import sys
from pathlib import Path
import json
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

sys.path.insert(0, str(Path(__file__).parent.parent))

from esp32_firmguard.utils import load_config, setup_logging
from scripts.create_ground_truth_from_cve import fetch_esp32_cves, match_cve_to_functions
from esp32_firmguard.pipeline import FirmwareSecurityPipeline


def create_ground_truth_for_firmware(firmware_path: Path, config: dict, cves: list, output_dir: Path):
    """Create CVE-based ground truth for a single firmware"""
    try:
        pipeline = FirmwareSecurityPipeline(config)
        
        # Run static analysis
        fw, feature_matrix, predictions, cwe_labels = pipeline.run_static_stage(
            str(firmware_path),
            source="cve_ground_truth"
        )
        
        # Match CVEs to functions
        ground_truth = match_cve_to_functions(cves, fw, cwe_labels)
        
        # Save
        fw_name = firmware_path.stem
        output_path = output_dir / f"{fw_name}_ground_truth.json"
        with open(output_path, 'w') as f:
            json.dump(ground_truth, f, indent=2)
        
        vulnerable_count = sum(1 for v in ground_truth.values() if v == 1)
        return {
            "firmware": fw_name,
            "success": True,
            "total_functions": len(ground_truth),
            "vulnerable": vulnerable_count,
            "safe": len(ground_truth) - vulnerable_count
        }
    except Exception as e:
        return {
            "firmware": firmware_path.stem,
            "success": False,
            "error": str(e)
        }


def main():
    parser = argparse.ArgumentParser(description="Batch create CVE-based ground truth")
    parser.add_argument("firmware_dir", type=str, help="Directory containing firmware binaries")
    parser.add_argument("-o", "--output", type=str, default="./firmware_samples/ground_truth",
                       help="Output directory for ground truth files")
    parser.add_argument("-c", "--config", type=str, default="configs/config.yaml",
                       help="Path to config file")
    parser.add_argument("-n", "--max-firmware", type=int, default=None,
                       help="Maximum number of firmware to process")
    parser.add_argument("--log-level", type=str, default="ERROR",
                       choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    parser.add_argument("--workers", type=int, default=4,
                       help="Number of parallel workers")
    
    args = parser.parse_args()
    
    config = load_config(args.config)
    setup_logging(args.log_level)
    
    firmware_dir = Path(args.firmware_dir)
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Find firmware files
    firmware_files = list(firmware_dir.glob("*.bin"))
    if not firmware_files:
        firmware_files = list(firmware_dir.rglob("*.bin"))
    
    if args.max_firmware:
        firmware_files = firmware_files[:args.max_firmware]
    
    print(f"Found {len(firmware_files)} firmware files")
    print(f"Fetching CVEs from database...")
    
    # Fetch CVEs once (shared across all firmware)
    cves = fetch_esp32_cves()
    print(f"Found {len(cves)} CVEs")
    
    print(f"\nCreating ground truth for {len(firmware_files)} firmware...")
    print(f"Output directory: {output_dir}")
    print()
    
    results = []
    start_time = time.time()
    
    # Process in parallel
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(create_ground_truth_for_firmware, fw, config, cves, output_dir): fw
            for fw in firmware_files
        }
        
        for i, future in enumerate(as_completed(futures), 1):
            result = future.result()
            results.append(result)
            
            if result["success"]:
                print(f"[{i}/{len(firmware_files)}] {result['firmware']}: "
                      f"{result['vulnerable']} vulnerable, {result['safe']} safe")
            else:
                print(f"[{i}/{len(firmware_files)}] {result['firmware']}: ERROR - {result['error']}")
    
    elapsed_time = time.time() - start_time
    
    # Summary
    successful = [r for r in results if r["success"]]
    failed = [r for r in results if not r["success"]]
    
    total_functions = sum(r["total_functions"] for r in successful)
    total_vulnerable = sum(r["vulnerable"] for r in successful)
    total_safe = sum(r["safe"] for r in successful)
    
    print(f"\n{'='*80}")
    print("SUMMARY")
    print(f"{'='*80}")
    print(f"Total firmware: {len(results)}")
    print(f"Successful: {len(successful)}")
    print(f"Failed: {len(failed)}")
    print(f"Total time: {elapsed_time:.2f} seconds")
    print(f"Average per firmware: {elapsed_time/len(results):.2f} seconds")
    print()
    print(f"Total functions labeled: {total_functions}")
    print(f"Vulnerable: {total_vulnerable} ({total_vulnerable/total_functions*100:.1f}%)")
    print(f"Safe: {total_safe} ({total_safe/total_functions*100:.1f}%)")
    print(f"\nGround truth files saved to: {output_dir}")


if __name__ == "__main__":
    main()

