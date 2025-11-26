#!/usr/bin/env python3
"""Example script to run the full pipeline on a firmware file"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from esp32_firmguard.utils import load_config, setup_logging
from esp32_firmguard.pipeline import FirmwareSecurityPipeline


def main():
    """Run full pipeline on a firmware file"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Run full ESP32 FirmGuard pipeline")
    parser.add_argument("firmware", type=str, help="Path to firmware binary")
    parser.add_argument("-c", "--config", type=str, default="configs/config.yaml",
                       help="Path to config file")
    parser.add_argument("-s", "--source", type=str, default="unknown",
                       help="Firmware source")
    parser.add_argument("--skip-validation", action="store_true",
                       help="Skip validation stage")
    parser.add_argument("--log-level", type=str, default="INFO",
                       choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    
    args = parser.parse_args()
    
    # Setup
    config = load_config(args.config)
    setup_logging(args.log_level)
    
    # Create pipeline
    pipeline = FirmwareSecurityPipeline(config)
    
    # Run pipeline
    results = pipeline.run_full_pipeline(
        firmware_path=args.firmware,
        source=args.source,
        run_validation=not args.skip_validation,
        run_evaluation=False
    )
    
    # Print results
    print("\n" + "=" * 80)
    print("Pipeline Results")
    print("=" * 80)
    print(f"\nFirmware: {args.firmware}")
    print(f"Source: {args.source}")
    print(f"\nFunctions analyzed: {len(results['predictions'])}")
    print(f"Vulnerable functions: {sum(p.is_vulnerable for p in results['predictions'])}")
    
    print("\nTop vulnerable functions:")
    sorted_preds = sorted(results['predictions'], key=lambda p: p.score, reverse=True)
    for pred in sorted_preds[:10]:
        if pred.is_vulnerable:
            print(f"  {pred.func_id}: score={pred.score:.3f}, CWE={pred.cwe}")
    
    if results.get("fuzz_results"):
        print(f"\nFuzzing results: {len(results['fuzz_results'])} functions")
        total_crashes = sum(r.crashes_found for r in results['fuzz_results'].values())
        print(f"  Total crashes found: {total_crashes}")
    
    if results.get("hw_results"):
        print(f"\nHardware power results: {len(results['hw_results'])} functions")
        anomalies = sum(1 for r in results['hw_results'].values() if r.is_anomaly)
        print(f"  Anomalies detected: {anomalies}")
    
    print("=" * 80)


if __name__ == "__main__":
    main()


