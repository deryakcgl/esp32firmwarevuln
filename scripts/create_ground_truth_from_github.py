#!/usr/bin/env python3
"""Create ground truth from GitHub vulnerability reports"""

import sys
from pathlib import Path
import json
import re
from typing import Dict, List, Any
import argparse

sys.path.insert(0, str(Path(__file__).parent.parent))

from esp32_firmguard.utils import load_config, setup_logging
from esp32_firmguard.pipeline import FirmwareSecurityPipeline


def load_github_vulnerability_reports(reports_path: Path) -> List[Dict[str, Any]]:
    """Load vulnerability reports from GitHub"""
    if not reports_path.exists():
        return []
    
    with open(reports_path, 'r') as f:
        return json.load(f)


def match_vulnerability_to_functions(
    vulnerability_reports: List[Dict[str, Any]],
    firmware_obj,
    cwe_labels: Dict[str, List[str]]
) -> Dict[str, int]:
    """
    Match vulnerability reports to firmware functions.
    This creates REAL ground truth (not synthetic) based on actual vulnerability reports.
    """
    ground_truth = {}
    
    # Extract all vulnerable function names from reports
    vulnerable_functions = set()
    vulnerable_cwes = set()
    vulnerable_cves = set()
    
    for report in vulnerability_reports:
        # Functions mentioned in vulnerability reports
        for func_name in report.get("functions", []):
            vulnerable_functions.add(func_name.lower())
        
        # CWEs mentioned in reports
        for cwe in report.get("cwes", []):
            vulnerable_cwes.add(cwe.upper())
        
        # CVEs mentioned in reports
        for cve in report.get("cves", []):
            vulnerable_cves.add(cve.upper())
    
    print(f"\nMatching vulnerability reports to functions...")
    print(f"  Vulnerable functions from reports: {len(vulnerable_functions)}")
    print(f"  Vulnerable CWEs from reports: {len(vulnerable_cwes)}")
    print(f"  Vulnerable CVEs from reports: {len(vulnerable_cves)}")
    
    # Match functions
    for func_id, func_info in firmware_obj.functions.items():
        func_name = func_info.get("name", "").lower()
        func_calls = [c.lower() for c in func_info.get("calls", [])]
        func_cwes = [cwe.upper() for cwe in cwe_labels.get(func_id, [])]
        
        is_vulnerable = False
        
        # Check 1: Function name matches vulnerable function from reports
        if func_name in vulnerable_functions:
            is_vulnerable = True
        
        # Check 2: Function calls contain vulnerable functions
        if not is_vulnerable:
            for vuln_func in vulnerable_functions:
                if vuln_func in func_calls or any(vuln_func in call for call in func_calls):
                    is_vulnerable = True
                    break
        
        # Check 3: CWE match (if CWE is mentioned in vulnerability reports)
        if not is_vulnerable and vulnerable_cwes:
            if any(func_cwe in vulnerable_cwes for func_cwe in func_cwes):
                is_vulnerable = True
        
        # Check 4: Function name contains vulnerable function patterns
        if not is_vulnerable:
            # Check if function name contains parts of vulnerable function names
            for vuln_func in vulnerable_functions:
                if len(vuln_func) > 5 and vuln_func in func_name:
                    is_vulnerable = True
                    break
        
        ground_truth[func_id] = 1 if is_vulnerable else 0
    
    vulnerable_count = sum(1 for v in ground_truth.values() if v == 1)
    print(f"  Matched {vulnerable_count} vulnerable functions out of {len(ground_truth)}")
    
    return ground_truth


def main():
    parser = argparse.ArgumentParser(description="Create ground truth from GitHub vulnerability reports")
    parser.add_argument("firmware", type=str, help="Path to firmware binary")
    parser.add_argument("-o", "--output", type=str, required=True,
                       help="Output JSON file for ground truth")
    parser.add_argument("-r", "--reports", type=str,
                       default="./firmware_samples/ground_truth/github/vulnerability_reports.json",
                       help="Path to GitHub vulnerability reports JSON")
    parser.add_argument("-c", "--config", type=str, default="configs/config.yaml",
                       help="Path to config file")
    parser.add_argument("--log-level", type=str, default="ERROR",
                       choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    
    args = parser.parse_args()
    
    config = load_config(args.config)
    setup_logging(args.log_level)
    
    # Load vulnerability reports
    reports_path = Path(args.reports)
    if not reports_path.exists():
        print(f"Error: Vulnerability reports file not found: {reports_path}")
        print("Run: python scripts/fetch_ground_truth_from_github.py first")
        return
    
    vulnerability_reports = load_github_vulnerability_reports(reports_path)
    if not vulnerability_reports:
        print("Warning: No vulnerability reports found. Using empty ground truth.")
        ground_truth = {}
    else:
        print(f"Loaded {len(vulnerability_reports)} vulnerability reports from GitHub")
        
        # Initialize pipeline
        pipeline = FirmwareSecurityPipeline(config)
        
        # Run static analysis
        print(f"Analyzing firmware: {args.firmware}")
        fw, feature_matrix, predictions, cwe_labels = pipeline.run_static_stage(
            args.firmware,
            source="github_ground_truth"
        )
        
        print(f"Extracted {len(fw.functions)} functions")
        
        # Match vulnerability reports to functions
        ground_truth = match_vulnerability_to_functions(
            vulnerability_reports, fw, cwe_labels
        )
    
    # Save ground truth
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(ground_truth, f, indent=2)
    
    vulnerable_count = sum(1 for v in ground_truth.values() if v == 1)
    safe_count = len(ground_truth) - vulnerable_count
    
    print(f"\nGround truth created from GitHub vulnerability reports:")
    print(f"  Total functions: {len(ground_truth)}")
    print(f"  Vulnerable: {vulnerable_count} ({vulnerable_count/len(ground_truth)*100:.1f}%)")
    print(f"  Safe: {safe_count} ({safe_count/len(ground_truth)*100:.1f}%)")
    print(f"  Saved to: {output_path}")


if __name__ == "__main__":
    main()

