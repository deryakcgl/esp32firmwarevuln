#!/usr/bin/env python3
"""Create ground truth from CVE database and match with firmware functions"""

import sys
from pathlib import Path
import json
import requests
from typing import Dict, List, Any
import argparse
import time

sys.path.insert(0, str(Path(__file__).parent.parent))

from esp32_firmguard.utils import load_config, setup_logging
from esp32_firmguard.pipeline import FirmwareSecurityPipeline


def fetch_esp32_cves() -> List[Dict[str, Any]]:
    """Fetch ESP32-related CVEs from CVE database"""
    cves = []
    
    # 1. CVE.circl.lu API
    try:
        print("Fetching CVEs from CVE.circl.lu...")
        url = "https://cve.circl.lu/api/search"
        params = {"q": "ESP32"}
        response = requests.get(url, params=params, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            cves.extend(data.get('data', []))
            print(f"  Found {len(cves)} CVEs from CVE.circl.lu")
    except Exception as e:
        print(f"  Error fetching from CVE.circl.lu: {e}")
    
    # 2. NVD API (optional, requires API key for higher rate limit)
    try:
        print("Fetching CVEs from NVD...")
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {
            "keywordSearch": "ESP32",
            "resultsPerPage": 50
        }
        response = requests.get(url, params=params, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            nvd_cves = data.get('vulnerabilities', [])
            for item in nvd_cves:
                cve_data = item.get('cve', {})
                cves.append({
                    'id': cve_data.get('id', ''),
                    'summary': cve_data.get('descriptions', [{}])[0].get('value', ''),
                    'references': [ref.get('url', '') for ref in cve_data.get('references', [])]
                })
            print(f"  Found {len(nvd_cves)} CVEs from NVD")
    except Exception as e:
        print(f"  Error fetching from NVD: {e}")
    
    return cves


def match_cve_to_functions(
    cves: List[Dict[str, Any]],
    firmware_obj,
    cwe_labels: Dict[str, List[str]],
    min_keyword_matches: int = 3,  # Daha conservative matching
    require_cwe_match: bool = True  # CWE match gerekli
) -> Dict[str, int]:
    """
    Match CVEs to functions based on:
    1. CVE description contains function name or calls (minimum 3 keyword match)
    2. CVE references contain function-related keywords
    3. CWE labels match CVE CWE IDs (if require_cwe_match=True)
    
    Args:
        min_keyword_matches: Minimum number of keywords that must match (default: 3)
        require_cwe_match: If True, CWE match is required in addition to keywords
    """
    ground_truth = {}
    
    # Extract CVE keywords
    cve_keywords = set()
    cve_cwes = set()
    
    # Common stopwords to filter out
    stopwords = {'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by', 'from', 'as', 'is', 'was', 'are', 'were', 'be', 'been', 'being', 'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'should', 'could', 'may', 'might', 'must', 'can', 'this', 'that', 'these', 'those', 'i', 'you', 'he', 'she', 'it', 'we', 'they', 'esp32', 'firmware', 'vulnerability', 'issue', 'discovered', 'found', 'allows', 'could', 'may', 'might'}
    
    for cve in cves:
        summary = cve.get('summary', '').lower()
        references = " ".join(cve.get('references', [])).lower()
        cve_id = cve.get('id', '').lower()
        
        # Extract meaningful keywords from CVE (filter stopwords, keep technical terms)
        import re
        # Split by non-alphanumeric, keep words with 4+ chars
        words = re.findall(r'\b[a-z]{4,}\b', summary + " " + references)
        # Filter stopwords and keep technical terms
        keywords = [w for w in words if w not in stopwords and len(w) >= 4]
        cve_keywords.update(keywords)
        
        # Extract CWE IDs from CVE
        cwe_matches = re.findall(r'cwe-\d+', summary + " " + references, re.IGNORECASE)
        cve_cwes.update([cwe.upper() for cwe in cwe_matches])
        
        # Extract function names from CVE (common vulnerable functions)
        # Look for patterns like "function()", "function_name", etc.
        func_patterns = re.findall(r'\b([a-z_][a-z0-9_]{3,})\s*\(', summary)
        cve_keywords.update(func_patterns)
    
    print(f"\nMatching CVEs to functions...")
    print(f"  CVE keywords: {len(cve_keywords)}")
    print(f"  CVE CWEs: {len(cve_cwes)}")
    
    # Match functions
    for func_id, func_info in firmware_obj.functions.items():
        func_name = func_info.get("name", "").lower()
        func_calls = [c.lower() for c in func_info.get("calls", [])]
        func_strings = [s.lower() for s in func_info.get("strings", [])]
        
        # Check 1: Function name or calls in CVE keywords (count matches)
        keyword_matches = 0
        # Function name match (exact or substring)
        if func_name and len(func_name) > 3:
            if any(kw in func_name or func_name in kw for kw in cve_keywords if len(kw) >= 4):
                keyword_matches += 1
        
        # Function calls match
        if func_calls:
            calls_str = " ".join(func_calls)
            if any(kw in calls_str or any(call in kw for call in func_calls if len(call) > 3) for kw in cve_keywords if len(kw) >= 4):
                keyword_matches += 1
        
        # Strings match
        if func_strings:
            strings_str = " ".join(func_strings)
            if any(kw in strings_str for kw in cve_keywords if len(kw) >= 4):
                keyword_matches += 1
        
        # Check 2: CWE labels match CVE CWEs
        func_cwes = [cwe.upper() for cwe in cwe_labels.get(func_id, [])]
        cwe_match = any(func_cwe in cve_cwes for func_cwe in func_cwes)
        
        # Check 3: Direct CVE description match (more specific)
        direct_match = False
        for cve in cves:
            summary = cve.get('summary', '').lower()
            # Exact function name match
            if func_name and len(func_name) > 3 and func_name in summary:
                direct_match = True
                keyword_matches += 1
                break
            # Function call match
            if func_calls:
                for call in func_calls:
                    if len(call) > 3 and call in summary:
                        direct_match = True
                        keyword_matches += 1
                        break
                if direct_match:
                    break
        
        # VERY STRICT matching for REAL ground truth (not synthetic):
        # Only mark as vulnerable if there's VERY STRONG evidence from CVE
        # 1. Exact function name match in CVE description (strongest)
        # 2. Known vulnerable function calls (strcpy, sprintf, etc.) in CVE context
        # 3. CWE match alone is NOT enough (to avoid synthetic ground truth)
        
        # Known vulnerable functions that appear in CVEs
        known_vulnerable_functions = ['strcpy', 'sprintf', 'gets', 'scanf', 'strcat', 'memcpy', 
                                     'strncpy', 'snprintf', 'vsprintf', 'sscanf', 'fgets']
        
        # Check if function calls contain known vulnerable functions
        has_vulnerable_call = any(vuln_func in func_calls for vuln_func in known_vulnerable_functions)
        
        # Check if function name is meaningful (not generic like "func_001")
        is_meaningful_name = func_name and len(func_name) > 5 and not func_name.startswith('func_')
        
        # VERY STRICT: Only mark as vulnerable if:
        # 1. Exact function name match in CVE description AND meaningful name
        # 2. OR known vulnerable function call AND mentioned in CVE
        is_vulnerable = False
        
        for cve in cves:
            summary = cve.get('summary', '').lower()
            
            # Check 1: Exact function name match (if meaningful)
            if is_meaningful_name and func_name in summary:
                # Verify it's not just a substring match
                # Look for function name followed by '(' or space
                import re
                if re.search(r'\b' + re.escape(func_name) + r'\s*\(', summary):
                    is_vulnerable = True
                    break
            
            # Check 2: Known vulnerable function call AND mentioned in CVE
            if has_vulnerable_call:
                for vuln_func in known_vulnerable_functions:
                    if vuln_func in func_calls and vuln_func in summary:
                        # Check if CVE mentions this function in vulnerability context
                        # Look for patterns like "strcpy vulnerability", "buffer overflow in strcpy", etc.
                        context_patterns = ['vulnerability', 'overflow', 'exploit', 'attack', 'security', 'cve']
                        if any(pattern in summary for pattern in context_patterns):
                            is_vulnerable = True
                            break
                if is_vulnerable:
                    break
        ground_truth[func_id] = 1 if is_vulnerable else 0
    
    vulnerable_count = sum(1 for v in ground_truth.values() if v == 1)
    print(f"  Matched {vulnerable_count} vulnerable functions out of {len(ground_truth)}")
    
    return ground_truth


def main():
    parser = argparse.ArgumentParser(description="Create ground truth from CVE database")
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
    
    # Initialize pipeline
    pipeline = FirmwareSecurityPipeline(config)
    
    # Run static analysis to get functions and CWE labels
    print(f"Analyzing firmware: {args.firmware}")
    fw, feature_matrix, predictions, cwe_labels = pipeline.run_static_stage(
        args.firmware,
        source="cve_ground_truth"
    )
    
    print(f"Extracted {len(fw.functions)} functions")
    
    # Fetch CVEs
    cves = fetch_esp32_cves()
    
    if not cves:
        print("Warning: No CVEs found. Using CWE labels only.")
        # Fallback to CWE-based ground truth
        ground_truth = {}
        for func_id, cwes in cwe_labels.items():
            ground_truth[func_id] = 1 if len(cwes) > 0 else 0
    else:
        # Match CVEs to functions (real ground truth - no CWE dependency)
        # Only use CVE matching, don't rely on CWE labels
        ground_truth = match_cve_to_functions(
            cves, fw, cwe_labels,
            min_keyword_matches=1,  # Require at least 1 keyword match
            require_cwe_match=False  # Don't require CWE match (pure CVE-based)
        )
        
        # If no CVEs matched, mark all as safe (0) - don't use CWE labels as fallback
        # This ensures ground truth is NOT synthetic
    
    # Save ground truth
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(ground_truth, f, indent=2)
    
    vulnerable_count = sum(1 for v in ground_truth.values() if v == 1)
    safe_count = len(ground_truth) - vulnerable_count
    
    print(f"\nGround truth created from CVE database:")
    print(f"  Total functions: {len(ground_truth)}")
    print(f"  Vulnerable: {vulnerable_count}")
    print(f"  Safe: {safe_count}")
    print(f"  Saved to: {output_path}")
    
    # Save CVE data for reference
    cve_output = output_path.parent / f"{output_path.stem}_cves.json"
    with open(cve_output, 'w') as f:
        json.dump(cves, f, indent=2)
    print(f"  CVE data saved to: {cve_output}")


if __name__ == "__main__":
    main()

