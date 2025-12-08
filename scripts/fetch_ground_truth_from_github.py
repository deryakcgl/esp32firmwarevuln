#!/usr/bin/env python3
"""Fetch ground truth datasets from GitHub repositories"""

import sys
from pathlib import Path
import json
import requests
import re
from typing import Dict, List, Any, Optional
import argparse
import time

sys.path.insert(0, str(Path(__file__).parent.parent))


class GitHubGroundTruthCollector:
    """Collect ground truth from GitHub repositories"""
    
    def __init__(self, token: Optional[str] = None):
        self.token = token
        self.headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "ESP32-FirmGuard"
        }
        if token:
            self.headers["Authorization"] = f"token {token}"
        self.api_url = "https://api.github.com"
    
    def search_repositories(self, query: str, max_results: int = 50) -> List[Dict]:
        """Search GitHub repositories"""
        repos = []
        page = 1
        per_page = min(100, max_results)
        
        while len(repos) < max_results:
            url = f"{self.api_url}/search/repositories"
            params = {
                "q": query,
                "sort": "updated",
                "order": "desc",
                "per_page": per_page,
                "page": page
            }
            
            try:
                response = requests.get(url, headers=self.headers, params=params, timeout=30)
                if response.status_code == 200:
                    data = response.json()
                    items = data.get("items", [])
                    if not items:
                        break
                    repos.extend(items[:max_results - len(repos)])
                    page += 1
                    time.sleep(0.5)  # Rate limiting
                elif response.status_code == 403:
                    print("Rate limit exceeded. Please use a GitHub token.")
                    break
                else:
                    print(f"Error searching repositories: {response.status_code}")
                    break
            except Exception as e:
                print(f"Error: {e}")
                break
        
        return repos
    
    def search_issues(self, query: str, max_results: int = 50) -> List[Dict]:
        """Search GitHub issues (vulnerability reports, CVE discussions)"""
        issues = []
        page = 1
        per_page = min(100, max_results)
        
        while len(issues) < max_results:
            url = f"{self.api_url}/search/issues"
            params = {
                "q": query,
                "sort": "updated",
                "order": "desc",
                "per_page": per_page,
                "page": page
            }
            
            try:
                response = requests.get(url, headers=self.headers, params=params, timeout=30)
                if response.status_code == 200:
                    data = response.json()
                    items = data.get("items", [])
                    if not items:
                        break
                    issues.extend(items[:max_results - len(issues)])
                    page += 1
                    time.sleep(0.5)
                elif response.status_code == 403:
                    print("Rate limit exceeded. Please use a GitHub token.")
                    break
                else:
                    break
            except Exception as e:
                print(f"Error: {e}")
                break
        
        return issues
    
    def get_repository_files(self, owner: str, repo: str, path: str = "") -> List[Dict]:
        """Get files from repository"""
        url = f"{self.api_url}/repos/{owner}/{repo}/contents/{path}"
        try:
            response = requests.get(url, headers=self.headers, timeout=30)
            if response.status_code == 200:
                return response.json()
            return []
        except Exception as e:
            print(f"Error getting files: {e}")
            return []
    
    def download_file(self, owner: str, repo: str, path: str, output_path: Path) -> bool:
        """Download file from repository"""
        url = f"{self.api_url}/repos/{owner}/{repo}/contents/{path}"
        try:
            response = requests.get(url, headers=self.headers, timeout=30)
            if response.status_code == 200:
                data = response.json()
                if data.get("type") == "file":
                    import base64
                    content = base64.b64decode(data.get("content", ""))
                    output_path.parent.mkdir(parents=True, exist_ok=True)
                    with open(output_path, 'wb') as f:
                        f.write(content)
                    return True
        except Exception as e:
            print(f"Error downloading file: {e}")
        return False
    
    def extract_vulnerability_info(self, text: str) -> Dict[str, Any]:
        """Extract vulnerability information from text"""
        vuln_info = {
            "functions": [],
            "cwes": [],
            "cves": [],
            "severity": None
        }
        
        # Extract CVE IDs
        cve_pattern = r'CVE-\d{4}-\d{4,}'
        vuln_info["cves"] = re.findall(cve_pattern, text, re.IGNORECASE)
        
        # Extract CWE IDs
        cwe_pattern = r'CWE-(\d+)'
        vuln_info["cwes"] = [f"CWE-{cwe}" for cwe in re.findall(cwe_pattern, text, re.IGNORECASE)]
        
        # Extract function names (common patterns)
        # Look for patterns like "function_name()", "in function_name", etc.
        func_patterns = [
            r'function\s+([a-z_][a-z0-9_]*)',
            r'in\s+([a-z_][a-z0-9_]*)\s*\(',
            r'([a-z_][a-z0-9_]*)\s*\(\)',
            r'vulnerability\s+in\s+([a-z_][a-z0-9_]*)',
        ]
        for pattern in func_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            vuln_info["functions"].extend(matches)
        
        # Extract severity
        severity_keywords = {
            "critical": ["critical", "crash", "remote code execution", "rce"],
            "high": ["high", "buffer overflow", "stack overflow"],
            "medium": ["medium", "denial of service", "dos"],
            "low": ["low", "information disclosure"]
        }
        text_lower = text.lower()
        for severity, keywords in severity_keywords.items():
            if any(kw in text_lower for kw in keywords):
                vuln_info["severity"] = severity
                break
        
        return vuln_info
    
    def collect_ground_truth(self, output_dir: Path, max_repos: int = 20) -> int:
        """Collect ground truth from GitHub"""
        output_dir.mkdir(parents=True, exist_ok=True)
        
        print("=" * 80)
        print("GitHub Ground Truth Collection")
        print("=" * 80)
        print()
        
        # Search queries for different types of repositories
        search_queries = [
            "ESP32 vulnerability security",
            "ESP32 CVE firmware",
            "ESP32 security analysis",
            "firmware vulnerability dataset",
            "ESP-IDF security",
            "ESP32 buffer overflow",
        ]
        
        all_repos = []
        for query in search_queries:
            print(f"Searching: {query}")
            repos = self.search_repositories(query, max_results=max_repos // len(search_queries))
            all_repos.extend(repos)
            print(f"  Found {len(repos)} repositories")
            time.sleep(1)  # Rate limiting
        
        # Remove duplicates
        seen = set()
        unique_repos = []
        for repo in all_repos:
            repo_id = repo.get("full_name", "")
            if repo_id and repo_id not in seen:
                seen.add(repo_id)
                unique_repos.append(repo)
        
        print(f"\nTotal unique repositories: {len(unique_repos)}")
        print()
        
        # Search for issues (vulnerability reports)
        print("Searching for vulnerability reports in issues...")
        issue_queries = [
            "ESP32 CVE",
            "ESP32 vulnerability",
            "ESP32 security",
            "ESP-IDF CVE",
        ]
        
        all_issues = []
        for query in issue_queries:
            issues = self.search_issues(query, max_results=20)
            all_issues.extend(issues)
            print(f"  Found {len(issues)} issues for: {query}")
            time.sleep(1)
        
        # Extract vulnerability information from issues
        print("\nExtracting vulnerability information from issues...")
        vulnerability_data = []
        for issue in all_issues[:50]:  # Limit to 50 issues
            title = issue.get("title", "")
            body = issue.get("body", "")
            text = f"{title}\n{body}"
            
            vuln_info = self.extract_vulnerability_info(text)
            if vuln_info["functions"] or vuln_info["cwes"] or vuln_info["cves"]:
                vuln_info["source"] = issue.get("html_url", "")
                vuln_info["title"] = title
                vulnerability_data.append(vuln_info)
        
        print(f"  Extracted {len(vulnerability_data)} vulnerability reports")
        
        # Search for ground truth files in repositories
        print("\nSearching for ground truth files in repositories...")
        ground_truth_files = []
        
        for repo in unique_repos[:20]:  # Limit to 20 repos
            owner = repo.get("owner", {}).get("login", "")
            repo_name = repo.get("name", "")
            full_name = repo.get("full_name", "")
            
            if not owner or not repo_name:
                continue
            
            print(f"  Checking: {full_name}")
            
            # Look for common ground truth file patterns
            patterns = [
                "ground_truth",
                "vulnerability",
                "cve",
                "security",
                "dataset",
                "labels",
            ]
            
            files = self.get_repository_files(owner, repo_name)
            for file_info in files:
                if file_info.get("type") == "file":
                    file_name = file_info.get("name", "").lower()
                    file_path = file_info.get("path", "")
                    
                    # Check if file matches patterns
                    if any(pattern in file_name for pattern in patterns):
                        if file_name.endswith(('.json', '.csv', '.txt', '.md')):
                            output_path = output_dir / f"{full_name.replace('/', '_')}_{file_name}"
                            if self.download_file(owner, repo_name, file_path, output_path):
                                ground_truth_files.append(str(output_path))
                                print(f"    Downloaded: {file_name}")
            
            time.sleep(0.5)
        
        # Save vulnerability data
        vuln_data_path = output_dir / "vulnerability_reports.json"
        with open(vuln_data_path, 'w') as f:
            json.dump(vulnerability_data, f, indent=2)
        print(f"\nSaved vulnerability reports to: {vuln_data_path}")
        
        # Summary
        print("\n" + "=" * 80)
        print("SUMMARY")
        print("=" * 80)
        print(f"Repositories searched: {len(unique_repos)}")
        print(f"Issues found: {len(all_issues)}")
        print(f"Vulnerability reports extracted: {len(vulnerability_data)}")
        print(f"Ground truth files downloaded: {len(ground_truth_files)}")
        print(f"\nOutput directory: {output_dir}")
        
        return len(vulnerability_data) + len(ground_truth_files)


def main():
    parser = argparse.ArgumentParser(description="Fetch ground truth from GitHub")
    parser.add_argument("-o", "--output", type=str, default="./firmware_samples/ground_truth/github",
                       help="Output directory")
    parser.add_argument("-t", "--token", type=str,
                       help="GitHub personal access token (optional but recommended)")
    parser.add_argument("-n", "--max-repos", type=int, default=20,
                       help="Maximum repositories to search")
    
    args = parser.parse_args()
    
    if not args.token:
        print("Warning: No token provided. API rate limits: 60 requests/hour")
        print("   Get token from: https://github.com/settings/tokens")
        print("   Token ile: 5000 requests/hour\n")
    
    collector = GitHubGroundTruthCollector(args.token)
    collector.collect_ground_truth(Path(args.output), args.max_repos)


if __name__ == "__main__":
    main()

