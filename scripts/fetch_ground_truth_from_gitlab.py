#!/usr/bin/env python3
"""GitLab/dış kaynaklardan ground truth dataset bulma ve indirme"""

import requests
import json
from pathlib import Path
import time
import argparse
from typing import List, Dict, Optional
import re


class GroundTruthCollector:
    def __init__(self, token: str = None, gitlab_url: str = "https://gitlab.com"):
        self.token = token
        self.gitlab_url = gitlab_url.rstrip('/')
        self.headers = {"PRIVATE-TOKEN": token} if token else {}
        self.api_url = f"{self.gitlab_url}/api/v4"
    
    def search_cve_databases(self, query: str = "ESP32 CVE vulnerability") -> List[Dict]:
        """CVE database'lerinde ESP32 vulnerability'leri ara"""
        # CVE database sources
        sources = []
        
        # 1. MITRE CVE database (public API)
        try:
            url = "https://cve.circl.lu/api/search"
            params = {"q": "ESP32"}
            response = requests.get(url, params=params, timeout=30)
            if response.status_code == 200:
                data = response.json()
                sources.extend(data.get('data', []))
        except Exception as e:
            print(f"CVE search error: {e}")
        
        return sources
    
    def search_gitlab_ground_truth(self, query: str = "firmware vulnerability ground truth") -> List[Dict]:
        """GitLab'da ground truth dataset'leri ara"""
        projects = []
        page = 1
        per_page = 20
        
        search_queries = [
            "firmware vulnerability dataset",
            "firmware ground truth",
            "CWE labels firmware",
            "firmware security dataset"
        ]
        
        for search_query in search_queries:
            while len(projects) < 50:
                url = f"{self.api_url}/projects"
                params = {
                    "search": search_query,
                    "order_by": "last_activity_at",
                    "sort": "desc",
                    "page": page,
                    "per_page": per_page
                }
                
                try:
                    response = requests.get(url, headers=self.headers, params=params, timeout=30)
                    if response.status_code == 200:
                        data = response.json()
                        if not data:
                            break
                        projects.extend(data)
                        page += 1
                        if len(data) < per_page:
                            break
                    time.sleep(0.5)
                except Exception as e:
                    print(f"Search error: {e}")
                    break
        
        return projects[:50]
    
    def download_ground_truth_file(self, project_id: int, file_path: str, output_path: Path, ref: str = "main") -> bool:
        """Ground truth dosyasını indir"""
        url = f"{self.api_url}/projects/{project_id}/repository/files/{file_path.replace('/', '%2F')}/raw"
        params = {"ref": ref}
        try:
            response = requests.get(url, headers=self.headers, params=params, timeout=60)
            if response.status_code == 200:
                output_path.parent.mkdir(parents=True, exist_ok=True)
                with open(output_path, 'wb') as f:
                    f.write(response.content)
                return True
        except Exception as e:
            print(f"  Download error: {e}")
        return False
    
    def get_project_files(self, project_id: int, path: str = "", ref: str = "main") -> List[Dict]:
        """Proje dosyalarını listele"""
        url = f"{self.api_url}/projects/{project_id}/repository/tree"
        params = {"path": path, "ref": ref, "recursive": "true"}
        try:
            response = requests.get(url, headers=self.headers, params=params, timeout=30)
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            print(f"  Files error: {e}")
        return []
    
    def collect_ground_truth(self, output_dir: Path) -> int:
        """Ground truth dataset'lerini topla"""
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        downloaded = 0
        
        # 1. GitLab'da ground truth dataset'leri ara
        print("Searching GitLab for ground truth datasets...")
        projects = self.search_gitlab_ground_truth()
        print(f"Found {len(projects)} potential projects\n")
        
        ground_truth_patterns = [
            r'.*ground.*truth.*\.json$',
            r'.*labels.*\.json$',
            r'.*vulnerability.*\.json$',
            r'.*cwe.*\.json$',
            r'.*dataset.*\.json$'
        ]
        
        for i, project in enumerate(projects[:20], 1):  # İlk 20 projeyi kontrol et
            project_id = project.get('id')
            project_path = project.get('path_with_namespace', 'unknown')
            
            print(f"[{i}/{min(20, len(projects))}] Checking: {project_path}")
            
            try:
                files = self.get_project_files(project_id, "", "main")
                for file_info in files:
                    if file_info.get('type') == 'blob':
                        file_path = file_info.get('path', '')
                        file_name = file_info.get('name', '')
                        if any(re.match(pattern, file_name.lower()) for pattern in ground_truth_patterns):
                            safe_name = re.sub(r'[^\w\-_\.]', '_', file_name)
                            output_path = output_dir / f"{project_path.replace('/', '_')}_{safe_name}"
                            if not output_path.exists():
                                if self.download_ground_truth_file(project_id, file_path, output_path):
                                    print(f"  Downloaded: {file_name}")
                                    downloaded += 1
            except Exception as e:
                print(f"  Error: {e}")
            
            time.sleep(0.5)
        
        # 2. CVE database'den vulnerability bilgileri topla
        print("\nSearching CVE databases for ESP32 vulnerabilities...")
        cves = self.search_cve_databases()
        if cves:
            cve_output = output_dir / "cve_esp32_vulnerabilities.json"
            with open(cve_output, 'w') as f:
                json.dump(cves, f, indent=2)
            print(f"  Saved {len(cves)} CVE entries to {cve_output}")
            downloaded += 1
        
        print(f"\nTotal downloaded: {downloaded} ground truth files")
        return downloaded


def main():
    parser = argparse.ArgumentParser(description="GitLab/dış kaynaklardan ground truth dataset topla")
    parser.add_argument(
        "-o", "--output",
        type=str,
        default="./firmware_samples/ground_truth",
        help="Output directory"
    )
    parser.add_argument(
        "-t", "--token",
        type=str,
        help="GitLab personal access token (optional but recommended)"
    )
    parser.add_argument(
        "--gitlab-url",
        type=str,
        default="https://gitlab.com",
        help="GitLab instance URL"
    )
    
    args = parser.parse_args()
    
    if not args.token:
        print("Warning: No token provided. API rate limits: 20 requests/minute")
        print("   Get token from: https://gitlab.com/-/user_settings/personal_access_tokens\n")
    
    collector = GroundTruthCollector(args.token, args.gitlab_url)
    collector.collect_ground_truth(Path(args.output))


if __name__ == "__main__":
    main()

