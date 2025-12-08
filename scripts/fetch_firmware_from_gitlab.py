#!/usr/bin/env python3
"""GitLab API ile ESP32 firmware binary'lerini otomatik toplama"""

import requests
import json
from pathlib import Path
import time
import argparse
from typing import List, Dict, Optional
import zipfile
import io
import re


class GitLabFirmwareCollector:
    def __init__(self, token: str = None, gitlab_url: str = "https://gitlab.com"):
        self.token = token
        self.gitlab_url = gitlab_url.rstrip('/')
        self.headers = {"PRIVATE-TOKEN": token} if token else {}
        self.api_url = f"{self.gitlab_url}/api/v4"
    
    def search_projects(self, query: str = "esp32 firmware", max_results: int = 50) -> List[Dict]:
        """ESP32 ile ilgili projeleri ara"""
        repos = []
        page = 1
        per_page = 20
        
        while len(repos) < max_results:
            url = f"{self.api_url}/projects"
            params = {
                "search": query,
                "order_by": "last_activity_at",
                "sort": "desc",
                "page": page,
                "per_page": per_page
            }
            
            try:
                response = requests.get(url, headers=self.headers, params=params, timeout=30)
                if response.status_code != 200:
                    print(f"API error: {response.status_code}")
                    break
                
                data = response.json()
                if not data:
                    break
                
                repos.extend(data)
                page += 1
                
                if len(data) < per_page:
                    break
                
                time.sleep(0.5)  # Rate limiting
            except Exception as e:
                print(f"Search error: {e}")
                break
        
        return repos[:max_results]
    
    def get_releases(self, project_id: int) -> List[Dict]:
        """Proje release'lerini getir"""
        url = f"{self.api_url}/projects/{project_id}/releases"
        try:
            response = requests.get(url, headers=self.headers, timeout=30)
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            print(f"  Releases error: {e}")
        return []
    
    def get_latest_release(self, project_id: int) -> Optional[Dict]:
        """En son release'i getir"""
        releases = self.get_releases(project_id)
        if releases:
            return releases[0]
        return None
    
    def download_release_asset(self, project_id: int, tag_name: str, asset_name: str, output_path: Path) -> bool:
        """Release asset'ını indir"""
        url = f"{self.api_url}/projects/{project_id}/releases/{tag_name}/downloads/{asset_name}"
        try:
            response = requests.get(url, headers=self.headers, stream=True, timeout=60)
            if response.status_code == 200:
                output_path.parent.mkdir(parents=True, exist_ok=True)
                with open(output_path, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)
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
    
    def download_file(self, project_id: int, file_path: str, output_path: Path, ref: str = "main") -> bool:
        """Proje dosyasını indir"""
        url = f"{self.api_url}/projects/{project_id}/repository/files/{file_path.replace('/', '%2F')}/raw"
        params = {"ref": ref}
        try:
            response = requests.get(url, headers=self.headers, params=params, stream=True, timeout=60)
            if response.status_code == 200:
                output_path.parent.mkdir(parents=True, exist_ok=True)
                with open(output_path, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)
                return True
        except Exception as e:
            print(f"  File download error: {e}")
        return False
    
    def extract_bin_files(self, archive_path: Path, output_dir: Path) -> List[Path]:
        """Archive'dan .bin dosyalarını çıkar"""
        output_dir.mkdir(parents=True, exist_ok=True)
        extracted = []
        
        try:
            with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                for member in zip_ref.namelist():
                    if member.endswith('.bin') and ('firmware' in member.lower() or 'esp32' in member.lower()):
                        zip_ref.extract(member, output_dir)
                        extracted.append(output_dir / member)
        except Exception as e:
            print(f"  Archive extraction error: {e}")
        
        return extracted
    
    def collect_firmware(self, output_dir: Path, max_projects: int = 30, min_firmware: int = 20) -> int:
        """ESP32 firmware'lerini topla"""
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        print(f"Searching for ESP32 repositories on GitLab...")
        projects = self.search_projects("esp32 firmware", max_projects)
        print(f"Found {len(projects)} projects\n")
        
        downloaded = 0
        firmware_patterns = [
            r'.*\.bin$',
            r'.*firmware.*\.bin$',
            r'.*esp32.*\.bin$',
            r'.*build.*\.bin$',
            r'.*release.*\.bin$'
        ]
        
        for i, project in enumerate(projects, 1):
            project_id = project.get('id')
            project_name = project.get('name', 'unknown')
            project_path = project.get('path_with_namespace', 'unknown')
            
            print(f"[{i}/{len(projects)}] Processing: {project_path}")
            
            # 1. Check latest release
            try:
                latest_release = self.get_latest_release(project_id)
                if latest_release:
                    tag_name = latest_release.get('tag_name', '')
                    assets = latest_release.get('assets', {}).get('links', [])
                    for asset in assets:
                        name = asset.get('name', '')
                        url = asset.get('url', '')
                        if any(re.match(pattern, name.lower()) for pattern in firmware_patterns):
                            safe_name = re.sub(r'[^\w\-_\.]', '_', name)
                            output_path = output_dir / f"{project_path.replace('/', '_')}_{tag_name}_{safe_name}"
                            if not output_path.exists():
                                # Download from URL
                                try:
                                    response = requests.get(url, stream=True, timeout=60)
                                    if response.status_code == 200:
                                        with open(output_path, 'wb') as f:
                                            for chunk in response.iter_content(chunk_size=8192):
                                                f.write(chunk)
                                        print(f"  Downloaded: {name}")
                                        downloaded += 1
                                        if downloaded >= min_firmware:
                                            break
                                except Exception as e:
                                    print(f"  Asset download error: {e}")
            except Exception as e:
                print(f"  Release error: {e}")
            
            if downloaded >= min_firmware:
                break
            
            # 2. Check repository files for .bin files
            try:
                files = self.get_project_files(project_id, "", "main")
                for file_info in files:
                    if file_info.get('type') == 'blob':
                        file_path = file_info.get('path', '')
                        file_name = file_info.get('name', '')
                        if any(re.match(pattern, file_name.lower()) for pattern in firmware_patterns):
                            safe_name = re.sub(r'[^\w\-_\.]', '_', file_name)
                            output_path = output_dir / f"{project_path.replace('/', '_')}_{safe_name}"
                            if not output_path.exists() and output_path.suffix == '.bin':
                                if self.download_file(project_id, file_path, output_path, "main"):
                                    print(f"  Downloaded: {file_name}")
                                    downloaded += 1
                                    if downloaded >= min_firmware:
                                        break
            except Exception as e:
                print(f"  Files error: {e}")
            
            if downloaded >= min_firmware:
                break
            
            time.sleep(0.5)  # Rate limiting
        
        print(f"\nTotal downloaded: {downloaded} firmware files")
        return downloaded


def main():
    parser = argparse.ArgumentParser(description="GitLab'dan ESP32 firmware topla")
    parser.add_argument(
        "-o", "--output",
        type=str,
        default="./firmware_samples/gitlab",
        help="Output directory"
    )
    parser.add_argument(
        "-t", "--token",
        type=str,
        help="GitLab personal access token (optional but recommended)"
    )
    parser.add_argument(
        "-n", "--max-projects",
        type=int,
        default=30,
        help="Maximum projects to search"
    )
    parser.add_argument(
        "-m", "--min-firmware",
        type=int,
        default=20,
        help="Minimum firmware files to collect"
    )
    parser.add_argument(
        "--gitlab-url",
        type=str,
        default="https://gitlab.com",
        help="GitLab instance URL (default: https://gitlab.com)"
    )
    
    args = parser.parse_args()
    
    if not args.token:
        print("Warning: No token provided. API rate limits: 20 requests/minute")
        print("   Get token from: https://gitlab.com/-/user_settings/personal_access_tokens")
        print("   Token ile: daha yüksek rate limit\n")
    
    collector = GitLabFirmwareCollector(args.token, args.gitlab_url)
    collector.collect_firmware(Path(args.output), args.max_projects, args.min_firmware)


if __name__ == "__main__":
    main()

