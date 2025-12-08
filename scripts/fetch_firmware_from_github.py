#!/usr/bin/env python3
"""GitHub API ile ESP32 firmware binary'lerini otomatik toplama"""

import requests
import json
from pathlib import Path
import time
import argparse
from typing import List, Dict
import zipfile
import io


class GitHubFirmwareCollector:
    def __init__(self, token: str = None):
        self.token = token
        self.headers = {"Authorization": f"token {token}"} if token else {}
        self.api_url = "https://api.github.com"
    
    def search_repos(self, query: str = "esp32 firmware", max_results: int = 50) -> List[Dict]:
        """ESP32 ile ilgili repository'leri ara"""
        repos = []
        page = 1
        per_page = 30
        
        while len(repos) < max_results:
            url = f"{self.api_url}/search/repositories"
            params = {
                "q": query,
                "sort": "updated",
                "order": "desc",
                "page": page,
                "per_page": per_page
            }
            
            response = requests.get(url, headers=self.headers, params=params)
            if response.status_code != 200:
                print(f"API error: {response.status_code}")
                break
            
            data = response.json()
            items = data.get('items', [])
            if not items:
                break
            
            repos.extend(items)
            page += 1
            
            if len(items) < per_page:
                break
            
            time.sleep(1)  # Rate limiting
        
        return repos[:max_results]
    
    def get_releases(self, owner: str, repo: str) -> List[Dict]:
        """Proje release'lerini getir"""
        url = f"{self.api_url}/repos/{owner}/{repo}/releases"
        response = requests.get(url, headers=self.headers)
        if response.status_code == 200:
            return response.json()
        return []
    
    def get_latest_release(self, owner: str, repo: str) -> Dict:
        """En son release'i getir"""
        url = f"{self.api_url}/repos/{owner}/{repo}/releases/latest"
        response = requests.get(url, headers=self.headers)
        if response.status_code == 200:
            return response.json()
        return {}
    
    def download_asset(self, asset_url: str, output_path: Path):
        """Release asset'ını indir"""
        headers = self.headers.copy()
        headers['Accept'] = 'application/octet-stream'
        
        response = requests.get(asset_url, headers=headers, stream=True)
        if response.status_code == 200:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            return True
        return False
    
    def get_workflow_artifacts(self, owner: str, repo: str) -> List[Dict]:
        """GitHub Actions artifact'larını getir"""
        url = f"{self.api_url}/repos/{owner}/{repo}/actions/artifacts"
        response = requests.get(url, headers=self.headers)
        if response.status_code == 200:
            data = response.json()
            return data.get('artifacts', [])
        return []
    
    def download_artifact(self, owner: str, repo: str, artifact_id: int, output_path: Path):
        """GitHub Actions artifact'ını indir"""
        url = f"{self.api_url}/repos/{owner}/{repo}/actions/artifacts/{artifact_id}/zip"
        headers = self.headers.copy()
        headers['Accept'] = 'application/vnd.github+json'
        
        response = requests.get(url, headers=headers, stream=True)
        if response.status_code == 200:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            return True
        return False
    
    def extract_bin_files(self, archive_path: Path, output_dir: Path):
        """Archive'dan .bin dosyalarını çıkar"""
        output_dir.mkdir(parents=True, exist_ok=True)
        extracted = []
        
        try:
            with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                for member in zip_ref.namelist():
                    if member.endswith('.bin') and 'firmware' in member.lower():
                        zip_ref.extract(member, output_dir)
                        extracted.append(output_dir / member)
        except Exception as e:
            print(f"  Archive extraction error: {e}")
        
        return extracted
    
    def collect_firmware(self, output_dir: Path, max_repos: int = 20):
        """ESP32 firmware'lerini topla"""
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        print(f"🔍 Searching for ESP32 repositories on GitHub...")
        repos = self.search_repos("esp32 firmware", max_repos)
        print(f"Found {len(repos)} repositories\n")
        
        downloaded = 0
        
        for i, repo in enumerate(repos, 1):
            repo_name = repo.get('full_name', 'unknown')
            owner, repo_name_only = repo_name.split('/', 1)
            
            print(f"[{i}/{len(repos)}] Processing: {repo_name}")
            
            # 1. Check latest release
            try:
                latest_release = self.get_latest_release(owner, repo_name_only)
                if latest_release:
                    assets = latest_release.get('assets', [])
                    for asset in assets:
                        name = asset.get('name', '')
                        if '.bin' in name.lower() or 'firmware' in name.lower():
                            output_path = output_dir / f"{repo_name.replace('/', '_')}_{name}"
                            asset_url = asset.get('url', '')
                            if self.download_asset(asset_url, output_path):
                                print(f"  Downloaded: {name}")
                                downloaded += 1
            except Exception as e:
                print(f"  Release error: {e}")
            
            # 2. Check all releases
            try:
                releases = self.get_releases(owner, repo_name_only)
                for release in releases[:3]:  # Son 3 release
                    tag = release.get('tag_name', '')
                    assets = release.get('assets', [])
                    for asset in assets:
                        name = asset.get('name', '')
                        if '.bin' in name.lower():
                            output_path = output_dir / f"{repo_name.replace('/', '_')}_{tag}_{name}"
                            if not output_path.exists():
                                asset_url = asset.get('url', '')
                                if self.download_asset(asset_url, output_path):
                                    print(f"  Downloaded: {tag}/{name}")
                                    downloaded += 1
            except Exception as e:
                print(f"  Releases error: {e}")
            
            # 3. Check workflow artifacts (if token provided)
            if self.token:
                try:
                    artifacts = self.get_workflow_artifacts(owner, repo_name_only)
                    for artifact in artifacts[:5]:  # Son 5 artifact
                        name = artifact.get('name', '')
                        if 'firmware' in name.lower() or 'build' in name.lower():
                            artifact_id = artifact.get('id')
                            output_path = output_dir / f"{repo_name.replace('/', '_')}_artifact_{artifact_id}.zip"
                            if self.download_artifact(owner, repo_name_only, artifact_id, output_path):
                                print(f"  Downloaded artifact: {name}")
                                bin_files = self.extract_bin_files(output_path, output_dir / "extracted")
                                if bin_files:
                                    print(f"  Extracted {len(bin_files)} .bin files")
                                    downloaded += len(bin_files)
                except Exception as e:
                    pass  # Artifacts require token
            
            time.sleep(0.5)  # Rate limiting
        
        print(f"\nTotal downloaded: {downloaded} firmware files")
        return downloaded


def main():
    parser = argparse.ArgumentParser(description="GitHub'dan ESP32 firmware topla")
    parser.add_argument(
        "-o", "--output",
        type=str,
        default="./firmware_samples/github",
        help="Output directory"
    )
    parser.add_argument(
        "-t", "--token",
        type=str,
        help="GitHub personal access token (optional but recommended)"
    )
    parser.add_argument(
        "-n", "--max-repos",
        type=int,
        default=20,
        help="Maximum repositories to search"
    )
    
    args = parser.parse_args()
    
    if not args.token:
        print("Warning: No token provided. API rate limits: 60 requests/hour")
        print("   Get token from: https://github.com/settings/tokens")
        print("   Token ile: 5000 requests/hour\n")
    
    collector = GitHubFirmwareCollector(args.token)
    collector.collect_firmware(Path(args.output), args.max_repos)


if __name__ == "__main__":
    main()

