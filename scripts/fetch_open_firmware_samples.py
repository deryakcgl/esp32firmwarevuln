#!/usr/bin/env python3
"""Download open ESP32-related .bin assets from public GitHub releases (no token required)."""

from __future__ import annotations

import argparse
import json
import ssl
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional


def _get_json(url: str, timeout: float = 30.0) -> Optional[Dict[str, Any]]:
    ctx = ssl.create_default_context()
    req = urllib.request.Request(
        url,
        headers={"Accept": "application/vnd.github+json", "User-Agent": "esp32-firmguard-fetch"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return json.loads(resp.read().decode())
    except (urllib.error.URLError, json.JSONDecodeError, OSError) as e:
        print(f"  API error for {url}: {e}", file=sys.stderr)
        return None


def _download(url: str, dest: Path, timeout: float = 120.0) -> bool:
    dest.parent.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(url, headers={"User-Agent": "esp32-firmguard-fetch"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read()
        dest.write_bytes(data)
        return len(data) > 0
    except (urllib.error.URLError, OSError) as e:
        print(f"  Download failed {url}: {e}", file=sys.stderr)
        return False


DEFAULT_RELEASES = [
    "https://api.github.com/repos/arendst/Tasmota/releases/latest",
    "https://api.github.com/repos/esphome/esphome/releases/latest",
    "https://api.github.com/repos/micropython/micropython/releases/latest",
]


def collect_bins(output_dir: Path, release_urls: List[str], max_per_release: int = 6) -> int:
    output_dir.mkdir(parents=True, exist_ok=True)
    saved = 0
    for api_url in release_urls:
        print(f"Fetching {api_url} ...")
        rel = _get_json(api_url)
        if not rel:
            continue
        tag = rel.get("tag_name", "unknown")
        repo = api_url.split("/repos/")[1].split("/releases")[0].replace("/", "_")
        assets: List[Dict[str, Any]] = rel.get("assets") or []
        bins = [
            a
            for a in assets
            if str(a.get("name", "")).lower().endswith(".bin")
            and a.get("browser_download_url")
        ]
        # Prefer names that look like firmware
        bins.sort(
            key=lambda a: (
                0
                if any(
                    k in a.get("name", "").lower()
                    for k in ("firmware", "esp32", "tasmota", "factory", "flash")
                )
                else 1,
                a.get("name", ""),
            )
        )
        for a in bins[:max_per_release]:
            name = a["name"]
            url = a["browser_download_url"]
            dest = output_dir / f"{repo}_{tag}_{name}".replace("/", "_")
            if dest.exists():
                print(f"  skip (exists): {dest.name}")
                continue
            print(f"  downloading {name} ...")
            if _download(url, dest):
                print(f"  saved {dest} ({dest.stat().st_size} bytes)")
                saved += 1
            time.sleep(0.4)
        time.sleep(0.6)
    return saved


def main() -> None:
    parser = argparse.ArgumentParser(description="Download public .bin firmware samples from GitHub")
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default="./firmware_samples/github_open",
        help="Directory to store .bin files",
    )
    parser.add_argument(
        "-n",
        "--max-per-release",
        type=int,
        default=6,
        help="Max .bin assets to take from each release",
    )
    parser.add_argument(
        "--extra-release-api",
        action="append",
        default=[],
        help="Additional GitHub API URL, e.g. https://api.github.com/repos/owner/repo/releases/latest",
    )
    args = parser.parse_args()
    urls = list(DEFAULT_RELEASES)
    urls.extend(args.extra_release_api)
    n = collect_bins(Path(args.output), urls, max_per_release=args.max_per_release)
    print(f"\nDone. New files downloaded: {n} -> {args.output}")


if __name__ == "__main__":
    main()
