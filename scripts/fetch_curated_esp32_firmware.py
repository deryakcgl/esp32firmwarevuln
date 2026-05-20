#!/usr/bin/env python3
"""
Download and/or build curated ESP32 firmware for FirmGuard training & test.

Each sample includes:
  - firmware.elf (+ .bin) with DWARF debug info (Xtensa ESP32)
  - source/ tree matched to DWARF paths where possible

Pairs (researched on GitHub):
  - Wokwi HTTP: clone wokwi/esp32-http-server + PlatformIO debug build (ELF paths match src/)
  - ESP-IDF examples: Docker build + copy example sources (main/*.c resolves via source/)
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from esp32_firmguard.ingestion.dwarf_mapper import _DwarfLineIndex, elf_has_debug_info
from esp32_firmguard.ingestion.elf_extractor import _elf_machine, is_elf
from esp32_firmguard.ingestion.source_reader import resolve_source_path

_EM_XTENSA = 94
RAW_BASE = "https://raw.githubusercontent.com"
IDF_IMAGE = "espressif/idf:v5.4.1"
PIO_IMAGE = "platformio/platformio-core:latest"

WOKWI_HTTP_SRC = "https://github.com/wokwi/esp32-http-server.git"
WOKWI_HTTP_BIN_RAW = f"{RAW_BASE}/wokwi/esp32-http-server-binaries/main"


@dataclass
class FirmwareSpec:
    slug: str
    role: str  # train | test
    description: str
    source_repo: str
    source_clone: Optional[str] = None  # git URL for application source
    idf_example: Optional[str] = None  # path under $IDF_PATH


WOKWI_HTTP = FirmwareSpec(
    slug="wokwi_http_server",
    role="test",
    description="Wokwi HTTP server — PlatformIO build + matching source (held-out test)",
    source_repo="wokwi/esp32-http-server",
    source_clone=WOKWI_HTTP_SRC,
)

IDF_EXAMPLES: List[FirmwareSpec] = [
    FirmwareSpec(
        slug="idf_hello_world",
        role="train",
        description="ESP-IDF hello_world — minimal baseline",
        source_repo="espressif/esp-idf@v5.4.1",
        idf_example="examples/get-started/hello_world",
    ),
    FirmwareSpec(
        slug="idf_wifi_station",
        role="train",
        description="ESP-IDF WiFi station",
        source_repo="espressif/esp-idf@v5.4.1",
        idf_example="examples/wifi/getting_started/station",
    ),
    FirmwareSpec(
        slug="idf_wifi_softap",
        role="train",
        description="ESP-IDF WiFi SoftAP",
        source_repo="espressif/esp-idf@v5.4.1",
        idf_example="examples/wifi/getting_started/softAP",
    ),
]


def _download(url: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f"  GET {url}")
    r = requests.get(url, timeout=600, stream=True)
    r.raise_for_status()
    with open(dest, "wb") as f:
        for chunk in r.iter_content(chunk_size=1 << 20):
            if chunk:
                f.write(chunk)


def _validate_elf(elf: Path) -> None:
    if not is_elf(elf):
        raise ValueError(f"Not an ELF: {elf}")
    if _elf_machine(elf) != _EM_XTENSA:
        raise ValueError(f"Not Xtensa ESP32 ELF (e_machine): {elf}")
    if not elf_has_debug_info(elf):
        raise ValueError(f"No DWARF debug sections: {elf}")


def _git_shallow_clone(url: str, dest: Path) -> None:
    if dest.exists():
        shutil.rmtree(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f"  git clone --depth 1 {url} -> {dest}")
    subprocess.run(
        ["git", "clone", "--depth", "1", url, str(dest)],
        check=True,
        cwd=str(ROOT),
    )


def _write_source_root_marker(sample_dir: Path, source_rel: str = "source") -> Path:
    """Write source_root path for desktop / scripts (relative to sample dir)."""
    root = sample_dir / source_rel
    root.mkdir(parents=True, exist_ok=True)
    marker = sample_dir / "source_root.txt"
    marker.write_text(
        f"{source_rel}\n# Set FirmGuard desktop 'Source root' to:\n"
        f"# {root.resolve()}\n",
        encoding="utf-8",
    )
    return root.resolve()


def _count_resolved_main_sources(elf: Path, source_root: Path) -> int:
    """How many DWARF paths resolve under source_root (sanity check)."""
    if not elf.is_file() or not source_root.is_dir():
        return 0
    idx = _DwarfLineIndex.for_elf(elf)
    paths = {idx.lookup(a)[0] for a in idx._addrs[:: max(1, len(idx._addrs) // 400)] if idx.lookup(a)[0]}
    ok = sum(1 for p in paths if resolve_source_path(p, [source_root]))
    return ok


def fetch_wokwi_http_prebuilt(dest_dir: Path) -> None:
    """Fallback: prebuilt ELF (DWARF paths may not match local source)."""
    _download(f"{WOKWI_HTTP_BIN_RAW}/firmware.bin", dest_dir / "firmware.bin")
    _download(f"{WOKWI_HTTP_BIN_RAW}/firmware.elf", dest_dir / "firmware.elf")
    _validate_elf(dest_dir / "firmware.elf")


def fetch_wokwi_http_with_source(dest_dir: Path) -> Path:
    """
    Clone app source and build debug ELF with PlatformIO so paths match src/.
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    work = dest_dir / "_build"
    if work.exists():
        shutil.rmtree(work)
    _git_shallow_clone(WOKWI_HTTP_SRC, work)

    print("  PlatformIO debug build (first run downloads toolchain)…")
    inner = """
set -e
cd /project
pio run -e esp32 --project-option="build_flags=-g -Og"
test -f .pio/build/esp32/firmware.elf
cp .pio/build/esp32/firmware.elf /out/firmware.elf
cp .pio/build/esp32/firmware.bin /out/firmware.bin
"""
    subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{work.resolve()}:/project",
            "-v",
            f"{dest_dir.resolve()}:/out",
            PIO_IMAGE,
            "bash",
            "-lc",
            inner,
        ],
        check=True,
        cwd=str(ROOT),
    )
    _validate_elf(dest_dir / "firmware.elf")

    src_dest = dest_dir / "source"
    if src_dest.exists():
        shutil.rmtree(src_dest)
    shutil.copytree(work, src_dest, ignore=shutil.ignore_patterns(".pio", ".git"))
    shutil.rmtree(work, ignore_errors=True)

    root = _write_source_root_marker(dest_dir)
    resolved = _count_resolved_main_sources(dest_dir / "firmware.elf", root)
    print(f"  OK wokwi ({dest_dir / 'firmware.elf'.stat().st_size // 1024} KiB ELF, "
          f"source resolve check: {resolved} DWARF paths)")
    return root


def _docker_idf_build(example_rel: str, artifact_dir: Path, *, with_source: bool) -> None:
    artifact_dir.mkdir(parents=True, exist_ok=True)
    src_copy = ""
    if with_source:
        src_copy = """
mkdir -p /out/source
for item in main CMakeLists.txt sdkconfig sdkconfig.defaults README.md; do
  if [ -e "$item" ]; then cp -a "$item" /out/source/; fi
done
"""

    inner = f"""
set -e
export IDF_CCACHE_ENABLE=0
cd "$IDF_PATH/{example_rel}"
idf.py set-target esp32
idf.py build
ELF=$(find build -maxdepth 1 -type f -name '*.elf' | head -1)
BIN=$(find build -maxdepth 1 -type f -name '*.bin' ! -name 'bootloader*.bin' | head -1)
test -n "$ELF" || {{ echo "No application ELF in build/"; exit 1; }}
cp "$ELF" /out/firmware.elf
if [ -n "$BIN" ]; then cp "$BIN" /out/firmware.bin; fi
{src_copy}
ls -la /out/
"""
    subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{artifact_dir.resolve()}:/out",
            IDF_IMAGE,
            "bash",
            "-lc",
            inner,
        ],
        check=True,
        cwd=str(ROOT),
    )
    _validate_elf(artifact_dir / "firmware.elf")
    if with_source:
        root = _write_source_root_marker(artifact_dir)
        n = _count_resolved_main_sources(artifact_dir / "firmware.elf", root)
        print(f"  OK {artifact_dir.name} ({artifact_dir / 'firmware.elf'.stat().st_size // 1024} KiB, "
              f"source paths resolved: {n})")
    else:
        print(f"  OK {artifact_dir.name}")


def docker_available() -> bool:
    try:
        subprocess.run(["docker", "info"], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def pull_images(*, idf: bool, pio: bool) -> None:
    if idf:
        print(f"Pulling {IDF_IMAGE}…")
        subprocess.run(["docker", "pull", IDF_IMAGE], check=True)
    if pio:
        print(f"Pulling {PIO_IMAGE}…")
        subprocess.run(["docker", "pull", PIO_IMAGE], check=True)


def write_manifest(out_root: Path, entries: List[dict]) -> None:
    doc = {
        "format": "debug ELF (Xtensa ESP32) + source/ per sample",
        "train_test_split": "Use train/ for training, test/ for evaluation only",
        "desktop_source_root": "Open source_root.txt in each sample folder",
        "samples": entries,
    }
    with open(out_root / "manifest.json", "w") as f:
        json.dump(doc, f, indent=2)


def main() -> int:
    import argparse

    ap = argparse.ArgumentParser(description="Fetch curated ESP32 ELF + source corpus")
    ap.add_argument("-o", "--output", type=Path, default=ROOT / "firmware_samples")
    ap.add_argument("--skip-docker", action="store_true", help="Only fetch Wokwi (prebuilt ELF)")
    ap.add_argument("--skip-pull", action="store_true", help="Do not docker pull images")
    ap.add_argument(
        "--no-source",
        action="store_true",
        help="Skip cloning/copying source trees (ELF only)",
    )
    ap.add_argument(
        "--wokwi-prebuilt",
        action="store_true",
        help="Use published Wokwi ELF instead of PlatformIO rebuild",
    )
    args = ap.parse_args()

    with_source = not args.no_source
    out_root: Path = args.output.resolve()
    if out_root.exists():
        print(f"Removing old samples under {out_root} …")
        shutil.rmtree(out_root)
    (out_root / "train").mkdir(parents=True)
    (out_root / "test").mkdir(parents=True)

    manifest_entries: List[dict] = []

    # --- Test: Wokwi HTTP ---
    print("\n[1/2] Wokwi HTTP server")
    test_dir = out_root / "test" / WOKWI_HTTP.slug
    source_root_abs: Optional[str] = None
    if with_source and not args.skip_docker and not args.wokwi_prebuilt:
        if not docker_available():
            print("  Docker missing — falling back to prebuilt ELF + source clone only")
            test_dir.mkdir(parents=True)
            fetch_wokwi_http_prebuilt(test_dir)
            _git_shallow_clone(WOKWI_HTTP_SRC, test_dir / "source")
            source_root_abs = str(_write_source_root_marker(test_dir))
        else:
            if not args.skip_pull:
                pull_images(idf=False, pio=True)
            source_root_abs = str(fetch_wokwi_http_with_source(test_dir))
    elif with_source:
        test_dir.mkdir(parents=True)
        fetch_wokwi_http_prebuilt(test_dir)
        if shutil.which("git"):
            _git_shallow_clone(WOKWI_HTTP_SRC, test_dir / "source")
            source_root_abs = str(_write_source_root_marker(test_dir))
    else:
        test_dir.mkdir(parents=True)
        fetch_wokwi_http_prebuilt(test_dir)

    manifest_entries.append(
        {
            "slug": WOKWI_HTTP.slug,
            "role": "test",
            "description": WOKWI_HTTP.description,
            "source_repo": WOKWI_HTTP.source_repo,
            "elf": str(test_dir / "firmware.elf"),
            "source_root": source_root_abs,
            "has_bundled_source": with_source and (test_dir / "source").is_dir(),
        }
    )

    # --- Train: ESP-IDF ---
    if not args.skip_docker:
        if not docker_available():
            print("ERROR: Docker required for ESP-IDF training firmware.", file=sys.stderr)
            return 1
        if not args.skip_pull:
            pull_images(idf=True, pio=False)
        print("\n[2/2] ESP-IDF examples (ELF + example source/)")
        for spec in IDF_EXAMPLES:
            dest = out_root / "train" / spec.slug
            _docker_idf_build(spec.idf_example or "", dest, with_source=with_source)
            sr = None
            if with_source and (dest / "source").is_dir():
                sr = str((dest / "source").resolve())
                _write_source_root_marker(dest)
            manifest_entries.append(
                {
                    "slug": spec.slug,
                    "role": "train",
                    "description": spec.description,
                    "source_repo": spec.source_repo,
                    "idf_example": spec.idf_example,
                    "elf": str(dest / "firmware.elf"),
                    "source_root": sr,
                    "has_bundled_source": bool(sr),
                }
            )
    else:
        print("\n[2/2] Skipped ESP-IDF (--skip-docker)")

    write_manifest(out_root, manifest_entries)
    print(f"\nDone. Manifest: {out_root / 'manifest.json'}")
    with_src = sum(1 for e in manifest_entries if e.get("has_bundled_source"))
    print(f"Samples with bundled source: {with_src}/{len(manifest_entries)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
