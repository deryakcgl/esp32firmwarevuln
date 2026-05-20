#!/usr/bin/env python3
import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from esp32_firmguard.services.training_service import TrainingService
from esp32_firmguard.services.validate import suggest_source_root, validate_source_root
from esp32_firmguard.utils import load_config, setup_logging


def _source_roots_map(elves: list[Path]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for elf in elves:
        root = suggest_source_root(elf)
        if not root:
            raise ValueError(
                f"No source root for {elf}. Add source_root.txt or a source/ folder next to the ELF."
            )
        root = validate_source_root(root)
        for key in (str(elf.resolve()), elf.name, elf.stem, elf.parent.name):
            out[key] = [root]
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Build dataset or train from debug ELFs")
    ap.add_argument("firmware_dir", help="Directory tree containing firmware.elf files")
    ap.add_argument("-o", "--output", default="./output/datasets/training_data")
    ap.add_argument("-c", "--config", default="configs/config.yaml")
    ap.add_argument("--train", action="store_true", help="Train model after dataset build")
    ap.add_argument("-m", "--model-name", default="user_model.pkl")
    ap.add_argument("--cwe-excel", required=True, help="CWE catalog or per-function labels (.xlsx)")
    args = ap.parse_args()

    setup_logging("INFO")
    config = load_config(args.config)
    service = TrainingService(config)

    fw_dir = Path(args.firmware_dir)
    elves = sorted({p.resolve() for p in fw_dir.rglob("*.elf")})
    if not elves:
        print(f"No .elf files under {fw_dir}. Use debug builds (-g).")
        return 1

    roots_map = _source_roots_map(elves)
    print(f"Found {len(elves)} ELF file(s)")
    if args.train:
        result = service.train(
            elves,
            model_name=args.model_name,
            dataset_name=Path(args.output).name,
            cwe_excel_path=args.cwe_excel,
            source_roots_map=roots_map,
        )
        print(f"Model: {result.model_path}")
        print(f"Metrics: {result.metrics}")
    else:
        fm, labels, _ = service.build_dataset_from_elfs(
            elves, source_roots_map=roots_map, cwe_excel_path=args.cwe_excel
        )
        out = Path(args.output)
        service.dataset_builder.save_dataset(fm, labels, out)
        print(f"Dataset saved to {out} ({fm.shape[0]} functions)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
