from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from collections import Counter
from pathlib import Path

from esp32_firmguard.reporting import default_report_path, write_markdown_report
from esp32_firmguard.services.analysis_service import AnalysisService
from esp32_firmguard.services.findings import prediction_to_finding
from esp32_firmguard.services.training_service import TrainingService
from esp32_firmguard.utils import ensure_dir, load_config, setup_logging

logger = logging.getLogger(__name__)


def analyze_firmware(args):
    config = load_config(args.config)
    log_level = "DEBUG" if getattr(args, "verbose", False) else (
        args.log_level or config.get("logging", {}).get("level", "INFO")
    )
    setup_logging(log_level)

    svc = AnalysisService(config)
    if getattr(args, "threshold", None) is not None:
        svc.pipeline.predictor.threshold = float(args.threshold)

    wall0 = time.perf_counter()
    result = svc.analyze(
        args.elf,
        model_path=getattr(args, "model", None),
        source_roots=[args.source_root],
        cwe_excel_path=args.cwe_excel,
    )
    cli_wall = round(time.perf_counter() - wall0, 3)

    predictions_data = [f.to_dict() for f in result.findings]
    predictions_data.sort(key=lambda x: x.get("score", 0), reverse=True)
    top_by_score = predictions_data[:25]
    vuln_count = sum(1 for f in result.findings if f.is_vulnerable)
    cwe_counter: Counter[str] = Counter()
    for row in predictions_data:
        for c in row.get("cwe") or []:
            cwe_counter[c] += 1

    elf_path = Path(args.elf).resolve()
    run_info = {
        "elf_path": str(elf_path),
        "source_root": str(Path(args.source_root).resolve()),
        "cwe_excel": str(Path(args.cwe_excel).resolve()) if args.cwe_excel else None,
        "model_threshold": float(svc.pipeline.predictor.threshold),
        "cli_wall_seconds": cli_wall,
        "static_seconds": result.timings.get("static_seconds"),
        "functions_with_source": result.functions_with_source,
        "vulnerable_count": vuln_count,
        "top_cwe_in_predictions": dict(cwe_counter.most_common(15)),
        "output_json": str(Path(args.output).resolve()) if args.output else None,
        "output_report": None,
    }

    if args.output:
        output_path = Path(args.output)
        ensure_dir(output_path.parent)
        out_doc = {
            "run_info": run_info,
            "predictions_top_by_score": top_by_score,
            "predictions": predictions_data,
        }
        with open(output_path, "w") as f:
            json.dump(out_doc, f, indent=2)
        logger.info("Results saved to %s", output_path)

    report_path: Path | None = None
    if not getattr(args, "no_report", False):
        if getattr(args, "report", None):
            report_path = Path(args.report)
        elif args.output:
            report_path = default_report_path(Path(args.output))

    if report_path is not None:
        report_path = report_path.resolve()
        run_info["output_report"] = str(report_path)
        preds = [prediction_to_finding(f, {}) for f in result.findings]
        write_markdown_report(
            report_path,
            run_info=run_info,
            functions={},
            predictions=preds,
            cwe_labels={},
            feature_matrix=None,
            threshold=float(svc.pipeline.predictor.threshold),
        )
        if args.output:
            out_doc["run_info"]["output_report"] = str(report_path)
            with open(Path(args.output), "w") as f:
                json.dump(out_doc, f, indent=2)

    print("\n" + "=" * 72)
    print("ESP32 FirmGuard — Analysis")
    print("=" * 72)
    print(f"ELF           : {elf_path}")
    print(f"Source root   : {args.source_root}")
    print(f"CWE Excel     : {args.cwe_excel or config.get('labeling', {}).get('excel_path')}")
    print(f"Wall time (s) : {cli_wall}")
    print(f"Mapped funcs  : {result.functions_with_source}")
    print(f"Vulnerable    : {vuln_count}")
    for row in top_by_score[:8]:
        cw = ", ".join(row.get("cwe") or []) or "-"
        print(f"  {row.get('name')}: score={row.get('score', 0):.4f} CWE=[{cw}]")
    if args.output:
        print(f"JSON: {Path(args.output).resolve()}")
    if report_path:
        print(f"Report: {report_path}")
    print("=" * 72)


def train_firmware(args):
    config = load_config(args.config)
    setup_logging(args.log_level or "INFO")
    elves = [str(Path(p).resolve()) for p in args.elf]
    svc = TrainingService(config)
    result = svc.train(
        elves,
        source_roots_map={str(Path(e).resolve()): [args.source_root] for e in elves},
        cwe_excel_path=args.cwe_excel,
        model_name=args.model_name or "user_model.pkl",
        validation_split=args.validation_split,
        ollama_model=getattr(args, "ollama_model", None),
    )
    print("\n" + "=" * 60)
    print("Training complete")
    print("=" * 60)
    print(f"Model: {result.model_path}")
    print(f"Functions: {result.function_count}")
    print(f"Firmwares: {result.firmware_count}")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(description="ESP32 FirmGuard — ELF + source + Excel/Ollama CWE")
    subparsers = parser.add_subparsers(dest="command")

    analyze_parser = subparsers.add_parser("analyze", help="Analyze a debug ELF")
    analyze_parser.add_argument("--elf", required=True, help="Path to debug ELF (-g)")
    analyze_parser.add_argument("--source-root", required=True, help="Project source folder")
    analyze_parser.add_argument(
        "--cwe-excel",
        required=True,
        help="CWE catalog or per-function labels Excel",
    )
    analyze_parser.add_argument("--model", type=str, default=None, help="Trained .pkl model")
    analyze_parser.add_argument("-c", "--config", default="configs/config.yaml")
    analyze_parser.add_argument("-o", "--output", type=str, help="Output JSON")
    analyze_parser.add_argument("--threshold", type=float, default=None)
    analyze_parser.add_argument("--report", type=str, default=None)
    analyze_parser.add_argument("--no-report", action="store_true")
    analyze_parser.add_argument("-v", "--verbose", action="store_true")
    analyze_parser.add_argument("--log-level", default="INFO")

    train_parser = subparsers.add_parser("train", help="Train from debug ELFs")
    train_parser.add_argument("--elf", action="append", required=True, help="Debug ELF (repeatable)")
    train_parser.add_argument("--source-root", required=True, help="Shared source root for all ELFs")
    train_parser.add_argument("--cwe-excel", required=True)
    train_parser.add_argument("-c", "--config", default="configs/config.yaml")
    train_parser.add_argument("-m", "--model-name", default="user_model.pkl")
    train_parser.add_argument("--validation-split", type=float, default=0.2)
    train_parser.add_argument("--ollama-model", type=str, default=None)
    train_parser.add_argument("--log-level", default="INFO")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    try:
        if args.command == "analyze":
            analyze_firmware(args)
        elif args.command == "train":
            train_firmware(args)
        else:
            parser.print_help()
            sys.exit(1)
    except Exception as e:
        logger.error("Error: %s", e, exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
