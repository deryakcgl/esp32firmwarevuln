#!/usr/bin/env python3
"""
README-style metrics vs current dataset.

1) Per-firmware: same as scripts/comprehensive_evaluation.py — each .bin evaluated,
   ground truth = CWE-derived labels for that image, then mean ± std across firmwares
   (matches README presentation: Precision/Recall/F1/Accuracy ± spread).

2) Function-level 5-fold stratified CV on saved dataset: train XGBoost only on train fold,
   no leakage — stricter generalization estimate on the same proxy labels.
"""

from __future__ import annotations

import argparse
import copy
import json
import shutil
import sys
import tempfile
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).parent.parent))

from esp32_firmguard.utils import load_config, setup_logging
from esp32_firmguard.pipeline import FirmwareSecurityPipeline
from esp32_firmguard.metrics.evaluation import EvaluationMetrics


def collect_firmware_bins(root: Path) -> list[Path]:
    files: list[Path] = []
    for pattern in ("*.bin", "*.elf", "*.img"):
        files.extend(root.glob(pattern))
        files.extend(root.rglob(pattern))
    return sorted({p.resolve() for p in files})


def config_with_model_override(base_config: dict, model_filename: str | None) -> dict:
    """Point model_output at a temp dir containing vulnerability_model.pkl copy."""
    if not model_filename:
        return base_config
    cfg = copy.deepcopy(base_config)
    src = Path(cfg.get("paths", {}).get("model_output", "./output/models")).resolve() / model_filename
    if not src.is_file():
        raise FileNotFoundError(f"Model file not found: {src}")
    tmp = Path(tempfile.mkdtemp(prefix="firmguard_eval_model_"))
    dst = tmp / "vulnerability_model.pkl"
    shutil.copy2(src, dst)
    cfg.setdefault("paths", {})["model_output"] = str(tmp)
    return cfg


def per_firmware_readme_style(
    firmware_dir: Path, config: dict
) -> tuple[list[dict], dict]:
    """Mirror comprehensive_evaluation: one metric dict per firmware file."""
    pipeline = FirmwareSecurityPipeline(config)
    metrics_engine = EvaluationMetrics(config)
    bins = collect_firmware_bins(firmware_dir)
    rows = []
    for fw_path in bins:
        try:
            fw, _fm, predictions, cwe_labels = pipeline.run_static_stage(
                str(fw_path), source="eval"
            )
            gt = {
                fid: (1 if len(cwes) > 0 else 0)
                for fid, cwes in cwe_labels.items()
            }
            m = metrics_engine.compute_all(
                ground_truth=gt,
                predictions=predictions,
                fuzz_results=None,
                hw_results=None,
            )
            rows.append(
                {
                    "firmware": fw_path.name,
                    "n_functions": len(predictions),
                    "precision": m["precision"],
                    "recall": m["recall"],
                    "f1_score": m["f1_score"],
                    "accuracy": m["accuracy"],
                }
            )
        except Exception as e:
            rows.append({"firmware": fw_path.name, "error": str(e)})

    ok = [r for r in rows if "error" not in r]
    summary = {}
    if ok:
        for k in ("precision", "recall", "f1_score", "accuracy"):
            vals = [r[k] for r in ok]
            summary[k] = {
                "mean": float(np.mean(vals)),
                "std": float(np.std(vals)),
                "min": float(np.min(vals)),
                "max": float(np.max(vals)),
            }
    summary["firmware_count"] = len(ok)
    summary["total_functions"] = int(sum(r["n_functions"] for r in ok))
    return rows, summary


def stratified_kfold_on_dataset(
    dataset_dir: Path,
    config: dict,
    k: int = 5,
    random_state: int = 42,
    max_samples: int | None = None,
) -> dict:
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
    from sklearn.model_selection import StratifiedKFold, train_test_split
    import xgboost as xgb

    fm = pd.read_csv(dataset_dir / "features.csv", index_col=0)
    labels = pd.read_csv(dataset_dir / "labels.csv", index_col=0).iloc[:, 0]
    y = labels.reindex(fm.index).fillna(0).astype(int)

    cwe_cols = [
        c
        for c in fm.columns
        if c.startswith("CWE-")
        or c in ("has_cwe", "num_cwe_labels")
        or c.startswith("cwe_")
    ]
    X = fm.drop(columns=cwe_cols, errors="ignore")

    cv_note = "Trained only on train fold each split; same hyperparameters as config model block."
    if max_samples is not None and len(X) > max_samples:
        X, _, y, _ = train_test_split(
            X,
            y,
            train_size=max_samples,
            stratify=y,
            random_state=random_state,
        )
        cv_note += f" Stratified subsample max_samples={max_samples} (full CSV had more rows)."

    skf = StratifiedKFold(n_splits=k, shuffle=True, random_state=random_state)
    mc = config.get("model", {})
    precs, recs, f1s, accs = [], [], [], []

    for train_idx, test_idx in skf.split(X, y):
        X_tr, X_te = X.iloc[train_idx], X.iloc[test_idx]
        y_tr, y_te = y.iloc[train_idx], y.iloc[test_idx]
        n_pos = int((y_tr == 1).sum())
        n_neg = int((y_tr == 0).sum())
        scale = n_neg / n_pos if n_pos > 0 else 1.0
        fn_mult = float(mc.get("fn_cost_multiplier", 5.0))
        sw = np.ones(len(y_tr))
        sw[y_tr.values == 1] = fn_mult
        clf = xgb.XGBClassifier(
            n_estimators=int(mc.get("n_estimators", 200)),
            max_depth=int(mc.get("max_depth", 8)),
            learning_rate=float(mc.get("learning_rate", 0.05)),
            scale_pos_weight=scale,
            subsample=float(mc.get("subsample", 0.8)),
            colsample_bytree=float(mc.get("colsample_bytree", 0.8)),
            min_child_weight=int(mc.get("min_child_weight", 1)),
            gamma=float(mc.get("gamma", 0.1)),
            reg_alpha=float(mc.get("reg_alpha", 0.1)),
            reg_lambda=float(mc.get("reg_lambda", 1.0)),
            objective="binary:logistic",
            eval_metric="logloss",
            random_state=random_state,
        )
        clf.fit(X_tr, y_tr, sample_weight=sw)
        thr = float(mc.get("threshold", 0.5))
        proba = clf.predict_proba(X_te)[:, 1]
        pred = (proba >= thr).astype(int)
        precs.append(precision_score(y_te, pred, zero_division=0))
        recs.append(recall_score(y_te, pred, zero_division=0))
        f1s.append(f1_score(y_te, pred, zero_division=0))
        accs.append(accuracy_score(y_te, pred))

    def stat(name: str, arr: list) -> dict:
        a = np.array(arr, dtype=float)
        return {"mean": float(a.mean()), "std": float(a.std()), "folds": arr}

    return {
        "k_folds": k,
        "precision": stat("precision", precs),
        "recall": stat("recall", recs),
        "f1_score": stat("f1_score", f1s),
        "accuracy": stat("accuracy", accs),
        "n_samples": len(X),
        "note": cv_note,
    }


def main() -> None:
    p = argparse.ArgumentParser(description="README-aligned evaluation + stratified CV")
    p.add_argument(
        "--firmware-dir",
        type=str,
        default="firmware_samples",
        help="Root directory to search for .bin files",
    )
    p.add_argument(
        "--dataset-dir",
        type=str,
        default="output/datasets/training_data",
        help="Dataset from prepare_training_data_from_firmware.py",
    )
    p.add_argument(
        "-c", "--config", type=str, default="configs/config.yaml"
    )
    p.add_argument(
        "-o",
        "--output",
        type=str,
        default="output/evaluation/readme_aligned_comparison.json",
    )
    p.add_argument("--k-folds", type=int, default=5)
    p.add_argument(
        "--model-file",
        type=str,
        default=None,
        help="Filename in model_output dir (e.g. vulnerability_model_full.pkl) copied to eval temp as vulnerability_model.pkl",
    )
    p.add_argument(
        "--max-cv-samples",
        type=int,
        default=100_000,
        help="Stratified subsample size for K-fold CV when CSV is larger (0 = use all rows, slow)",
    )
    args = p.parse_args()

    base_config = load_config(args.config)
    config = config_with_model_override(base_config, args.model_file)
    setup_logging("WARNING")

    fw_dir = Path(args.firmware_dir)
    ds_dir = Path(args.dataset_dir)
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    readme_baseline = {
        "precision_mean": 0.435,
        "precision_std": 0.099,
        "recall_mean": 0.255,
        "recall_std": 0.055,
        "f1_mean": 0.320,
        "f1_std": 0.067,
        "accuracy_mean": 0.608,
        "accuracy_std": 0.041,
        "dataset_functions": 101_966,
        "dataset_firmware": 1_747,
        "source": "README.md Performance section",
    }

    per_fw_detail, per_fw_summary = per_firmware_readme_style(fw_dir, config)

    cv_summary = None
    if (ds_dir / "features.csv").exists() and (ds_dir / "labels.csv").exists():
        max_cv = None if args.max_cv_samples == 0 else args.max_cv_samples
        cv_summary = stratified_kfold_on_dataset(
            ds_dir, config, k=args.k_folds, max_samples=max_cv
        )

    report = {
        "readme_baseline": readme_baseline,
        "eval_model_file": args.model_file,
        "max_cv_samples": args.max_cv_samples,
        "current_per_firmware_aggregate": per_fw_summary,
        "current_per_firmware_detail": per_fw_detail,
        "current_stratified_kfold_cv": cv_summary,
        "disclaimer": (
            "README baseline used ~102k functions / 1747 firmware; full corpus here may differ in extraction counts. "
            "Ground truth is CWE-pattern proxy labels. "
            "Per-firmware metrics use the loaded model; K-fold retrains each fold (subsampled if --max-cv-samples)."
        ),
    }

    with open(out_path, "w") as f:
        json.dump(report, f, indent=2)

    print("=" * 72)
    print("README baseline (documented in README.md)")
    print("=" * 72)
    print(
        f"  Precision: {readme_baseline['precision_mean']:.1%} ± {readme_baseline['precision_std']:.1%}"
    )
    print(
        f"  Recall:    {readme_baseline['recall_mean']:.1%} ± {readme_baseline['recall_std']:.1%}"
    )
    print(
        f"  F1:        {readme_baseline['f1_mean']:.1%} ± {readme_baseline['f1_std']:.1%}"
    )
    print(
        f"  Accuracy:  {readme_baseline['accuracy_mean']:.1%} ± {readme_baseline['accuracy_std']:.1%}"
    )
    print(
        f"  Dataset:   {readme_baseline['dataset_functions']:,} functions, "
        f"{readme_baseline['dataset_firmware']} firmware"
    )

    print()
    print("=" * 72)
    print("Current corpus — per-firmware metrics, then mean ± std (README-style)")
    print("=" * 72)
    if per_fw_summary.get("firmware_count", 0) == 0:
        print("  No successful firmware evaluations.")
    else:
        for k in ("precision", "recall", "f1_score", "accuracy"):
            s = per_fw_summary[k]
            print(f"  {k:12s}  {s['mean']:.4f} ± {s['std']:.4f}  (min {s['min']:.4f}, max {s['max']:.4f})")
        print(
            f"  Firmware: {per_fw_summary['firmware_count']}, "
            f"functions: {per_fw_summary['total_functions']}"
        )

    if cv_summary:
        print()
        print("=" * 72)
        print(f"Current dataset — {cv_summary['k_folds']}-fold stratified CV (no train leakage)")
        print("=" * 72)
        for k in ("precision", "recall", "f1_score", "accuracy"):
            s = cv_summary[k]
            print(f"  {k:12s}  {s['mean']:.4f} ± {s['std']:.4f}")
        print(f"  n_samples: {cv_summary['n_samples']}")

    print()
    print(f"Full JSON: {out_path}")


if __name__ == "__main__":
    main()
