"""Command-line interface for ESP32 FirmGuard"""

import argparse
import sys
import json
from pathlib import Path
import logging

from esp32_firmguard.utils import load_config, setup_logging, ensure_dir
from esp32_firmguard.pipeline import FirmwareSecurityPipeline

logger = logging.getLogger(__name__)


def analyze_firmware(args):
    """Analyze a firmware file"""
    # Load config
    config = load_config(args.config)
    
    # Setup logging
    log_level = args.log_level or config.get("logging", {}).get("level", "INFO")
    setup_logging(log_level)
    
    # Initialize pipeline
    pipeline = FirmwareSecurityPipeline(config)
    
    # Load ground truth if provided
    ground_truth = None
    if args.ground_truth:
        with open(args.ground_truth, 'r') as f:
            ground_truth = json.load(f)
    
    # Run pipeline
    results = pipeline.run_full_pipeline(
        firmware_path=args.firmware,
        source=args.source or "unknown",
        ground_truth=ground_truth,
        run_validation=not args.skip_validation,
        run_evaluation=args.ground_truth is not None
    )
    
    # Save results
    if args.output:
        output_path = Path(args.output)
        ensure_dir(output_path.parent)
        
        # Save predictions
        predictions_data = [
            {
                "func_id": p.func_id,
                "score": float(p.score),
                "cwe": p.cwe,
                "is_vulnerable": bool(p.is_vulnerable),
            }
            for p in results["predictions"]
        ]
        
        with open(output_path, 'w') as f:
            json.dump({
                "predictions": predictions_data,
                "cwe_labels": results["cwe_labels"],
                "metrics": results["metrics"]
            }, f, indent=2)
        
        logger.info(f"Results saved to {output_path}")
    
    # Print summary
    print("\n" + "=" * 60)
    print("Analysis Summary")
    print("=" * 60)
    print(f"Firmware: {args.firmware}")
    print(f"Functions analyzed: {len(results['predictions'])}")
    print(f"Vulnerable functions: {sum(p.is_vulnerable for p in results['predictions'])}")
    
    if results["metrics"]:
        print("\nMetrics:")
        print(f"  Precision: {results['metrics']['precision']:.3f}")
        print(f"  Recall: {results['metrics']['recall']:.3f}")
        print(f"  F1-Score: {results['metrics']['f1_score']:.3f}")
        print(f"  VCR: {results['metrics']['vcr']:.3f}")
        print(f"  SRI: {results['metrics']['sri']:.3f}")
    
    print("=" * 60)


def train_model(args):
    """Train a vulnerability prediction model"""
    from esp32_firmguard.models.trainer import ModelTrainer
    from esp32_firmguard.models.dataset import DatasetBuilder
    
    # Load config
    config = load_config(args.config)
    setup_logging(args.log_level or "INFO")
    
    # Load dataset
    dataset_builder = DatasetBuilder(config)
    feature_matrix, labels = dataset_builder.load_dataset(Path(args.dataset))
    
    # Train model
    trainer = ModelTrainer(config)
    metrics = trainer.train(feature_matrix, labels, validation_split=args.validation_split)
    
    # Save model
    model_path = trainer.save_model(args.model_name or "vulnerability_model.pkl")
    
    print("\n" + "=" * 60)
    print("Training Summary")
    print("=" * 60)
    print(f"Training samples: {metrics['train_samples']}")
    print(f"Validation samples: {metrics['validation_samples']}")
    print(f"Training accuracy: {metrics['train_accuracy']:.3f}")
    print(f"Validation accuracy: {metrics['validation_accuracy']:.3f}")
    print(f"Model saved to: {model_path}")
    print("=" * 60)


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="ESP32 Firmware Security Analysis Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # Analyze command
    analyze_parser = subparsers.add_parser("analyze", help="Analyze a firmware file")
    analyze_parser.add_argument("firmware", type=str, help="Path to firmware binary")
    analyze_parser.add_argument("-c", "--config", type=str, default="configs/config.yaml",
                               help="Path to config file")
    analyze_parser.add_argument("-s", "--source", type=str, help="Firmware source (e.g., tasmota, esp-idf)")
    analyze_parser.add_argument("-o", "--output", type=str, help="Output JSON file for results")
    analyze_parser.add_argument("--ground-truth", type=str, help="Path to ground truth JSON file")
    analyze_parser.add_argument("--skip-validation", action="store_true",
                               help="Skip validation stage")
    analyze_parser.add_argument("--log-level", type=str, choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                               default="INFO", help="Logging level")
    
    # Train command
    train_parser = subparsers.add_parser("train", help="Train a vulnerability prediction model")
    train_parser.add_argument("dataset", type=str, help="Path to dataset directory")
    train_parser.add_argument("-c", "--config", type=str, default="configs/config.yaml",
                             help="Path to config file")
    train_parser.add_argument("-m", "--model-name", type=str, help="Name for saved model")
    train_parser.add_argument("--validation-split", type=float, default=0.2,
                             help="Validation split ratio")
    train_parser.add_argument("--log-level", type=str, choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                             default="INFO", help="Logging level")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    try:
        if args.command == "analyze":
            analyze_firmware(args)
        elif args.command == "train":
            train_model(args)
        else:
            parser.print_help()
            sys.exit(1)
    except Exception as e:
        logger.error(f"Error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()


