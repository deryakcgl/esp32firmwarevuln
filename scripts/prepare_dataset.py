#!/usr/bin/env python3
"""Script to prepare dataset from multiple firmware samples"""

import sys
from pathlib import Path
import json

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from esp32_firmguard.utils import load_config, setup_logging, ensure_dir
from esp32_firmguard.pipeline import FirmwareSecurityPipeline
from esp32_firmguard.models.dataset import DatasetBuilder


def process_firmware_samples(firmware_dir: Path, config: dict, output_dir: Path):
    """Process multiple firmware samples and create dataset"""
    firmware_dir = Path(firmware_dir)
    output_dir = Path(output_dir)
    ensure_dir(output_dir)
    
    # Find all firmware files
    firmware_files = list(firmware_dir.glob("*.bin")) + list(firmware_dir.glob("*.elf"))
    
    if not firmware_files:
        print(f"No firmware files found in {firmware_dir}")
        return
    
    print(f"Found {len(firmware_files)} firmware files")
    
    # Initialize pipeline
    pipeline = FirmwareSecurityPipeline(config)
    dataset_builder = DatasetBuilder(config)
    
    all_structural = []
    all_peripheral = []
    all_embeddings = []
    all_cwe_labels = {}
    
    # Process each firmware
    for i, fw_path in enumerate(firmware_files, 1):
        print(f"\n[{i}/{len(firmware_files)}] Processing {fw_path.name}...")
        
        try:
            # Run static analysis
            fw, feature_matrix, predictions, cwe_labels = pipeline.run_static_stage(
                str(fw_path),
                source="dataset"
            )
            
            # Extract individual feature types
            structural = pipeline.struct_feat.extract(fw)
            peripheral = pipeline.periph_feat.extract(fw)
            embeddings = pipeline.embed_feat.extract(fw)
            
            # Add prefix to function IDs to avoid collisions
            prefix = f"{fw_path.stem}_"
            structural.index = [prefix + str(idx) for idx in structural.index]
            peripheral.index = [prefix + str(idx) for idx in peripheral.index]
            embeddings.index = [prefix + str(idx) for idx in embeddings.index]
            
            # Update CWE labels with prefix
            prefixed_cwe_labels = {prefix + k: v for k, v in cwe_labels.items()}
            
            all_structural.append(structural)
            all_peripheral.append(peripheral)
            all_embeddings.append(embeddings)
            all_cwe_labels.update(prefixed_cwe_labels)
            
            print(f"  Extracted {len(structural)} functions")
            
        except Exception as e:
            print(f"  Error processing {fw_path.name}: {e}")
            continue
    
    # Combine all features
    print("\nCombining features...")
    import pandas as pd
    
    combined_structural = pd.concat(all_structural) if all_structural else pd.DataFrame()
    combined_peripheral = pd.concat(all_peripheral) if all_peripheral else pd.DataFrame()
    combined_embeddings = pd.concat(all_embeddings) if all_embeddings else pd.DataFrame()
    
    # Build feature matrix
    feature_matrix = dataset_builder.build_feature_matrix(
        combined_structural,
        combined_peripheral,
        combined_embeddings,
        all_cwe_labels
    )
    
    # Create labels
    labels = dataset_builder.create_labels(all_cwe_labels, feature_matrix.index)
    
    # Save dataset
    print(f"\nSaving dataset to {output_dir}...")
    dataset_builder.save_dataset(feature_matrix, labels, output_dir)
    
    print(f"\nDataset created:")
    print(f"  Features: {feature_matrix.shape}")
    print(f"  Labels: {len(labels)}")
    print(f"  Vulnerable functions: {labels.sum()}")
    print(f"  Safe functions: {(labels == 0).sum()}")


def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Prepare dataset from firmware samples")
    parser.add_argument("firmware_dir", type=str, help="Directory containing firmware files")
    parser.add_argument("-o", "--output", type=str, default="./output/datasets/dataset",
                       help="Output directory for dataset")
    parser.add_argument("-c", "--config", type=str, default="configs/config.yaml",
                       help="Path to config file")
    parser.add_argument("--log-level", type=str, default="INFO",
                       choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    
    args = parser.parse_args()
    
    # Setup
    config = load_config(args.config)
    setup_logging(args.log_level)
    
    # Process firmware samples
    process_firmware_samples(
        firmware_dir=Path(args.firmware_dir),
        config=config,
        output_dir=Path(args.output)
    )


if __name__ == "__main__":
    main()


