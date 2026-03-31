#!/usr/bin/env python3
"""GitLab'dan indirilen firmware'lerden training data oluştur"""

import sys
from pathlib import Path
import json

sys.path.insert(0, str(Path(__file__).parent.parent))

from esp32_firmguard.utils import load_config, setup_logging
from esp32_firmguard.pipeline import FirmwareSecurityPipeline
from esp32_firmguard.models.dataset import DatasetBuilder


def create_training_data_from_firmware_dir(firmware_dir: Path, output_dir: Path, config: dict):
    """Firmware klasöründen training data oluştur"""
    import pandas as pd
    
    firmware_dir = Path(firmware_dir)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Find all firmware files
    firmware_files = []
    for pattern in ("*.bin", "*.elf", "*.img"):
        firmware_files.extend(firmware_dir.rglob(pattern))
    firmware_files = sorted({p.resolve() for p in firmware_files})
    
    if not firmware_files:
        print(f"Firmware bulunamadı: {firmware_dir}")
        return None, None
    
    print(f"{len(firmware_files)} firmware dosyası bulundu\n")
    
    # Initialize pipeline
    pipeline = FirmwareSecurityPipeline(config)
    dataset_builder = DatasetBuilder(config)
    
    all_structural = []
    all_peripheral = []
    all_embeddings = []
    all_cwe_labels = {}
    
    # Process each firmware
    for i, fw_path in enumerate(firmware_files, 1):
        print(f"[{i}/{len(firmware_files)}] İşleniyor: {fw_path.name}...")
        
        try:
            # Run static analysis
            fw, feature_matrix, predictions, cwe_labels = pipeline.run_static_stage(
                str(fw_path),
                source="gitlab"
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
            
            print(f"  {len(structural)} fonksiyon çıkarıldı")
            print(f"  CWE labels: {len(prefixed_cwe_labels)} fonksiyon\n")
            
        except Exception as e:
            print(f"  Hata: {e}\n")
            continue
    
    if not all_structural:
        print("Hiç fonksiyon çıkarılamadı!")
        return None, None
    
    # Combine all features
    print("📊 Feature'lar birleştiriliyor...")
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

    n_before = len(feature_matrix)
    if feature_matrix.index.duplicated().any():
        nd = int(feature_matrix.index.duplicated().sum())
        print(f"\n⚠️  {nd} duplicate index rows in feature matrix; deduplicating (keep='first').")
        feature_matrix = feature_matrix[~feature_matrix.index.duplicated(keep="first")]
        print(f"   Rows: {n_before} -> {len(feature_matrix)}")
    
    # Create labels from CWE labels
    # Strategy: If function has CWE label, consider it vulnerable (1)
    # Otherwise, safe (0)
    print("\n🏷️  Ground truth labels oluşturuluyor...")
    print("   Strateji: CWE label'ı olan fonksiyonlar = vulnerable (1)")
    print("             CWE label'ı olmayan fonksiyonlar = safe (0)")
    
    labels = dataset_builder.create_labels(all_cwe_labels, feature_matrix.index)
    
    # Statistics
    vulnerable_count = labels.sum()
    safe_count = (labels == 0).sum()
    total = len(labels)
    
    print(f"\n📊 Dataset İstatistikleri:")
    print(f"   Toplam fonksiyon: {total}")
    print(f"   Vulnerable: {vulnerable_count} ({vulnerable_count/total*100:.1f}%)")
    print(f"   Safe: {safe_count} ({safe_count/total*100:.1f}%)")
    
    # Save dataset
    print(f"\n💾 Dataset kaydediliyor: {output_dir}...")
    dataset_builder.save_dataset(feature_matrix, labels, output_dir)
    
    # Save CWE labels for reference
    cwe_labels_path = output_dir / "cwe_labels.json"
    with open(cwe_labels_path, 'w') as f:
        json.dump(all_cwe_labels, f, indent=2)
    print(f"   CWE labels kaydedildi: {cwe_labels_path}")
    
    print(f"\nDataset oluşturuldu!")
    print(f"   Features: {feature_matrix.shape}")
    print(f"   Labels: {len(labels)}")
    
    return feature_matrix, labels


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Firmware'lerden training data oluştur")
    parser.add_argument(
        "firmware_dir",
        type=str,
        help="Firmware dosyalarının bulunduğu dizin"
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        default="./output/datasets/training_data",
        help="Output directory"
    )
    parser.add_argument(
        "-c", "--config",
        type=str,
        default="configs/config.yaml",
        help="Config dosyası"
    )
    
    args = parser.parse_args()
    
    # Setup
    config = load_config(args.config)
    setup_logging("INFO")
    
    print("=" * 80)
    print("TRAINING DATA OLUŞTURMA")
    print("=" * 80)
    print()
    
    feature_matrix, labels = create_training_data_from_firmware_dir(
        Path(args.firmware_dir),
        Path(args.output),
        config
    )
    
    if feature_matrix is not None:
        print("\n" + "=" * 80)
        print("TRAINING DATA HAZIR!")
        print("=" * 80)
        print(f"\nModel eğitmek için:")
        print(f"  python -m esp32_firmguard.cli train {args.output} -m model.pkl")
        print("=" * 80)
    else:
        print("\nTraining data oluşturulamadı!")


if __name__ == "__main__":
    main()

