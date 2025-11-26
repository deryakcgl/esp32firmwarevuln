#!/usr/bin/env python3
"""Örnek: Test datası ile pipeline çalıştırma"""

import sys
from pathlib import Path
import json

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from esp32_firmguard.utils import load_config, setup_logging
from esp32_firmguard.pipeline import FirmwareSecurityPipeline


def main():
    """Test datası ile örnek pipeline çalıştırma"""
    
    # Setup
    config = load_config("configs/config.yaml")
    setup_logging("INFO")
    
    # Pipeline oluştur
    pipeline = FirmwareSecurityPipeline(config)
    
    # Test firmware ve ground truth
    firmware_path = "firmware_samples/example_firmware.bin"
    ground_truth_path = "firmware_samples/ground_truth/example_firmware_ground_truth.json"
    
    # Ground truth yükle
    with open(ground_truth_path, 'r') as f:
        ground_truth = json.load(f)
    
    print("=" * 80)
    print("Test Data ile Pipeline Çalıştırma")
    print("=" * 80)
    print(f"\nFirmware: {firmware_path}")
    print(f"Ground Truth: {ground_truth_path}")
    print(f"Ground Truth Functions: {len(ground_truth)}")
    print(f"Vulnerable Functions: {sum(ground_truth.values())}")
    print("\n" + "=" * 80 + "\n")
    
    # Pipeline'ı çalıştır
    results = pipeline.run_full_pipeline(
        firmware_path=firmware_path,
        source="test",
        ground_truth=ground_truth,
        run_validation=True,
        run_evaluation=True
    )
    
    # Sonuçları göster
    print("\n" + "=" * 80)
    print("SONUÇLAR")
    print("=" * 80)
    
    print(f"\nToplam Fonksiyon: {len(results['predictions'])}")
    print(f"Tahmin Edilen Vulnerable: {sum(p.is_vulnerable for p in results['predictions'])}")
    print(f"Gerçek Vulnerable: {sum(ground_truth.values())}")
    
    if results['metrics']:
        print("\n📊 Metrikler:")
        print(f"  Precision: {results['metrics']['precision']:.3f}")
        print(f"  Recall: {results['metrics']['recall']:.3f}")
        print(f"  F1-Score: {results['metrics']['f1_score']:.3f}")
        print(f"  Accuracy: {results['metrics']['accuracy']:.3f}")
        print(f"  VCR: {results['metrics']['vcr']:.3f}")
        print(f"  SRI: {results['metrics']['sri']:.3f}")
    
    print("\n🔍 Top 5 Vulnerable Fonksiyonlar:")
    sorted_preds = sorted(results['predictions'], key=lambda p: p.score, reverse=True)
    for i, pred in enumerate(sorted_preds[:5], 1):
        status = "✅ VULNERABLE" if pred.is_vulnerable else "⚪ Safe"
        print(f"  {i}. {pred.func_id}: score={pred.score:.3f} {status} CWE={pred.cwe}")
    
    if results.get('fuzz_results'):
        print(f"\n🔬 Fuzzing Sonuçları:")
        total_crashes = sum(r.crashes_found for r in results['fuzz_results'].values())
        print(f"  Toplam Crash: {total_crashes}")
    
    if results.get('hw_results'):
        print(f"\n⚡ Hardware Power Sonuçları:")
        anomalies = sum(1 for r in results['hw_results'].values() if r.is_anomaly)
        print(f"  Tespit Edilen Anomali: {anomalies}")
    
    print("\n" + "=" * 80)


if __name__ == "__main__":
    main()


