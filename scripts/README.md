# Scripts Directory

Utility scripts for ESP32 FirmGuard project.

## Main Scripts

### Data Collection
- `fetch_firmware_from_github.py` - Collect firmware binaries from GitHub
- `fetch_firmware_from_gitlab.py` - Collect firmware binaries from GitLab
- `fetch_ground_truth_from_github.py` - Collect ground truth from GitHub vulnerability reports
- `fetch_ground_truth_from_gitlab.py` - Collect ground truth from GitLab

### Training Data Preparation
- `prepare_training_data_from_firmware.py` - Prepare training dataset from firmware samples

### Ground Truth Creation
- `create_ground_truth.py` - Create ground truth using hybrid approach
- `create_ground_truth_from_cve.py` - Create ground truth from CVE database
- `create_ground_truth_from_github.py` - Create ground truth from GitHub reports
- `create_cve_ground_truth_batch.py` - Batch CVE-based ground truth creation
- `create_cwe_ground_truth_batch.py` - Batch CWE-based ground truth creation
- `create_github_ground_truth_batch.py` - Batch GitHub-based ground truth creation

### Evaluation
- `comprehensive_evaluation.py` - Comprehensive evaluation on multiple firmware samples
- `baseline_comparison.py` - Compare feature combinations and models
- `ablation_study.py` - Ablation studies (components, features, thresholds)
- `run_test.py` - Run pipeline on single firmware with detailed metrics

### Model Optimization
- `hyperparameter_tuning.py` - XGBoost hyperparameter tuning
- `optimize_threshold.py` - Find optimal prediction threshold
- `optimize_threshold_for_accuracy.py` - Threshold optimization for accuracy
- `find_optimal_threshold.py` - Alternative threshold optimization
- `train_ensemble_model.py` - Train ensemble models

### Utilities
- `manual_labeling_helper.py` - Manual labeling helper

## Usage Examples

```bash
# Prepare training data
python scripts/prepare_training_data_from_firmware.py firmware_samples/filtered -o ./output/datasets/training_data

# Run comprehensive evaluation
python scripts/comprehensive_evaluation.py firmware_samples/filtered -o output/evaluation/results.json

# Run ablation study
python scripts/ablation_study.py firmware_samples/example_firmware.bin -o output/evaluation/ablation/
```
