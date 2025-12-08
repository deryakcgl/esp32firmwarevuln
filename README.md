# ESP32 FirmGuard

ESP32 firmware security analysis pipeline for vulnerability detection using static analysis, LLM-based semantic labeling, and machine learning.

## Overview

ESP32 FirmGuard is a comprehensive static analysis framework for detecting vulnerabilities in ESP32 firmware binaries. The system combines structural feature extraction, peripheral analysis, semantic embeddings, and XGBoost-based risk prediction to identify potential security issues.

**Key Features:**
- Static analysis of firmware binaries (Binwalk, EMBA, Ghidra)
- Multi-dimensional feature extraction (structural, peripheral, semantic)
- LLM-based CWE classification (OpenAI, Anthropic, Ollama, or pattern-based)
- XGBoost vulnerability prediction model
- Comprehensive evaluation metrics

**Performance:**
- Precision: 43.5% ± 9.9%
- Recall: 25.5% ± 5.5%
- F1 Score: 32.0% ± 6.7%
- Accuracy: 60.8% ± 4.1%
- Dataset: 101,966 function samples from 1,747 firmware binaries

## Installation

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Quick Start

### Analyze a Firmware Binary

```bash
python -m esp32_firmguard.cli analyze firmware_samples/example_firmware.bin -s test -o results.json
```

### Train the Model

```bash
python scripts/prepare_training_data_from_firmware.py firmware_samples/filtered -o ./output/datasets/training_data
python -m esp32_firmguard.cli train ./output/datasets/training_data -m ./output/models/vulnerability_model.pkl
```

### Python API

```python
from esp32_firmguard.utils import load_config, setup_logging
from esp32_firmguard.pipeline import FirmwareSecurityPipeline

config = load_config("configs/config.yaml")
setup_logging("INFO")
pipeline = FirmwareSecurityPipeline(config)

# Run static analysis
fw, features, predictions, cwe_labels = pipeline.run_static_stage(
    firmware_path="firmware.bin",
    source="test"
)

# Evaluate with ground truth
metrics = pipeline.evaluate(
    ground_truth=ground_truth_dict,
    predictions=predictions
)
```

## Configuration

Edit `configs/config.yaml` to customize:
- Feature extraction settings
- LLM provider and model selection
- Model hyperparameters
- Validation options

## Project Structure

```
esp32_firmguard/
├── ingestion/          # Firmware extraction (Binwalk, EMBA, Ghidra)
├── features/           # Feature extraction (structural, peripheral, embeddings)
├── labeling/           # CWE classification (LLM-based)
├── models/             # Model training and prediction
├── validation/         # Dynamic validation (fuzzing, hardware)
└── metrics/            # Evaluation metrics

scripts/                # Utility scripts for training, evaluation, data collection
output/                 # Analysis results, models, datasets
firmware_samples/       # Firmware binaries and ground truth
```

## Evaluation

See `output/evaluation/EVALUATION_SUMMARY.md` for comprehensive evaluation results, ablation studies, and baseline comparisons.

## License

MIT License

