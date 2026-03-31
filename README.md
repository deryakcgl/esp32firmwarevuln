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
- Bounded dynamic validation (mutation-based fuzzing + optional QEMU smoke tests)

**Performance note (important):**
- Reported metrics depend heavily on the firmware corpus and the ground-truth labeling strategy.
- This repository includes scripts to reproduce metrics locally, but large corpora, models, and outputs are typically **not committed** (see `.gitignore`).

**Performance (example results):**
- The numbers below are **example outputs** from running `scripts/evaluate_readme_aligned.py` on a local corpus.
- They are **not guaranteed** to match your environment unless you use the same corpus, config, and labeling/ground-truth setup.

Example (README-style: per-firmware mean ± std, CWE-pattern proxy ground truth):
- Precision: **0.947 ± 0.063**
- Recall: **1.000 ± 0.000**
- F1: **0.972 ± 0.035**
- Accuracy: **0.988 ± 0.015**
- Corpus scale in that run: **~1960 firmware**, **~97,766 functions** (counted per firmware evaluation)

To reproduce on your machine, run the evaluation script and use the JSON it writes:

```bash
python scripts/evaluate_readme_aligned.py \
  --firmware-dir <your_firmware_dir> \
  --dataset-dir output/datasets/training_data \
  --model-file vulnerability_model.pkl \
  --max-cv-samples 100000 \
  -o output/evaluation/readme_aligned_comparison.json
```

## Installation

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Optional: Install Espressif QEMU (ESP32 machine)

The stock Homebrew `qemu-system-xtensa` often does **not** include `-machine esp32`.
This repo provides a helper script to install Espressif’s prebuilt QEMU and configure the project to use it.

```bash
brew install libgcrypt pixman glib sdl2 gettext
bash scripts/install_espressif_qemu.sh
```

By default, `configs/config.yaml` points fuzzing to:

```
./tools/espressif-qemu/qemu/bin/qemu-system-xtensa
```

## Quick Start

### Analyze a Firmware Binary

```bash
python -m esp32_firmguard.cli analyze firmware_samples/example_firmware.bin -s test -o results.json
```

Notes:
- Use `--skip-validation` to run static-only analysis.
- Without `--skip-validation`, the pipeline runs a bounded fuzzing validation stage (see `configs/config.yaml`).

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

Fuzzing-related options live under `validation.fuzzing` (e.g., `mutations_per_function`, `max_functions_to_fuzz`, `qemu_timeout_sec`, `qemu_path`).

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

### README-aligned evaluation (reproducible)

This repo includes an evaluation script that prints:
- a documented README baseline block (if you keep it for comparison), and
- current corpus results as per-firmware mean ± std (README-style),
- plus optional stratified K-fold CV on a saved dataset.

Example:

```bash
python scripts/evaluate_readme_aligned.py \
  --firmware-dir firmware_samples \
  --dataset-dir output/datasets/training_data \
  --model-file vulnerability_model.pkl \
  --max-cv-samples 100000 \
  -o output/evaluation/readme_aligned_comparison.json
```

### QEMU + fuzzing visibility demo

To see QEMU baseline vs mutated runs and per-function fuzz details in the terminal:

```bash
python scripts/demo_qemu_fuzz_smoke.py --firmware path/to/firmware.bin --mutations 8 --max-funcs 2
```

## License

MIT License

