# ESP32 FirmGuard

ESP32 firmware vulnerability analysis: static features, CWE labeling, ML risk scoring, and a **desktop app** that shows **function name, source file, line numbers, and highlighted source code** for each finding.

## Desktop app (primary workflow)

1. **Train my model** — upload debug ELF files (`-g`) and a **source root** per firmware; the app builds a dataset, splits by firmware, trains XGBoost, saves `output/models/user_model.pkl`.
2. **Test my firmware** — upload a debug ELF; review functions sorted by risk (highest first). **Vulnerable rows are red**; select a row to see source with highlighted lines.

### Requirements

- Python 3.10+
- **ESP-IDF / Xtensa toolchain** on `PATH`: `xtensa-esp32-elf-objdump`, `xtensa-esp32-elf-addr2line`
- Firmware built **with debug symbols** (`-g`)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Optional: prepend Xtensa tools
source scripts/esp_prepend_xtensa_tools.sh

python -m firmguard_desktop
```

Point **Source root** at your project directory (sketch / `main/`) so DWARF paths resolve to `.c` / `.cpp` files on disk.

### CWE labels (Excel + Ollama)

All training and analysis **requires a CWE Excel file** (desktop, CLI, API, scripts).

1. **CWE catalog** (`cwe_id`, `llm_labeling_rule`, `use_as_label`, …) → Ollama labels every function using your Excel rules.
2. **Per-function rows** (`function_name`, `cwe`, …) → Excel rows are used first; Ollama fills functions without a row.

Set default path in `configs/config.yaml` → `labeling.excel_path`, or pass `--cwe-excel` / upload in the API.

Ollama must be running for LLM steps (`ollama pull llama3.2`). Desktop → **Test connection** in the CWE section.

### Optional HTTP API

```bash
uvicorn esp32_firmguard.api.app:app --port 8765
```

`POST /train` (ELF files + **cwe_excel** file), `POST /analyze` (ELF + **cwe_excel** + optional `source_root`, `model_path`).

## CLI (automation)

```bash
# Analyze debug ELF
python -m esp32_firmguard.cli analyze \
  --elf path/to/firmware.elf \
  --source-root path/to/project/source \
  --cwe-excel path/to/cwe_catalog.xlsx \
  -o output/results.json

# Train from debug ELFs
python -m esp32_firmguard.cli train \
  --elf path/to/fw1.elf --elf path/to/fw2.elf \
  --source-root path/to/project/source \
  --cwe-excel path/to/cwe_catalog.xlsx
```

## Python services API

```python
from esp32_firmguard.utils import load_config
from esp32_firmguard.services import TrainingService, AnalysisService

config = load_config("configs/config.yaml")

TrainingService(config).train(
    ["build/project.elf"],
    source_roots_map={"project": ["/path/to/project"]},
    cwe_excel_path="path/to/cwe_catalog.xlsx",
)

result = AnalysisService(config).analyze(
    "build/project.elf",
    model_path="output/models/user_model.pkl",
    source_roots=["/path/to/project"],
    cwe_excel_path="path/to/cwe_catalog.xlsx",
)
for f in result.findings:
    print(f.score, f.name, f.source_file, f.line_start)
```

## Pipeline architecture

```
Upload debug ELF
    → ELF symbols + objdump disassembly
    → DWARF (addr2line) → source_file, line_start/end
    → Read source snippet from disk
    → Features + CWE labels → XGBoost predict
    → Ranked findings with source context
```

| Package | Role |
|---------|------|
| `esp32_firmguard/ingestion/` | ELF extraction, DWARF mapping, source snippets |
| `esp32_firmguard/features/` | Structural, peripheral, embedding features |
| `esp32_firmguard/labeling/` | CWE labeling (Excel + Ollama) |
| `esp32_firmguard/models/` | Dataset, trainer, predictor |
| `esp32_firmguard/services/` | Training & analysis orchestration |
| `esp32_firmguard/api/` | FastAPI wrapper |
| `firmguard_desktop/` | PySide6 GUI |

## Configuration

Edit `configs/config.yaml`: `labeling.excel_path`, model threshold, Ollama settings, ELF extraction limits.

## Scripts

See [scripts/README.md](scripts/README.md) for helper scripts.

## License

MIT License
