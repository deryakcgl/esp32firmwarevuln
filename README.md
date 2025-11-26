# ESP32 FirmGuard

ESP32 firmware güvenlik analizi için kapsamlı bir pipeline.

## Özellikler

- Firmware extraction (Binwalk/EMBA/Ghidra)
- Feature extraction (structural, peripheral, embeddings)
- LLM-based CWE labeling
- Risk prediction (XGBoost/RandomForest)
- Dynamic validation (fuzzing)
- Hardware validation (power trace analysis)
- Comprehensive metrics (Precision, Recall, F1, VCR, SRI)

## Kurulum

```bash
# Virtual environment oluştur
python3 -m venv venv
source venv/bin/activate

# Bağımlılıkları yükle
pip install -r requirements.txt
```

## Kullanım

### CLI

```bash
# Firmware analizi
python -m esp32_firmguard.cli analyze firmware.bin -s tasmota -o results.json

# Model eğitimi
python -m esp32_firmguard.cli train ./output/datasets/dataset -m model.pkl
```

### Python API

```python
from esp32_firmguard.utils import load_config, setup_logging
from esp32_firmguard.pipeline import FirmwareSecurityPipeline

config = load_config("configs/config.yaml")
setup_logging("INFO")
pipeline = FirmwareSecurityPipeline(config)

results = pipeline.run_full_pipeline(
    firmware_path="firmware.bin",
    source="tasmota",
    run_validation=True
)
```

## Konfigürasyon

`configs/config.yaml` dosyasını düzenleyerek pipeline'ı özelleştirebilirsiniz.

## Test

```bash
pytest tests/
```

## Lisans

MIT License

