# Scripts

| Script | Purpose |
|--------|---------|
| `fetch_curated_esp32_firmware.py` | Download train/test debug ELFs (Wokwi + ESP-IDF via Docker) |
| `prepare_training_data_from_firmware.py` | Batch dataset export via CLI |
| `run_wokwi_realistic_test.sh` | CLI analyze on Wokwi sample (`CWE_EXCEL=…/catalog.xlsx` required) |
| `esp_prepend_xtensa_tools.sh` | Prepend Xtensa objdump/addr2line to PATH |

## Curated firmware

```bash
python scripts/fetch_curated_esp32_firmware.py
```

Each sample folder contains `firmware.elf`, `source/`, and `source_root.txt`.

## Desktop (recommended)

```bash
pip install -r requirements.txt
python -m firmguard_desktop
```
