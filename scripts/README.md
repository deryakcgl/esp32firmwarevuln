# Scripts

| Script | Purpose |
|--------|---------|
| `prepare_training_data_from_firmware.py` | Batch dataset export via CLI |
| `esp_prepend_xtensa_tools.sh` | Prepend Xtensa objdump/addr2line to PATH |

## Desktop (recommended)

```bash
pip install -r requirements.txt
python -m firmguard_desktop
```

Place debug ELFs and matching source trees locally; set **Source root** in the app per firmware.
