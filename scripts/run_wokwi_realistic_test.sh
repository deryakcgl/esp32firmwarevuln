#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck disable=SC1091
source "$ROOT/scripts/esp_prepend_xtensa_tools.sh"
DEST="$ROOT/firmware_samples/test/wokwi_http_server"
ELF="$DEST/firmware.elf"
SOURCE="$DEST/source"
OUT="$ROOT/output/wokwi_http_realistic.json"
PY="$ROOT/.venv/bin/python"

if [[ ! -f "$ELF" ]]; then
  echo "Sample firmware missing. Run:"
  echo "  python scripts/fetch_curated_esp32_firmware.py"
  exit 1
fi

if [[ ! -d "$SOURCE" ]]; then
  echo "Missing source tree: $SOURCE" >&2
  echo "Run: python scripts/fetch_curated_esp32_firmware.py" >&2
  exit 1
fi

if [[ -z "${CWE_EXCEL:-}" || ! -f "${CWE_EXCEL}" ]]; then
  echo "Set CWE_EXCEL to your CWE catalog or per-function labels .xlsx" >&2
  exit 1
fi

if [[ ! -x "$PY" ]]; then
  echo "Missing venv. Run: python3 -m venv .venv && .venv/bin/pip install -r requirements.txt" >&2
  exit 1
fi

exec "$PY" -m esp32_firmguard.cli analyze \
  --elf "$ELF" \
  --source-root "$SOURCE" \
  --cwe-excel "$CWE_EXCEL" \
  -c "$ROOT/configs/config.yaml" \
  --threshold 0.12 \
  -o "$OUT"
