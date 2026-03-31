#!/usr/bin/env bash
# Espressif QEMU (ESP32 xtensa softmmu) — macOS önceden derlenmiş paket.
# Çıktı: tools/espressif-qemu/qemu/bin/qemu-system-xtensa
#
# Gerekli Homebrew kütüphaneleri (ikili bunlara bağlı):
#   brew install libgcrypt pixman glib sdl2 gettext
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="${ROOT}/tools/espressif-qemu"
VERSION="esp-develop-9.2.2-20250817"
BASE="https://github.com/espressif/qemu/releases/download/${VERSION}"

arch="$(uname -m)"
case "$arch" in
  arm64|aarch64) PKG="qemu-xtensa-softmmu-esp_develop_9.2.2_20250817-aarch64-apple-darwin.tar.xz" ;;
  x86_64)        PKG="qemu-xtensa-softmmu-esp_develop_9.2.2_20250817-x86_64-apple-darwin.tar.xz" ;;
  *) echo "Unsupported arch: $arch"; exit 1 ;;
esac

mkdir -p "${DEST}"
TMP="${DEST}/${PKG}"
echo "Downloading ${PKG} ..."
curl -fL --progress-bar -o "${TMP}" "${BASE}/${PKG}"
echo "Extracting to ${DEST} ..."
tar -xJf "${TMP}" -C "${DEST}"
rm -f "${TMP}"

BIN="${DEST}/qemu/bin/qemu-system-xtensa"
if [[ ! -x "$BIN" ]]; then
  BIN="$(find "${DEST}" -name qemu-system-xtensa -type f -perm -111 2>/dev/null | head -1)"
fi
if [[ ! -x "$BIN" ]]; then
  echo "qemu-system-xtensa bulunamadı; arşiv yapısı değişmiş olabilir."
  find "${DEST}" -maxdepth 4 -type f | head -20
  exit 1
fi

echo ""
echo "Kurulum tamam: $BIN"
"$BIN" -machine help 2>&1 | grep -iE esp32 | head -5 || true
echo ""
echo "configs/config.yaml içinde şunu ayarla:"
echo "  validation:"
echo "    fuzzing:"
echo "      qemu_path: ${BIN}"
