#!/usr/bin/env bash
# Prepend Espressif Xtensa toolchain bin to PATH (objdump + addr2line for source mapping).
# Safe to `source` from other scripts. Compatible with bash 3.2 + set -u (no empty-array pitfalls).
# Searches: $IDF_PATH, ~/esp/esp-idf, ~/.espressif, Arduino ESP32 package.

_try_prepend_from_dir() {
  local root="$1"
  [[ -n "$root" && -d "$root" ]] || return 1
  local obj bindir
  obj=$(find "$root" -maxdepth 6 -type f \( -name 'xtensa-esp32-elf-objdump' -o -name 'xtensa-esp32s3-elf-objdump' -o -name 'xtensa-esp32s2-elf-objdump' \) 2>/dev/null | head -1)
  if [[ -n "$obj" && -x "$obj" ]]; then
    bindir=$(dirname "$obj")
    export PATH="$bindir:$PATH"
    return 0
  fi
  return 1
}

esp_prepend_xtensa_tools() {
  if [[ -n "${OBJDUMP:-}" && -x "$OBJDUMP" ]]; then
    export PATH="$(dirname "$OBJDUMP"):$PATH"
    return 0
  fi
  if command -v xtensa-esp32-elf-objdump >/dev/null 2>&1; then
    return 0
  fi

  if [[ -n "${IDF_PATH:-}" ]]; then
    _try_prepend_from_dir "${IDF_PATH}/tools/xtensa-esp32-elf" && return 0
  fi
  _try_prepend_from_dir "${HOME}/esp/esp-idf/tools/xtensa-esp32-elf" && return 0
  _try_prepend_from_dir "${HOME}/.espressif/tools/xtensa-esp32-elf" && return 0
  _try_prepend_from_dir "${HOME}/Library/Arduino15/packages/esp32/tools/xtensa-esp32-elf" && return 0

  return 1
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  esp_prepend_xtensa_tools && echo "PATH updated: $(command -v xtensa-esp32-elf-objdump 2>/dev/null || command -v xtensa-esp32s3-elf-objdump 2>/dev/null || echo 'no xtensa objdump found')"
else
  esp_prepend_xtensa_tools || true
fi
