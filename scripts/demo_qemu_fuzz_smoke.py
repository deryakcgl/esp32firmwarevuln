#!/usr/bin/env python3
"""
Görsel QEMU + fuzzing duman testi.

Ne yapar:
  1) Baseline QEMU + stderr özeti.
  1b) Birkaç agresif mutasyon (4KB/64KB sıfır, XOR, rastgele) ve _regression karşılaştırması.
  2) Pipeline + FuzzingValidator._run_fuzzing (--raw-only ile atlanır).

Örnek:
  .venv/bin/python scripts/demo_qemu_fuzz_smoke.py \\
    --firmware "firmware_samples copy/github_collected/some_tasmota.bin"
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from esp32_firmguard.utils import load_config, setup_logging
from esp32_firmguard.validation.fuzzing import FuzzingValidator
from esp32_firmguard.pipeline import FirmwareSecurityPipeline


def _tail_text(b: bytes, max_len: int = 1200) -> str:
    if not b:
        return "(boş)"
    chunk = b[-max_len:]
    return chunk.decode("utf-8", errors="replace")


def find_default_firmware() -> Path | None:
    roots = [
        Path("firmware_samples copy/github_collected"),
        Path("firmware_samples copy/github"),
        Path("firmware_samples/github_open"),
    ]
    for root in roots:
        if not root.is_dir():
            continue
        bins = sorted(root.rglob("*.bin"))
        if bins:
            return bins[0]
    return None


def demo_raw_qemu(validator: FuzzingValidator, firmware: Path) -> None:
    print("\n" + "=" * 72)
    print("1) Ham QEMU dumanı (validator ile aynı argümanlar)")
    print("=" * 72)
    if not validator.qemu_exe:
        print("QEMU bulunamadı. config.yaml içinde validation.fuzzing.qemu_path kontrol et.")
        return

    raw = firmware.read_bytes()
    print(f"Firmware: {firmware} ({len(raw)} byte)")
    print(f"QEMU:     {validator.qemu_exe}")
    print(f"Makine:   {validator.qemu_machine}")
    print(f"Timeout:  {validator.qemu_timeout_sec} s")

    cmd = [
        validator.qemu_exe,
        "-nographic",
        "-machine",
        validator.qemu_machine,
        "-drive",
        f"file=__PATH__,if=mtd,format=raw",
        "-serial",
        "null",
        "-monitor",
        "none",
    ]
    print("\nKomut şablonu:")
    print(" ", " ".join(cmd).replace("__PATH__", "<geçici_dosya>"))

    # Agresif karşılaştırmada biraz daha süre (timeout vs nonzero ayrımı için)
    validator.qemu_timeout_sec = max(float(validator.qemu_timeout_sec), 3.0)
    print(f"(Demo: qemu_timeout_sec={validator.qemu_timeout_sec} s)\n")

    def mutate_xor_head(buf: bytearray, n: int) -> bytes:
        for i in range(min(n, len(buf))):
            buf[i] ^= 0xFF
        return bytes(buf)

    def mutate_zero_head(buf: bytearray, n: int) -> bytes:
        for i in range(min(n, len(buf))):
            buf[i] = 0
        return bytes(buf)

    def mutate_random_head(buf: bytearray, n: int) -> bytes:
        n = min(n, len(buf))
        buf[:n] = os.urandom(n)
        return bytes(buf)

    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as t:
        t.write(raw)
        base_path = Path(t.name)
    try:
        st, sig, out = validator._qemu_run(base_path)
        print(f"\n--- Baseline sonuç ---\n  status={st!r}  signal={sig!r}")
        print("--- Çıktı sonu (stderr+stdout) ---")
        print(_tail_text(out))
        low = out.lower()
        if b"unsupported machine" in low or b"invalid machine" in low:
            print(
                "\n[!] Bu QEMU derlemesinde '-machine esp32' yok. Espressif/ESP-IDF QEMU veya "
                "esp32 hedefi olan bir build gerekir; aksi halde validator QEMU'yu atlayıp "
                "sadece mutasyon + esp_image oracle kullanır (fuzzing.py düzeltmesi sonrası)."
            )
    finally:
        base_path.unlink(missing_ok=True)

    print("\n" + "-" * 72)
    print("1b) Agresif bozulmalar (boot / partition başına müdahale)")
    print("-" * 72)
    print(
        "Amaç: Küçük bit-flip bazen aynı timeout’u verir; başı sıfırlamak veya "
        "rastgele doldurmak stderr/çıkış kodunu değiştirebilir → _regression True olabilir."
    )

    probes: list[tuple[str, bytes]] = [
        ("İlk 4 KB XOR 0xFF", mutate_xor_head(bytearray(raw), 4096)),
        ("İlk 4 KB sıfır", mutate_zero_head(bytearray(raw), 4096)),
        ("İlk 64 KB sıfır", mutate_zero_head(bytearray(raw), 65536)),
        ("İlk 64 KB rastgele", mutate_random_head(bytearray(raw), 65536)),
    ]

    any_regression = False
    for label, payload in probes:
        with tempfile.NamedTemporaryFile(suffix=".probe.bin", delete=False) as t:
            t.write(payload)
            mut_path = Path(t.name)
        try:
            st2, sig2, out2 = validator._qemu_run(mut_path)
            reg = validator._qemu_regression(st, st2, out, out2)
            fb = validator._fallback_crash(raw, payload)
            if reg:
                any_regression = True
            print(f"\n>>> {label}")
            print(f"    status={st2!r}  regression_vs_baseline={reg}  esp_image_oracle={fb}")
            if st2 != st or reg or fb:
                print("    --- Çıktı sonu ---")
                print(_tail_text(out2, 800))
        finally:
            mut_path.unlink(missing_ok=True)

    print(f"\nÖzet: en az bir regression sinyali = {any_regression}")
    if not any_regression and st == "timeout":
        print(
            "(Her koşu timeout kaldıysa: imaj hâlâ QEMU’yu aynı şekilde ‘takılı’ bırakıyor; "
            "bu exploit değil, sadece davranış farkı arıyoruz.)"
        )


def demo_validator_fuzz(
    firmware: Path, config: dict, mutations: int, max_funcs: int
) -> None:
    print("\n" + "=" * 72)
    print("2) Pipeline + FuzzingValidator._run_fuzzing (gerçek kod yolu)")
    print("=" * 72)
    cfg = dict(config)
    fuzz = cfg.setdefault("validation", {}).setdefault("fuzzing", {})
    fuzz["mutations_per_function"] = mutations
    fuzz["max_functions_to_fuzz"] = max_funcs
    fuzz["qemu_timeout_sec"] = min(float(fuzz.get("qemu_timeout_sec", 4)), 5.0)

    setup_logging("INFO")
    pipeline = FirmwareSecurityPipeline(cfg)
    fw, _fm, predictions, _cwe = pipeline.run_static_stage(str(firmware), source="demo")

    preds = sorted(predictions, key=lambda p: -p.score)
    threshold = float(cfg.get("model", {}).get("threshold", 0.4))
    high = [p.func_id for p in preds if p.score >= threshold][:max_funcs]
    if not high:
        high = [next(iter(fw.functions.keys()))]

    validator = pipeline.fuzz_validator
    for fid in high[:max_funcs]:
        print(f"\n>>> _run_fuzzing(func_id={fid!r})")
        res = validator._run_fuzzing(fw, fid)
        print(f"    crashes_found={res.crashes_found} unique_crashes={res.unique_crashes}")
        print(f"    coverage={res.coverage:.1f}% time={res.execution_time:.2f}s")
        print(f"    details={res.details}")


def main() -> None:
    p = argparse.ArgumentParser(description="QEMU + fuzzing görünür duman testi")
    p.add_argument(
        "--firmware",
        type=str,
        default="",
        help=".bin yolu (boşsa bilinen klasörlerden ilk .bin)",
    )
    p.add_argument("-c", "--config", default="configs/config.yaml")
    p.add_argument("--mutations", type=int, default=4)
    p.add_argument("--max-funcs", type=int, default=1)
    p.add_argument(
        "--raw-only",
        action="store_true",
        help="Sadece ham QEMU karşılaştırması (pipeline çalıştırma)",
    )
    args = p.parse_args()

    fw_path = Path(args.firmware) if args.firmware else None
    if fw_path is None or not fw_path.is_file():
        cand = find_default_firmware()
        if cand is None:
            print(
                "Firmware bulunamadı. --firmware ile .bin ver veya "
                "'firmware_samples copy/github_collected' altına örnek koy.",
                file=sys.stderr,
            )
            sys.exit(1)
        fw_path = cand
        print(f"(Varsayılan firmware seçildi: {fw_path})")

    config = load_config(args.config)
    setup_logging("WARNING")
    validator = FuzzingValidator(config)

    demo_raw_qemu(validator, fw_path)

    if not args.raw_only:
        demo_validator_fuzz(fw_path, config, args.mutations, args.max_funcs)

    print("\n" + "=" * 72)
    print("Bitti. Timeout görmek normal: gerçek cihaz flash düzeni ile tam boot beklenmez.")
    print("Önemli olan: QEMU sürecinin çalışması ve durumların baseline vs mutant ile kıyaslanması.")
    print("=" * 72 + "\n")


if __name__ == "__main__":
    main()
