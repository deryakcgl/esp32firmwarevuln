"""Dynamic validation using fuzzing (QEMU smoke tests + byte mutation)."""

import logging
import os
import random
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

_FATAL_MARKERS = (
    b"qemu:",
    b"fatal",
    b"segmentation",
    b"segfault",
    b"panic",
    b"guru meditation",
    b"invalid",
    b"rom:",
    b"assert",
    b"double fault",
)


@dataclass
class FuzzingResult:
    """Results from fuzzing validation"""

    func_id: str
    crashes_found: int
    coverage: float  # Proxy: share of mutations exercised (0-100)
    execution_time: float  # Seconds
    unique_crashes: int
    timeout_reached: bool
    details: Dict[str, Any]


class FuzzingValidator:
    """Validate high-risk areas with bounded mutation fuzzing and optional QEMU smoke runs."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.fuzzing_config = config.get("validation", {}).get("fuzzing", {})
        self.enabled = self.fuzzing_config.get("enabled", True)
        self.qemu_path = self.fuzzing_config.get("qemu_path", "/usr/bin/qemu-system-xtensa")
        self.afl_path = self.fuzzing_config.get("afl_path", "/usr/local/bin/afl-fuzz")
        self.timeout = float(self.fuzzing_config.get("timeout", 3600))
        self.max_crashes = int(self.fuzzing_config.get("max_crashes", 100))

        self.qemu_machine = self.fuzzing_config.get("qemu_machine", "esp32")
        self.qemu_timeout_sec = float(self.fuzzing_config.get("qemu_timeout_sec", 4.0))
        self.mutations_per_function = int(self.fuzzing_config.get("mutations_per_function", 24))
        self.max_functions_to_fuzz = int(self.fuzzing_config.get("max_functions_to_fuzz", 12))
        self.allow_mutation_only = self.fuzzing_config.get("allow_mutation_only", True)
        self.fallback_oracle = self.fuzzing_config.get(
            "fallback_oracle", "esp_image"
        )  # esp_image | none

        self.qemu_exe = self._resolve_executable(self.qemu_path)
        self.afl_exe = self._resolve_executable(self.afl_path)
        self._qemu_checked = False
        self._qemu_works = False

        # AFL is optional; pipeline used to require it and then always crashed on NotImplementedError.
        if self.enabled:
            if self.qemu_exe:
                logger.info("Fuzzing: QEMU found at %s", self.qemu_exe)
            else:
                logger.warning("qemu-system-xtensa not found at %s", self.qemu_path)
            if self.afl_exe:
                logger.info("AFL++ binary present at %s (optional; not used in default mutate+QEMU path)", self.afl_exe)
            if not self.qemu_exe and not self.allow_mutation_only:
                logger.warning("Mutation-only fallback disabled and QEMU missing; fuzzing will be skipped.")

        self.tools_available = self.enabled and (
            self.qemu_exe is not None or self.allow_mutation_only
        )
        if not self.tools_available and self.enabled:
            logger.warning("Fuzzing enabled but no executor available; skipping dynamic validation.")

    @staticmethod
    def _resolve_executable(path_or_name: str) -> Optional[str]:
        p = Path(path_or_name)
        if p.is_file() and os.access(p, os.X_OK):
            return str(p.resolve())
        exe = shutil.which(Path(path_or_name).name)
        return exe

    def run(self, firmware_obj: Any, high_risk_funcs: List[str]) -> Dict[str, FuzzingResult]:
        if not self.enabled:
            logger.info("Fuzzing validation disabled")
            return {}

        if not self.tools_available:
            logger.warning("Fuzzing tools not available. Skipping dynamic validation.")
            return {}

        if not high_risk_funcs:
            logger.info("No high-risk functions to fuzz")
            return {}

        to_fuzz = high_risk_funcs[: self.max_functions_to_fuzz]
        if len(high_risk_funcs) > len(to_fuzz):
            logger.info(
                "Fuzzing capped to %s functions (of %s high-risk)",
                len(to_fuzz),
                len(high_risk_funcs),
            )

        logger.info("Starting fuzzing validation for %s functions", len(to_fuzz))
        results: Dict[str, FuzzingResult] = {}
        for func_id in to_fuzz:
            if func_id not in firmware_obj.functions:
                logger.warning("Function %s not found in firmware", func_id)
                continue
            results[func_id] = self._fuzz_function(firmware_obj, func_id)

        total_crashes = sum(r.crashes_found for r in results.values())
        logger.info("Fuzzing validation complete. Total crash signals: %s", total_crashes)
        return results

    def _fuzz_function(self, firmware_obj: Any, func_id: str) -> FuzzingResult:
        return self._run_fuzzing(firmware_obj, func_id)

    def _ensure_qemu_smoke(self) -> bool:
        if self._qemu_checked:
            return self._qemu_works
        self._qemu_checked = True
        if not self.qemu_exe:
            self._qemu_works = False
            return False
        try:
            r = subprocess.run(
                [self.qemu_exe, "-machine", "help"],
                capture_output=True,
                timeout=15,
                text=False,
            )
            out = (r.stdout or b"") + (r.stderr or b"")
            # `-machine help` exits 0 even when esp32 is not listed; require the name in the list.
            self._qemu_works = b"esp32" in out.lower()
            if not self._qemu_works:
                logger.warning(
                    "QEMU smoke: no 'esp32' machine in `qemu-system-xtensa -machine help`. "
                    "Fuzzing will use mutation + fallback oracle only unless you install ESP32-capable QEMU."
                )
        except (OSError, subprocess.SubprocessError) as e:
            logger.warning("QEMU probe failed: %s", e)
            self._qemu_works = False
        return self._qemu_works

    def _func_region(self, func_info: Dict[str, Any], file_size: int) -> Tuple[int, int]:
        addr_s = str(func_info.get("address", "0x40000000"))
        try:
            addr = int(addr_s, 16) if addr_s.startswith("0x") else int(addr_s, 16)
        except ValueError:
            addr = 0x40000000
        base = int(self.fuzzing_config.get("flash_load_address", "0x40000000"), 16)
        off = max(0, min(addr - base, max(0, file_size - 1)))
        span = int(func_info.get("size", 256) or 256)
        end = min(file_size, off + max(span, 1))
        if end <= off:
            end = min(file_size, off + 1)
        return off, end

    def _mutate(self, data: bytes, region: Tuple[int, int], seed: int) -> bytes:
        rng = random.Random(seed)
        buf = bytearray(data)
        start, end = region
        if end <= start:
            end = min(len(buf), start + 1)
        width = end - start
        flips = max(1, min(width, rng.randint(1, min(16, width))))
        for _ in range(flips):
            pos = rng.randint(start, end - 1)
            buf[pos] = (buf[pos] ^ (1 << rng.randint(0, 7))) & 0xFF
        return bytes(buf)

    _ESP_FLASH_SIZES = (2 * 1024 * 1024, 4 * 1024 * 1024, 8 * 1024 * 1024, 16 * 1024 * 1024)

    def _pad_esp_flash_image(self, data: bytes) -> bytes:
        """Espressif QEMU accepts only 2/4/8/16 MiB raw SPI flash images; pad with 0xFF (erased flash)."""
        if not self.fuzzing_config.get("esp_flash_pad", True):
            return data
        if len(data) > self._ESP_FLASH_SIZES[-1]:
            data = data[: self._ESP_FLASH_SIZES[-1]]
        for sz in self._ESP_FLASH_SIZES:
            if len(data) <= sz:
                return data + (b"\xff" * (sz - len(data)))
        return data

    def _qemu_run(self, image_path: Path) -> Tuple[str, Optional[int], bytes]:
        """Returns (status, signal_number_or_None, combined_output_bytes)."""
        if not self.qemu_exe:
            return "no_qemu", None, b""
        raw = Path(image_path).read_bytes()
        padded = self._pad_esp_flash_image(raw)
        run_path: Path = Path(image_path)
        cleanup: Optional[Path] = None
        if padded != raw:
            tmp = tempfile.NamedTemporaryFile(
                dir=Path(image_path).parent,
                suffix=".espflash.bin",
                delete=False,
            )
            tmp.write(padded)
            tmp.close()
            run_path = Path(tmp.name)
            cleanup = run_path
        cmd = [
            self.qemu_exe,
            "-nographic",
            "-machine",
            self.qemu_machine,
            "-drive",
            f"file={run_path},if=mtd,format=raw",
            "-serial",
            "null",
            "-monitor",
            "none",
        ]
        try:
            r = subprocess.run(
                cmd,
                capture_output=True,
                timeout=self.qemu_timeout_sec,
            )
            out = (r.stdout or b"") + (r.stderr or b"")
            low = out.lower()
            if any(m in low for m in _FATAL_MARKERS):
                return "guest_fault", None, out
            if r.returncode < 0:
                return "signal", -r.returncode, out
            if r.returncode != 0:
                return "nonzero_exit", r.returncode, out
            return "clean_exit", None, out
        except subprocess.TimeoutExpired as e:
            out = (e.stdout or b"") + (e.stderr or b"")
            return "timeout", None, out
        finally:
            if cleanup is not None:
                try:
                    cleanup.unlink(missing_ok=True)
                except OSError:
                    pass

    @staticmethod
    def _severity(status: str) -> int:
        order = {
            "no_qemu": 0,
            "clean_exit": 1,
            "timeout": 2,
            "nonzero_exit": 3,
            "signal": 4,
            "guest_fault": 5,
        }
        return order.get(status, 0)

    def _qemu_regression(
        self, baseline_status: str, cur_status: str, base_out: bytes, cur_out: bytes
    ) -> bool:
        """True if mutated run looks strictly worse than baseline (likely crash / new fault)."""
        if self._severity(cur_status) > self._severity(baseline_status):
            return True
        if cur_status == baseline_status == "guest_fault" and base_out[:512] != cur_out[:512]:
            return True
        if cur_status == "nonzero_exit" and baseline_status == "timeout":
            return True
        return False

    def _fallback_crash(self, original: bytes, mutated: bytes) -> bool:
        if self.fallback_oracle == "none":
            return False
        if self.fallback_oracle == "esp_image":
            window = min(len(original), 65536)
            if window < 32:
                return False
            # Common Espressif packed images use 0xE9 segment markers in the first blocks.
            had = b"\xe9" in original[:window]
            has = b"\xe9" in mutated[:window]
            return had and not has
        return False

    def _run_fuzzing(self, firmware_obj: Any, func_id: str) -> FuzzingResult:
        fw_path = Path(firmware_obj.path)
        if not fw_path.is_file():
            return FuzzingResult(
                func_id=func_id,
                crashes_found=0,
                coverage=0.0,
                execution_time=0.0,
                unique_crashes=0,
                timeout_reached=False,
                details={"error": "firmware path missing"},
            )

        raw = fw_path.read_bytes()
        if not raw:
            return FuzzingResult(
                func_id=func_id,
                crashes_found=0,
                coverage=0.0,
                execution_time=0.0,
                unique_crashes=0,
                timeout_reached=False,
                details={"error": "empty firmware"},
            )

        func_info = firmware_obj.functions.get(func_id, {})
        region = self._func_region(func_info, len(raw))
        use_qemu = self._ensure_qemu_smoke()

        crashes = 0
        unique_sigs: Set[str] = set()
        timeouts = 0
        qemu_runs = 0
        t0 = time.time()
        completed = 0
        baseline_status = "skipped"
        baseline_out = b""

        if use_qemu:
            with tempfile.NamedTemporaryFile(
                dir=fw_path.parent, suffix=".fuzz.base.bin", delete=False
            ) as tmp_b:
                tmp_b.write(raw)
                base_path = Path(tmp_b.name)
            try:
                qemu_runs += 1
                baseline_status, _, baseline_out = self._qemu_run(base_path)
            finally:
                try:
                    base_path.unlink(missing_ok=True)
                except OSError:
                    pass

        for i in range(self.mutations_per_function):
            if crashes >= self.max_crashes:
                break
            seed = (hash(func_id) ^ hash(fw_path.name) ^ i) & 0xFFFFFFFF
            mutated = self._mutate(raw, region, seed)

            if use_qemu:
                with tempfile.NamedTemporaryFile(
                    dir=fw_path.parent, suffix=".fuzz.bin", delete=False
                ) as tmp:
                    tmp.write(mutated)
                    tmp_path = Path(tmp.name)
                try:
                    qemu_runs += 1
                    status, _sig, out = self._qemu_run(tmp_path)
                    if status == "timeout":
                        timeouts += 1
                    regressed = self._qemu_regression(
                        baseline_status, status, baseline_out, out
                    )
                    if regressed:
                        crashes += 1
                        unique_sigs.add(f"{status}:{hash(out[:2048])}")
                    elif self._fallback_crash(raw, mutated):
                        crashes += 1
                        unique_sigs.add("esp_magic_loss")
                finally:
                    try:
                        tmp_path.unlink(missing_ok=True)
                    except OSError:
                        pass
            else:
                if self._fallback_crash(raw, mutated):
                    crashes += 1
                    unique_sigs.add("esp_magic_loss")
            completed += 1

        elapsed = time.time() - t0
        coverage = float(
            min(100.0, completed * (100.0 / max(1, self.mutations_per_function)))
        )

        details: Dict[str, Any] = {
            "mode": "mutate_qemu" if use_qemu else "mutate_fallback",
            "baseline_qemu_status": baseline_status,
            "region": {"start": region[0], "end": region[1]},
            "mutations_planned": self.mutations_per_function,
            "mutations_completed": completed,
            "qemu_runs": qemu_runs,
            "qemu_timeouts": timeouts,
            "fallback_oracle": self.fallback_oracle,
        }

        return FuzzingResult(
            func_id=func_id,
            crashes_found=crashes,
            coverage=coverage,
            execution_time=elapsed,
            unique_crashes=len(unique_sigs),
            timeout_reached=timeouts > self.mutations_per_function // 2,
            details=details,
        )
