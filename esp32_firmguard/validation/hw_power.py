"""Hardware power-based validation (INA219 + oscilloscope)"""

import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from pathlib import Path
import numpy as np
import time

from .cnn_analyzer import CNNAnalyzer

logger = logging.getLogger(__name__)


@dataclass
class PowerTraceResult:
    """Results from power trace analysis"""
    func_id: str
    anomaly_score: float
    is_anomaly: bool
    confidence: float
    power_trace: Optional[np.ndarray] = None
    details: Dict[str, Any] = None

    def __post_init__(self):
        if self.details is None:
            self.details = {}


class HardwarePowerValidator:
    """Validate vulnerabilities using hardware power analysis"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.hw_config = config.get("validation", {}).get("hardware", {})
        self.enabled = self.hw_config.get("enabled", True)
        self.ina219_address = self.hw_config.get("ina219_address", 0x40)
        self.oscilloscope_enabled = self.hw_config.get("oscilloscope_enabled", False)
        self.samples = self.hw_config.get("power_trace_samples", 10000)
        
        self.hardware_available = self.hw_config.get("hardware_available", False)
        if not self.hardware_available and self.enabled:
            logger.warning("INA219 sensor and ESP32 hardware not available. Physical validation will be skipped.")
        
        # Initialize CNN analyzer
        self.cnn_analyzer = CNNAnalyzer(config)
        self.cnn_analyzer.load_model()
    
    def run(self, firmware_obj, high_risk_funcs: List[str]) -> Dict[str, PowerTraceResult]:
        """
        Run hardware power validation on high-risk functions using INA219 and CNN.
        
        Args:
            firmware_obj: FirmwareObject to validate
            high_risk_funcs: List of function IDs to analyze
        
        Returns:
            Dictionary mapping func_id -> PowerTraceResult
        """
        if not self.enabled:
            logger.info("Hardware power validation disabled")
            return {}
        
        if not self.hardware_available:
            logger.warning("INA219 sensor and ESP32 hardware not available. Skipping physical validation.")
            return {}
        
        if not self.cnn_analyzer.model_loaded:
            logger.warning("CNN model not loaded. Skipping physical validation.")
            return {}
        
        if not high_risk_funcs:
            logger.info("No high-risk functions to analyze")
            return {}
        
        logger.info(f"Starting hardware power validation for {len(high_risk_funcs)} functions")
        
        results = {}
        
        for func_id in high_risk_funcs:
            if func_id not in firmware_obj.functions:
                logger.warning(f"Function {func_id} not found in firmware")
                continue
            
            result = self._analyze_function_power(firmware_obj, func_id)
            results[func_id] = result
        
        anomalies = sum(1 for r in results.values() if r.is_anomaly)
        logger.info(f"Hardware validation complete. Found {anomalies} anomalies out of {len(results)} functions")
        
        return results
    
    def _analyze_function_power(self, firmware_obj, func_id: str) -> PowerTraceResult:
        """Analyze power consumption for a function using INA219 and CNN"""
        if not self.hardware_available:
            raise RuntimeError("INA219 sensor and ESP32 hardware required. Set hardware_available: true in config.")
        
        if not self.cnn_analyzer.model_loaded:
            raise RuntimeError("CNN model required for power trace analysis. Train and load model first.")
        
        return self._read_power_trace(firmware_obj, func_id)
    
    def _read_power_trace(self, firmware_obj, func_id: str) -> PowerTraceResult:
        """Read power trace from INA219 sensor and analyze with CNN"""
        func_info = firmware_obj.functions.get(func_id, {})
        func_name = func_info.get("name", "")
        
        # Read power trace from INA219 sensor
        power_trace = self._read_ina219_trace(func_id)
        
        # Analyze using CNN
        analysis = self.cnn_analyzer.analyze(power_trace)
        
        return PowerTraceResult(
            func_id=func_id,
            anomaly_score=analysis["anomaly_score"],
            is_anomaly=analysis["is_anomaly"],
            confidence=analysis["confidence"],
            power_trace=power_trace,
            details={
                "function_name": func_name,
                "mean_power": float(np.mean(power_trace)),
                "std_power": float(np.std(power_trace)),
                "max_power": float(np.max(power_trace)),
                "min_power": float(np.min(power_trace))
            }
        )
    
    def _read_ina219_trace(self, func_id: str) -> np.ndarray:
        """Read power trace from INA219 sensor"""
        raise NotImplementedError("INA219 sensor integration required. See documentation for hardware setup.")


