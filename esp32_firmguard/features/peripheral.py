"""Peripheral-aware feature extraction (I/O, UART, SPI, WiFi, etc.)"""

import logging
from typing import Dict, Any, List
import pandas as pd
import numpy as np

logger = logging.getLogger(__name__)


class PeripheralFeatureExtractor:
    """Extract peripheral and I/O related features"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.feature_config = config.get("features", {}).get("peripheral", {})
        self.io_patterns = self.feature_config.get("io_patterns", [
            "uart", "spi", "i2c", "gpio", "wifi", "bluetooth"
        ])
    
    def extract(self, firmware_obj) -> pd.DataFrame:
        """
        Extract peripheral-related features for each function.
        
        Returns:
            DataFrame with rows=functions, columns=peripheral features
        """
        functions = firmware_obj.functions
        if not functions:
            logger.warning("No functions found in firmware object")
            return pd.DataFrame()
        
        features = []
        
        for func_id, func_info in functions.items():
            func_features = self._extract_peripheral_features(func_id, func_info)
            features.append(func_features)
        
        df = pd.DataFrame(features)
        df.set_index('func_id', inplace=True)
        
        logger.info(f"Extracted peripheral features for {len(features)} functions")
        return df
    
    def _extract_peripheral_features(self, func_id: str, func_info: Dict[str, Any]) -> Dict[str, Any]:
        """Extract peripheral features for a single function"""
        func_name = func_info.get("name", "").lower()
        calls = [c.lower() for c in func_info.get("calls", [])]
        strings = [s.lower() for s in func_info.get("strings", [])]
        
        features = {"func_id": func_id}
        
        # Check for peripheral-related patterns in function name
        for pattern in self.io_patterns:
            features[f"name_contains_{pattern}"] = 1 if pattern in func_name else 0
        
        # Check for peripheral-related strings
        for pattern in self.io_patterns:
            features[f"string_contains_{pattern}"] = 1 if any(pattern in s for s in strings) else 0
        
        # Check for peripheral-related function calls
        peripheral_calls = {
            "uart": ["uart_read", "uart_write", "uart_init", "uart_send", "uart_recv"],
            "spi": ["spi_transfer", "spi_init", "spi_write", "spi_read"],
            "i2c": ["i2c_write", "i2c_read", "i2c_init", "i2c_master_write"],
            "gpio": ["gpio_set", "gpio_get", "gpio_config", "gpio_reset"],
            "wifi": ["wifi_init", "wifi_connect", "wifi_send", "wifi_recv", "wifi_config"],
            "bluetooth": ["bt_init", "bt_send", "bt_recv", "ble_init"]
        }
        
        for pattern, call_list in peripheral_calls.items():
            matches = sum(1 for c in calls if any(periph_call in c for periph_call in call_list))
            features[f"calls_{pattern}"] = matches
        
        # I/O intensity score
        io_score = sum(features.get(f"calls_{p}", 0) for p in self.io_patterns)
        features["io_intensity"] = io_score
        
        # Network-related features
        network_patterns = ["wifi", "bluetooth", "http", "tcp", "udp", "socket"]
        features["is_network_function"] = 1 if any(
            p in func_name or any(p in s for s in strings) or any(p in c for c in calls)
            for p in network_patterns
        ) else 0
        
        # Input processing features
        input_patterns = ["input", "read", "recv", "receive", "parse", "decode"]
        features["is_input_function"] = 1 if any(
            p in func_name or any(p in s for s in strings)
            for p in input_patterns
        ) else 0
        
        # Output processing features
        output_patterns = ["output", "write", "send", "transmit", "encode"]
        features["is_output_function"] = 1 if any(
            p in func_name or any(p in s for s in strings)
            for p in output_patterns
        ) else 0
        
        return features


