"""Helper functions for creating test data"""

import json
from pathlib import Path
from typing import Dict


def create_test_firmware(tmp_path: Path, name: str = "test.bin", size: int = 1024) -> Path:
    """Create a test firmware file"""
    firmware_path = tmp_path / name
    firmware_path.write_bytes(b"\x00" * size)
    return firmware_path


def create_ground_truth(
    func_ids: list,
    vulnerable_funcs: list,
    output_path: Path
) -> Dict[str, int]:
    """Create ground truth dictionary"""
    ground_truth = {}
    for func_id in func_ids:
        ground_truth[func_id] = 1 if func_id in vulnerable_funcs else 0
    
    with open(output_path, 'w') as f:
        json.dump(ground_truth, f, indent=2)
    
    return ground_truth


def load_ground_truth(ground_truth_path: Path) -> Dict[str, int]:
    """Load ground truth from JSON file"""
    with open(ground_truth_path, 'r') as f:
        return json.load(f)


