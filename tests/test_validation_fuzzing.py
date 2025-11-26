"""Tests for fuzzing validation"""

import pytest
from pathlib import Path

from esp32_firmguard.ingestion.extractor import FirmwareExtractor
from esp32_firmguard.validation.fuzzing import FuzzingValidator


@pytest.fixture
def sample_firmware(tmp_path):
    """Create a sample firmware object for testing"""
    config = {
        "paths": {
            "analysis_output": str(tmp_path / "out")
        }
    }
    extractor = FirmwareExtractor(config)
    
    fake_fw = tmp_path / "test.bin"
    fake_fw.write_bytes(b"\x00" * 1024)
    
    return extractor.extract(str(fake_fw))


def test_fuzzing_validator(sample_firmware):
    """Test fuzzing validator"""
    config = {
        "validation": {
            "fuzzing": {
                "enabled": True,
                "timeout": 60
            }
        }
    }
    validator = FuzzingValidator(config)
    
    high_risk_funcs = ["func_001", "func_002"]
    results = validator.run(sample_firmware, high_risk_funcs)
    
    assert isinstance(results, dict)
    assert len(results) > 0
    
    for func_id, result in results.items():
        assert hasattr(result, "crashes_found")
        assert hasattr(result, "coverage")
        assert result.coverage >= 0 and result.coverage <= 1

