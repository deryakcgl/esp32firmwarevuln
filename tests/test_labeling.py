"""Tests for CWE labeling"""

import pytest
from pathlib import Path

from esp32_firmguard.ingestion.extractor import FirmwareExtractor
from esp32_firmguard.labeling.cwe_labeler import CWELabeler


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


def test_cwe_labeler(sample_firmware):
    """Test CWE labeling"""
    config = {
        "llm": {
            "provider": "openai",
            "model": "gpt-4",
            "cwe_categories": ["CWE-120", "CWE-79", "CWE-89"]
        }
    }
    labeler = CWELabeler(config)
    
    labels = labeler.label(sample_firmware)
    
    assert isinstance(labels, dict)
    assert len(labels) > 0
    
    # Check that labels are lists
    for func_id, cwe_list in labels.items():
        assert isinstance(cwe_list, list)
        # CWE IDs should start with "CWE-"
        for cwe in cwe_list:
            assert cwe.startswith("CWE-")

