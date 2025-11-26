"""Tests for firmware ingestion module"""

import pytest
from pathlib import Path

from esp32_firmguard.ingestion.extractor import FirmwareExtractor
from esp32_firmguard.ingestion.metadata import extract_metadata


def test_extractor_creates_output(tmp_path):
    """Test that extractor creates output directory"""
    config = {
        "paths": {
            "analysis_output": str(tmp_path / "out")
        }
    }
    extractor = FirmwareExtractor(config)
    
    # Create fake firmware file
    fake_fw = tmp_path / "firmware.bin"
    fake_fw.write_bytes(b"\x00" * 1024)
    
    fw_obj = extractor.extract(str(fake_fw))
    
    assert fw_obj.path == fake_fw
    assert fw_obj.disassembly_dir.exists()
    assert len(fw_obj.functions) > 0


def test_extractor_creates_functions(tmp_path):
    """Test that extractor creates function list"""
    config = {
        "paths": {
            "analysis_output": str(tmp_path / "out")
        }
    }
    extractor = FirmwareExtractor(config)
    
    fake_fw = tmp_path / "test.bin"
    fake_fw.write_bytes(b"\x00" * 2048)
    
    fw_obj = extractor.extract(str(fake_fw))
    
    assert len(fw_obj.functions) > 0
    assert "func_001" in fw_obj.functions
    assert "name" in fw_obj.functions["func_001"]


def test_metadata_extraction(tmp_path):
    """Test metadata extraction"""
    fake_fw = tmp_path / "firmware.bin"
    test_data = b"test firmware data" * 100
    fake_fw.write_bytes(test_data)
    
    meta = extract_metadata(fake_fw, source="test")
    
    assert meta.name == "firmware.bin"
    assert meta.size == len(test_data)
    assert meta.source == "test"
    assert len(meta.md5_hash) == 32
    assert len(meta.sha256_hash) == 64

