"""Tests for feature extraction"""

import pytest
import pandas as pd
from pathlib import Path

from esp32_firmguard.ingestion.extractor import FirmwareExtractor
from esp32_firmguard.features.structural import StructuralFeatureExtractor
from esp32_firmguard.features.peripheral import PeripheralFeatureExtractor
from esp32_firmguard.features.embeddings import EmbeddingFeatureExtractor


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


def test_structural_features(sample_firmware):
    """Test structural feature extraction"""
    config = {
        "features": {
            "structural": {
                "enabled": True
            }
        }
    }
    extractor = StructuralFeatureExtractor(config)
    
    features = extractor.extract(sample_firmware)
    
    assert isinstance(features, pd.DataFrame)
    assert len(features) > 0
    assert "function_size" in features.columns
    assert "instruction_count" in features.columns
    assert "entropy" in features.columns


def test_peripheral_features(sample_firmware):
    """Test peripheral feature extraction"""
    config = {
        "features": {
            "peripheral": {
                "enabled": True,
                "io_patterns": ["uart", "spi", "wifi"]
            }
        }
    }
    extractor = PeripheralFeatureExtractor(config)
    
    features = extractor.extract(sample_firmware)
    
    assert isinstance(features, pd.DataFrame)
    assert len(features) > 0
    assert "io_intensity" in features.columns


def test_embedding_features(sample_firmware):
    """Test embedding feature extraction"""
    config = {
        "features": {
            "embeddings": {
                "enabled": True,
                "model_name": "gpt-4"
            }
        }
    }
    extractor = EmbeddingFeatureExtractor(config)
    
    features = extractor.extract(sample_firmware)
    
    assert isinstance(features, pd.DataFrame)
    assert len(features) > 0
    # Check for embedding dimensions
    embedding_cols = [col for col in features.columns if col.startswith("embedding_")]
    assert len(embedding_cols) > 0

