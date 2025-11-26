"""End-to-end pipeline tests"""

import pytest
from pathlib import Path

from esp32_firmguard.utils import load_config
from esp32_firmguard.pipeline import FirmwareSecurityPipeline


def test_pipeline_static_stage(tmp_path):
    """Test static analysis stage of pipeline"""
    config = {
        "paths": {
            "analysis_output": str(tmp_path / "out"),
            "model_output": str(tmp_path / "models")
        },
        "features": {
            "structural": {"enabled": True},
            "peripheral": {"enabled": True},
            "embeddings": {"enabled": True}
        },
        "llm": {
            "provider": "openai",
            "cwe_categories": ["CWE-120", "CWE-79"]
        },
        "model": {
            "threshold": 0.7
        }
    }
    
    pipeline = FirmwareSecurityPipeline(config)
    
    # Create fake firmware
    fake_fw = tmp_path / "test.bin"
    fake_fw.write_bytes(b"\x00" * 1024)
    
    # Run static stage
    fw, feature_matrix, predictions, cwe_labels = pipeline.run_static_stage(
        str(fake_fw),
        source="test"
    )
    
    assert fw is not None
    assert len(feature_matrix) > 0
    assert len(predictions) > 0
    assert len(cwe_labels) > 0


def test_pipeline_full(tmp_path):
    """Test full pipeline execution"""
    config = {
        "paths": {
            "analysis_output": str(tmp_path / "out"),
            "model_output": str(tmp_path / "models")
        },
        "features": {
            "structural": {"enabled": True},
            "peripheral": {"enabled": True},
            "embeddings": {"enabled": True}
        },
        "llm": {
            "provider": "openai",
            "cwe_categories": ["CWE-120"]
        },
        "model": {
            "threshold": 0.7
        },
        "validation": {
            "fuzzing": {"enabled": True},
            "hardware": {"enabled": True}
        }
    }
    
    pipeline = FirmwareSecurityPipeline(config)
    
    # Create fake firmware
    fake_fw = tmp_path / "test.bin"
    fake_fw.write_bytes(b"\x00" * 1024)
    
    # Run full pipeline
    results = pipeline.run_full_pipeline(
        firmware_path=str(fake_fw),
        source="test",
        run_validation=True,
        run_evaluation=False
    )
    
    assert "firmware" in results
    assert "predictions" in results
    assert "fuzz_results" in results
    assert "hw_results" in results

