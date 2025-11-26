"""Tests for model training and prediction"""

import pytest
import pandas as pd
import numpy as np
from pathlib import Path

from esp32_firmguard.models.dataset import DatasetBuilder
from esp32_firmguard.models.trainer import ModelTrainer
from esp32_firmguard.models.predictor import VulnerabilityPredictor


def test_dataset_builder():
    """Test dataset building"""
    config = {}
    builder = DatasetBuilder(config)
    
    # Create mock features
    structural = pd.DataFrame({
        "function_size": [100, 200, 300],
        "entropy": [3.5, 4.0, 4.5]
    }, index=["func_1", "func_2", "func_3"])
    
    peripheral = pd.DataFrame({
        "io_intensity": [1, 2, 0]
    }, index=["func_1", "func_2", "func_3"])
    
    embeddings = pd.DataFrame({
        "embedding_0": [0.1, 0.2, 0.3],
        "embedding_1": [0.4, 0.5, 0.6]
    }, index=["func_1", "func_2", "func_3"])
    
    cwe_labels = {
        "func_1": ["CWE-120"],
        "func_2": [],
        "func_3": ["CWE-79"]
    }
    
    feature_matrix = builder.build_feature_matrix(
        structural, peripheral, embeddings, cwe_labels
    )
    
    assert isinstance(feature_matrix, pd.DataFrame)
    assert len(feature_matrix) == 3
    assert "function_size" in feature_matrix.columns
    assert "io_intensity" in feature_matrix.columns


def test_predictor_mock(tmp_path):
    """Test predictor with mock model"""
    config = {
        "model": {
            "threshold": 0.7
        },
        "paths": {
            "model_output": str(tmp_path)
        }
    }
    predictor = VulnerabilityPredictor(config)
    
    # Create mock feature matrix
    feature_matrix = pd.DataFrame({
        "function_size": [100, 200, 300],
        "has_strcpy": [1, 0, 1],
        "has_sprintf": [0, 1, 0]
    }, index=["func_1", "func_2", "func_3"])
    
    cwe_labels = {
        "func_1": ["CWE-120"],
        "func_2": [],
        "func_3": ["CWE-79"]
    }
    
    predictions = predictor.predict(feature_matrix, cwe_labels)
    
    assert len(predictions) == 3
    assert all(hasattr(p, "func_id") for p in predictions)
    assert all(hasattr(p, "score") for p in predictions)
    assert all(0 <= p.score <= 1 for p in predictions)

