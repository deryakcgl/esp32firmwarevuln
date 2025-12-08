"""CNN-based power trace analysis"""

import logging
from typing import Dict, Any, List, Optional, Tuple
import numpy as np
from pathlib import Path

logger = logging.getLogger(__name__)

try:
    import tensorflow as tf
    TENSORFLOW_AVAILABLE = True
except ImportError:
    TENSORFLOW_AVAILABLE = False


class CNNAnalyzer:
    """Analyze power traces using CNN for anomaly detection"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.model_path = Path(config.get("validation", {}).get("hardware", {}).get("cnn_model_path", "./models/power_cnn.h5"))
        self.model = None
        self.model_loaded = False
    
    def load_model(self) -> None:
        """Load trained CNN model"""
        if not self.model_path.exists():
            logger.warning(f"CNN model not found at {self.model_path}.")
            self.model = None
            self.model_loaded = False
            return
        
        if TENSORFLOW_AVAILABLE:
            try:
                self.model = tf.keras.models.load_model(str(self.model_path))
                self.model_loaded = True
                logger.info(f"Loaded CNN model from {self.model_path}")
            except Exception as e:
                logger.error(f"Failed to load CNN model: {e}")
                self.model = None
                self.model_loaded = False
        else:
            logger.warning("TensorFlow not available for CNN analysis.")
            self.model = None
            self.model_loaded = False
    
    def analyze(self, power_trace: np.ndarray) -> Dict[str, float]:
        """
        Analyze power trace and return anomaly scores.
        
        Args:
            power_trace: 1D array of power measurements
        
        Returns:
            Dictionary with anomaly scores and predictions
        """
        if power_trace is None or len(power_trace) == 0:
            logger.warning("Empty power trace provided")
            return {"anomaly_score": 0.0, "is_anomaly": False, "confidence": 0.0}
        
        if not self.model_loaded:
            raise RuntimeError("CNN model required for power trace analysis. Train and load model first.")
        
        if not TENSORFLOW_AVAILABLE:
            raise RuntimeError("TensorFlow required for CNN analysis. Install: pip install tensorflow")
        
        # Preprocess power trace
        processed = self._preprocess_trace(power_trace)
        
        # Predict using CNN
        prediction = self.model.predict(processed, verbose=0)
        anomaly_score = float(prediction[0][0]) if len(prediction[0]) > 0 else 0.0
        
        return {
            "anomaly_score": anomaly_score,
            "is_anomaly": anomaly_score > 0.5,
            "confidence": abs(anomaly_score - 0.5) * 2
        }
    
    def _preprocess_trace(self, power_trace: np.ndarray) -> np.ndarray:
        """Preprocess power trace for CNN input"""
        # Normalize
        trace = (power_trace - np.mean(power_trace)) / (np.std(power_trace) + 1e-8)
        
        # Reshape for CNN (assuming model expects fixed-size input)
        target_length = 1000
        if len(trace) > target_length:
            # Downsample
            indices = np.linspace(0, len(trace) - 1, target_length, dtype=int)
            trace = trace[indices]
        elif len(trace) < target_length:
            # Pad
            trace = np.pad(trace, (0, target_length - len(trace)), mode='constant')
        
        # Reshape for CNN: (1, length, 1) for 1D CNN
        trace = trace.reshape(1, len(trace), 1)
        
        return trace
    


