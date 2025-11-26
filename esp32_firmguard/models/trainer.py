"""Model training for vulnerability prediction"""

import logging
from typing import Dict, Any, Optional
import pandas as pd
import numpy as np
from pathlib import Path
import pickle

logger = logging.getLogger(__name__)

try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False

try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.linear_model import LogisticRegression
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


class ModelTrainer:
    """Train vulnerability prediction models"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.model_config = config.get("model", {})
        self.model_type = self.model_config.get("type", "xgboost")
        self.model_output_dir = Path(config.get("paths", {}).get("model_output", "./output/models"))
        self.model_output_dir.mkdir(parents=True, exist_ok=True)
        
        self.model = None
    
    def train(
        self,
        feature_matrix: pd.DataFrame,
        labels: pd.Series,
        validation_split: float = 0.2
    ) -> Dict[str, float]:
        """
        Train the vulnerability prediction model.
        
        Args:
            feature_matrix: Feature matrix (functions x features)
            labels: Binary labels (1=vulnerable, 0=safe)
            validation_split: Fraction of data to use for validation
        
        Returns:
            Dictionary with training metrics
        """
        logger.info(f"Training {self.model_type} model on {len(feature_matrix)} samples")
        
        # Split data
        n_train = int(len(feature_matrix) * (1 - validation_split))
        train_features = feature_matrix.iloc[:n_train]
        train_labels = labels.iloc[:n_train]
        val_features = feature_matrix.iloc[n_train:]
        val_labels = labels.iloc[n_train:]
        
        # Train model - prefer XGBoost, fallback to sklearn, then mock
        if self.model_type == "xgboost" and XGBOOST_AVAILABLE:
            self.model = self._train_xgboost(train_features, train_labels, val_features, val_labels)
        elif self.model_type in ["random_forest", "rf"] and SKLEARN_AVAILABLE:
            self.model = self._train_random_forest(train_features, train_labels, val_features, val_labels)
        elif SKLEARN_AVAILABLE:
            # Default to RandomForest if sklearn available
            logger.info("XGBoost not available. Using RandomForest classifier.")
            self.model = self._train_random_forest(train_features, train_labels, val_features, val_labels)
        else:
            # Last resort: use rule-based model
            logger.warning("No ML library available. Using rule-based model.")
            self.model = self._train_rule_based_model(train_features, train_labels)
        
        # Evaluate
        if hasattr(self.model, 'predict_proba'):
            train_pred = self.model.predict_proba(train_features)[:, 1]
            val_pred = self.model.predict_proba(val_features)[:, 1]
        else:
            train_pred = self._rule_based_predict_proba(train_features)[:, 1]
            val_pred = self._rule_based_predict_proba(val_features)[:, 1]
        
        train_acc = np.mean((train_pred > 0.5) == train_labels)
        val_acc = np.mean((val_pred > 0.5) == val_labels)
        
        metrics = {
            "train_accuracy": float(train_acc),
            "validation_accuracy": float(val_acc),
            "train_samples": len(train_features),
            "validation_samples": len(val_features)
        }
        
        logger.info(f"Training complete. Validation accuracy: {val_acc:.3f}")
        return metrics
    
    def _train_xgboost(
        self,
        train_features: pd.DataFrame,
        train_labels: pd.Series,
        val_features: pd.DataFrame,
        val_labels: pd.Series
    ) -> xgb.XGBClassifier:
        """Train XGBoost model"""
        params = {
            "n_estimators": self.model_config.get("n_estimators", 100),
            "max_depth": self.model_config.get("max_depth", 6),
            "learning_rate": self.model_config.get("learning_rate", 0.1),
            "objective": "binary:logistic",
            "eval_metric": "logloss",
            "random_state": 42
        }
        
        model = xgb.XGBClassifier(**params)
        model.fit(
            train_features,
            train_labels,
            eval_set=[(val_features, val_labels)],
            verbose=False
        )
        
        return model
    
    def _train_random_forest(
        self,
        train_features: pd.DataFrame,
        train_labels: pd.Series,
        val_features: pd.DataFrame,
        val_labels: pd.Series
    ) -> RandomForestClassifier:
        """Train RandomForest model (fallback when XGBoost not available)"""
        n_estimators = self.model_config.get("n_estimators", 100)
        max_depth = self.model_config.get("max_depth", 6)
        
        model = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            random_state=42,
            n_jobs=-1
        )
        model.fit(train_features, train_labels)
        return model
    
    def _train_rule_based_model(self, train_features: pd.DataFrame, train_labels: pd.Series) -> Dict[str, Any]:
        """Train a rule-based model (last resort when no ML libraries available)"""
        # Calculate feature importance based on correlation with labels
        correlations = train_features.corrwith(train_labels).abs().sort_values(ascending=False)
        top_features = correlations.head(10).index.tolist()
        
        # Calculate thresholds for each feature
        feature_thresholds = {}
        for feat in top_features[:5]:  # Use top 5 features
            if feat in train_features.columns:
                vulnerable_mean = train_features[train_labels == 1][feat].mean()
                safe_mean = train_features[train_labels == 0][feat].mean()
                feature_thresholds[feat] = (vulnerable_mean + safe_mean) / 2
        
        rule_model = {
            "type": "rule_based",
            "top_features": top_features,
            "feature_thresholds": feature_thresholds,
            "mean_label": float(train_labels.mean()),
            "feature_means": train_features.mean().to_dict()
        }
        
        return rule_model
    
    def _rule_based_predict_proba(self, features: pd.DataFrame) -> np.ndarray:
        """Rule-based prediction probabilities"""
        if isinstance(self.model, dict) and self.model.get("type") == "rule_based":
            scores = np.zeros(len(features))
            thresholds = self.model.get("feature_thresholds", {})
            
            # Use threshold-based scoring
            for feat, threshold in thresholds.items():
                if feat in features.columns:
                    # Higher value = more likely vulnerable (if correlation is positive)
                    scores += (features[feat].values > threshold).astype(float) * 0.2
            
            # Normalize to probabilities using sigmoid
            scores = 1 / (1 + np.exp(-scores))
            return np.column_stack([1 - scores, scores])
        
        # Fallback: use feature correlations
        if isinstance(self.model, dict):
            scores = np.zeros(len(features))
            top_features = self.model.get("top_features", [])[:5]
            for feat in top_features:
                if feat in features.columns:
                    scores += features[feat].values * 0.2
            
            scores = 1 / (1 + np.exp(-scores))
            return np.column_stack([1 - scores, scores])
        
        # Last resort: random probabilities
        return np.random.rand(len(features), 2)
    
    def save_model(self, model_name: str = "vulnerability_model.pkl") -> Path:
        """Save trained model to disk"""
        model_path = self.model_output_dir / model_name
        
        if isinstance(self.model, dict):
            # Save mock model as pickle
            with open(model_path, 'wb') as f:
                pickle.dump(self.model, f)
        else:
            # Save XGBoost model
            if hasattr(self.model, 'save_model'):
                self.model.save_model(str(model_path))
            else:
                with open(model_path, 'wb') as f:
                    pickle.dump(self.model, f)
        
        logger.info(f"Saved model to {model_path}")
        return model_path
    
    def load_model(self, model_path: Path):
        """Load trained model from disk"""
        model_path = Path(model_path)
        
        if not model_path.exists():
            raise FileNotFoundError(f"Model not found: {model_path}")
        
        # Try loading as XGBoost first
        if XGBOOST_AVAILABLE and model_path.suffix == '.pkl':
            try:
                with open(model_path, 'rb') as f:
                    model = pickle.load(f)
                    if isinstance(model, dict):
                        self.model = model
                    else:
                        # Try loading as XGBoost
                        self.model = xgb.XGBClassifier()
                        self.model.load_model(str(model_path))
            except:
                # Fallback to pickle
                with open(model_path, 'rb') as f:
                    self.model = pickle.load(f)
        else:
            with open(model_path, 'rb') as f:
                self.model = pickle.load(f)
        
        logger.info(f"Loaded model from {model_path}")
        return self.model

