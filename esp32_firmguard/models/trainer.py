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
    from sklearn.model_selection import train_test_split
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    train_test_split = None  # type: ignore


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
        
        # Remove CWE features from training (to force model to learn from other features)
        cwe_cols = [col for col in feature_matrix.columns 
                    if col.startswith('CWE-') or col in ['has_cwe', 'num_cwe_labels'] 
                    or col.startswith('cwe_')]
        if cwe_cols:
            logger.info(f"Removing {len(cwe_cols)} CWE features from training: {cwe_cols[:5]}...")
            feature_matrix = feature_matrix.drop(columns=cwe_cols, errors='ignore')
        
        # Split data (shuffled; stratify when both classes exist)
        stratify = None
        if SKLEARN_AVAILABLE and train_test_split is not None:
            y = labels.reindex(feature_matrix.index).fillna(0).astype(int)
            n_pos = int((y == 1).sum())
            n_neg = int((y == 0).sum())
            if n_pos >= 2 and n_neg >= 2:
                stratify = y
            train_features, val_features, train_labels, val_labels = train_test_split(
                feature_matrix,
                y,
                test_size=validation_split,
                random_state=42,
                stratify=stratify,
            )
        else:
            n_train = int(len(feature_matrix) * (1 - validation_split))
            train_features = feature_matrix.iloc[:n_train]
            train_labels = labels.reindex(feature_matrix.index).iloc[:n_train]
            val_features = feature_matrix.iloc[n_train:]
            val_labels = labels.reindex(feature_matrix.index).iloc[n_train:]
        
        # Train model - prefer XGBoost, fallback to sklearn
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
        # Calculate class weights for imbalanced dataset
        n_positive = (train_labels == 1).sum()
        n_negative = (train_labels == 0).sum()
        scale_pos_weight = n_negative / n_positive if n_positive > 0 else 1.0
        
        logger.info(f"Class distribution: {n_positive} positive, {n_negative} negative")
        logger.info(f"Using scale_pos_weight: {scale_pos_weight:.3f}")
        
        # Get scale_pos_weight from config or calculate
        config_scale = self.model_config.get("scale_pos_weight", "auto")
        if config_scale == "auto" or config_scale is None:
            final_scale = scale_pos_weight
        else:
            final_scale = float(config_scale)
        
        params = {
            "n_estimators": self.model_config.get("n_estimators", 200),
            "max_depth": self.model_config.get("max_depth", 8),
            "learning_rate": self.model_config.get("learning_rate", 0.05),
            "scale_pos_weight": final_scale,
            "subsample": self.model_config.get("subsample", 0.8),
            "colsample_bytree": self.model_config.get("colsample_bytree", 0.8),
            "min_child_weight": self.model_config.get("min_child_weight", 1),
            "gamma": self.model_config.get("gamma", 0.1),
            "reg_alpha": self.model_config.get("reg_alpha", 0.1),
            "reg_lambda": self.model_config.get("reg_lambda", 1.0),
            "objective": "binary:logistic",
            "eval_metric": "logloss",
            "random_state": 42
        }
        
        # Cost-sensitive learning: False negatives are more expensive
        # Vulnerable (1) samples get higher weight to reduce FN
        sample_weights = np.ones(len(train_labels))
        fn_cost_multiplier = self.model_config.get("fn_cost_multiplier", 5.0)  # FN 5x more expensive
        sample_weights[train_labels == 1] = fn_cost_multiplier
        
        logger.info(f"Using cost-sensitive learning: FN cost multiplier = {fn_cost_multiplier}")
        
        model = xgb.XGBClassifier(**params)
        model.fit(
            train_features,
            train_labels,
            sample_weight=sample_weights,  # Cost-sensitive learning
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

