import logging
import pickle
from pathlib import Path
from typing import Any, Dict

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False

try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    train_test_split = None  # type: ignore


class ModelTrainer:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.model_config = config.get("model", {})
        self.model_type = self.model_config.get("type", "xgboost")
        self.model_output_dir = Path(config.get("paths", {}).get("model_output", "./output/models"))
        self.model_output_dir.mkdir(parents=True, exist_ok=True)
        self.model = None

    def train_on_splits(
        self,
        train_features: pd.DataFrame,
        train_labels: pd.Series,
        val_features: pd.DataFrame,
        val_labels: pd.Series,
    ) -> Dict[str, float]:
        train_features, train_labels, val_features, val_labels = self._drop_cwe_columns(
            train_features, train_labels, val_features, val_labels
        )
        logger.info(
            "Training %s: %d train / %d val",
            self.model_type,
            len(train_features),
            len(val_features),
        )
        if self.model_type == "xgboost" and XGBOOST_AVAILABLE:
            self.model = self._train_xgboost(train_features, train_labels, val_features, val_labels)
        elif SKLEARN_AVAILABLE:
            self.model = self._train_random_forest(train_features, train_labels, val_features, val_labels)
        else:
            self.model = self._train_rule_based_model(train_features, train_labels)

        if hasattr(self.model, "predict_proba"):
            train_pred = self.model.predict_proba(train_features)[:, 1]
            val_pred = self.model.predict_proba(val_features)[:, 1]
        else:
            train_pred = self._rule_based_predict_proba(train_features)[:, 1]
            val_pred = self._rule_based_predict_proba(val_features)[:, 1]

        return {
            "train_accuracy": float(np.mean((train_pred > 0.5) == train_labels)),
            "validation_accuracy": float(np.mean((val_pred > 0.5) == val_labels)),
            "train_samples": len(train_features),
            "validation_samples": len(val_features),
        }

    def _drop_cwe_columns(
        self,
        train_features: pd.DataFrame,
        train_labels: pd.Series,
        val_features: pd.DataFrame,
        val_labels: pd.Series,
    ):
        cwe_cols = [
            col
            for col in train_features.columns
            if col.startswith("CWE-")
            or col in ("has_cwe", "num_cwe_labels")
            or col.startswith("cwe_")
        ]
        if cwe_cols:
            logger.info("Removing %d CWE columns from training", len(cwe_cols))
            train_features = train_features.drop(columns=cwe_cols, errors="ignore")
            val_features = val_features.drop(columns=cwe_cols, errors="ignore")
        return train_features, train_labels, val_features, val_labels

    def train(
        self,
        feature_matrix: pd.DataFrame,
        labels: pd.Series,
        validation_split: float = 0.2,
    ) -> Dict[str, float]:
        y = labels.reindex(feature_matrix.index).fillna(0).astype(int)
        stratify = None
        if SKLEARN_AVAILABLE and train_test_split is not None:
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
            train_labels = y.iloc[:n_train]
            val_features = feature_matrix.iloc[n_train:]
            val_labels = y.iloc[n_train:]

        metrics = self.train_on_splits(train_features, train_labels, val_features, val_labels)
        logger.info("Validation accuracy: %.3f", metrics["validation_accuracy"])
        return metrics

    def _train_xgboost(
        self,
        train_features: pd.DataFrame,
        train_labels: pd.Series,
        val_features: pd.DataFrame,
        val_labels: pd.Series,
    ) -> xgb.XGBClassifier:
        n_positive = (train_labels == 1).sum()
        n_negative = (train_labels == 0).sum()
        scale_pos_weight = n_negative / n_positive if n_positive > 0 else 1.0
        config_scale = self.model_config.get("scale_pos_weight", "auto")
        final_scale = scale_pos_weight if config_scale in ("auto", None) else float(config_scale)

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
            "random_state": 42,
        }
        sample_weights = np.ones(len(train_labels))
        fn_cost = self.model_config.get("fn_cost_multiplier", 5.0)
        sample_weights[train_labels == 1] = fn_cost

        model = xgb.XGBClassifier(**params)
        model.fit(
            train_features,
            train_labels,
            sample_weight=sample_weights,
            eval_set=[(val_features, val_labels)],
            verbose=False,
        )
        return model

    def _train_random_forest(
        self,
        train_features: pd.DataFrame,
        train_labels: pd.Series,
        val_features: pd.DataFrame,
        val_labels: pd.Series,
    ) -> RandomForestClassifier:
        model = RandomForestClassifier(
            n_estimators=self.model_config.get("n_estimators", 100),
            max_depth=self.model_config.get("max_depth", 6),
            random_state=42,
            n_jobs=-1,
        )
        model.fit(train_features, train_labels)
        return model

    def _train_rule_based_model(self, train_features: pd.DataFrame, train_labels: pd.Series) -> Dict[str, Any]:
        correlations = train_features.corrwith(train_labels).abs().sort_values(ascending=False)
        top_features = correlations.head(10).index.tolist()
        feature_thresholds = {}
        for feat in top_features[:5]:
            if feat in train_features.columns:
                v_mean = train_features[train_labels == 1][feat].mean()
                s_mean = train_features[train_labels == 0][feat].mean()
                feature_thresholds[feat] = (v_mean + s_mean) / 2
        return {
            "type": "rule_based",
            "top_features": top_features,
            "feature_thresholds": feature_thresholds,
            "mean_label": float(train_labels.mean()),
            "feature_means": train_features.mean().to_dict(),
        }

    def _rule_based_predict_proba(self, features: pd.DataFrame) -> np.ndarray:
        if isinstance(self.model, dict) and self.model.get("type") == "rule_based":
            scores = np.zeros(len(features))
            for feat, threshold in self.model.get("feature_thresholds", {}).items():
                if feat in features.columns:
                    scores += (features[feat].values > threshold).astype(float) * 0.2
            scores = 1 / (1 + np.exp(-scores))
            return np.column_stack([1 - scores, scores])
        if isinstance(self.model, dict):
            scores = np.zeros(len(features))
            for feat in self.model.get("top_features", [])[:5]:
                if feat in features.columns:
                    scores += features[feat].values * 0.2
            scores = 1 / (1 + np.exp(-scores))
            return np.column_stack([1 - scores, scores])
        return np.random.rand(len(features), 2)

    def save_model(self, model_name: str = "vulnerability_model.pkl") -> Path:
        model_path = self.model_output_dir / model_name
        if isinstance(self.model, dict):
            with open(model_path, "wb") as f:
                pickle.dump(self.model, f)
        elif hasattr(self.model, "save_model"):
            self.model.save_model(str(model_path))
        else:
            with open(model_path, "wb") as f:
                pickle.dump(self.model, f)
        logger.info("Saved model to %s", model_path)
        return model_path

    def load_model(self, model_path: Path):
        model_path = Path(model_path)
        if not model_path.exists():
            raise FileNotFoundError(f"Model not found: {model_path}")
        if XGBOOST_AVAILABLE and model_path.suffix == ".pkl":
            try:
                with open(model_path, "rb") as f:
                    model = pickle.load(f)
                if isinstance(model, dict):
                    self.model = model
                else:
                    self.model = xgb.XGBClassifier()
                    self.model.load_model(str(model_path))
            except Exception:
                with open(model_path, "rb") as f:
                    self.model = pickle.load(f)
        else:
            with open(model_path, "rb") as f:
                self.model = pickle.load(f)
        logger.info("Loaded model from %s", model_path)
        return self.model
