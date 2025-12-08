#!/usr/bin/env python3
"""Train ensemble model (XGBoost + RandomForest + CWE-free model)"""

import sys
from pathlib import Path
import json
import pandas as pd
import numpy as np
from typing import Dict, Any, List
import argparse
import pickle

sys.path.insert(0, str(Path(__file__).parent.parent))

from esp32_firmguard.utils import load_config, setup_logging
from esp32_firmguard.models.dataset import DatasetBuilder
from esp32_firmguard.models.trainer import ModelTrainer
import xgboost as xgb

try:
    from sklearn.ensemble import RandomForestClassifier
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


class EnsembleModel:
    """Ensemble of multiple models"""
    
    def __init__(self, models: List[Any], weights: List[float]):
        self.models = models
        self.weights = np.array(weights) / sum(weights)  # Normalize weights
    
    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        """Weighted average of model predictions"""
        predictions = []
        for model in self.models:
            if hasattr(model, 'predict_proba'):
                pred = model.predict_proba(X)[:, 1]
            else:
                # Fallback to predict
                pred = model.predict(X).astype(float)
            predictions.append(pred)
        
        # Weighted average
        predictions = np.array(predictions)
        weighted_pred = np.average(predictions, axis=0, weights=self.weights)
        
        # Return in sklearn format
        return np.column_stack([1 - weighted_pred, weighted_pred])


def train_ensemble(
    feature_matrix: pd.DataFrame,
    labels: pd.Series,
    config: Dict[str, Any]
) -> EnsembleModel:
    """Train ensemble model"""
    print("=" * 80)
    print("ENSEMBLE MODEL TRAINING")
    print("=" * 80)
    print()
    
    # Split data
    n_train = int(len(feature_matrix) * 0.8)
    train_features = feature_matrix.iloc[:n_train]
    train_labels = labels.iloc[:n_train]
    val_features = feature_matrix.iloc[n_train:]
    val_labels = labels.iloc[n_train:]
    
    models = []
    weights = []
    
    # Model 1: XGBoost with all features (including CWE)
    print("Training Model 1: XGBoost (all features)...")
    n_positive = (train_labels == 1).sum()
    n_negative = (train_labels == 0).sum()
    scale_pos_weight = n_negative / n_positive if n_positive > 0 else 1.0
    
    model1 = xgb.XGBClassifier(
        n_estimators=200,
        max_depth=8,
        learning_rate=0.05,
        scale_pos_weight=scale_pos_weight,
        subsample=0.8,
        colsample_bytree=0.8,
        min_child_weight=1,
        gamma=0.1,
        reg_alpha=0.1,
        reg_lambda=1.0,
        objective='binary:logistic',
        eval_metric='logloss',
        random_state=42
    )
    model1.fit(train_features, train_labels)
    
    # Evaluate
    val_pred1 = model1.predict_proba(val_features)[:, 1]
    from sklearn.metrics import f1_score
    val_pred_binary1 = (val_pred1 > 0.5).astype(int)
    f1_1 = f1_score(val_labels, val_pred_binary1)
    print(f"  Validation F1: {f1_1:.4f}")
    models.append(model1)
    weights.append(f1_1)
    
    # Model 2: XGBoost without CWE features
    print("\nTraining Model 2: XGBoost (without CWE features)...")
    cwe_cols = [c for c in feature_matrix.columns if c.startswith('CWE-') or c in ['has_cwe', 'num_cwe_labels']]
    interaction_cols = [c for c in feature_matrix.columns if 'cwe_' in c]
    cols_to_remove = cwe_cols + interaction_cols
    
    train_features_no_cwe = train_features.drop(columns=cols_to_remove, errors='ignore')
    val_features_no_cwe = val_features.drop(columns=cols_to_remove, errors='ignore')
    
    model2 = xgb.XGBClassifier(
        n_estimators=300,  # More trees to compensate for fewer features
        max_depth=10,
        learning_rate=0.03,
        scale_pos_weight=scale_pos_weight * 1.5,  # Higher weight since no CWE
        subsample=0.8,
        colsample_bytree=0.8,
        min_child_weight=1,
        gamma=0.2,
        reg_alpha=0.2,
        reg_lambda=1.5,
        objective='binary:logistic',
        eval_metric='logloss',
        random_state=42
    )
    model2.fit(train_features_no_cwe, train_labels)
    
    # Evaluate
    val_pred2 = model2.predict_proba(val_features_no_cwe)[:, 1]
    val_pred_binary2 = (val_pred2 > 0.5).astype(int)
    f1_2 = f1_score(val_labels, val_pred_binary2)
    print(f"  Validation F1: {f1_2:.4f}")
    models.append(model2)
    weights.append(f1_2)
    
    # Model 3: RandomForest (if available)
    if SKLEARN_AVAILABLE:
        print("\nTraining Model 3: RandomForest...")
        model3 = RandomForestClassifier(
            n_estimators=200,
            max_depth=15,
            min_samples_split=5,
            min_samples_leaf=2,
            class_weight='balanced',
            random_state=42,
            n_jobs=-1
        )
        model3.fit(train_features, train_labels)
        
        # Evaluate
        val_pred3 = model3.predict_proba(val_features)[:, 1]
        val_pred_binary3 = (val_pred3 > 0.5).astype(int)
        f1_3 = f1_score(val_labels, val_pred_binary3)
        print(f"  Validation F1: {f1_3:.4f}")
        models.append(model3)
        weights.append(f1_3)
    
    # Create ensemble
    ensemble = EnsembleModel(models, weights)
    
    # Evaluate ensemble
    print("\nEvaluating Ensemble Model...")
    ensemble_pred = ensemble.predict_proba(val_features)[:, 1]
    ensemble_pred_binary = (ensemble_pred > 0.5).astype(int)
    ensemble_f1 = f1_score(val_labels, ensemble_pred_binary)
    print(f"  Ensemble Validation F1: {ensemble_f1:.4f}")
    
    print()
    print("=" * 80)
    print("ENSEMBLE SUMMARY")
    print("=" * 80)
    print(f"Model 1 (XGBoost all features): F1 = {f1_1:.4f}, Weight = {weights[0]/sum(weights):.2%}")
    print(f"Model 2 (XGBoost no CWE): F1 = {f1_2:.4f}, Weight = {weights[1]/sum(weights):.2%}")
    if SKLEARN_AVAILABLE:
        print(f"Model 3 (RandomForest): F1 = {f1_3:.4f}, Weight = {weights[2]/sum(weights):.2%}")
    print(f"Ensemble: F1 = {ensemble_f1:.4f}")
    print("=" * 80)
    
    return ensemble, models


def main():
    parser = argparse.ArgumentParser(description="Train ensemble model")
    parser.add_argument("dataset", type=str, help="Path to dataset directory")
    parser.add_argument("-c", "--config", type=str, default="configs/config.yaml",
                       help="Path to config file")
    parser.add_argument("-o", "--output", type=str, default="output/models/ensemble_model.pkl",
                       help="Output path for ensemble model")
    parser.add_argument("--log-level", type=str, default="INFO",
                       choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    
    args = parser.parse_args()
    
    config = load_config(args.config)
    setup_logging(args.log_level)
    
    # Load dataset
    dataset_builder = DatasetBuilder(config)
    feature_matrix, labels = dataset_builder.load_dataset(Path(args.dataset))
    
    print(f"Loaded dataset: {len(feature_matrix)} samples, {len(feature_matrix.columns)} features")
    print(f"Label distribution: {(labels == 1).sum()} positive, {(labels == 0).sum()} negative")
    print()
    
    # Train ensemble
    ensemble, models = train_ensemble(feature_matrix, labels, config)
    
    # Save ensemble
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Save as pickle (ensemble object)
    with open(output_path, 'wb') as f:
        pickle.dump(ensemble, f)
    
    print(f"\nEnsemble model saved to: {output_path}")


if __name__ == "__main__":
    main()

