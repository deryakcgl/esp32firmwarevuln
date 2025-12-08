#!/usr/bin/env python3
"""Hyperparameter tuning for XGBoost model"""

import sys
from pathlib import Path
import json
import pandas as pd
import numpy as np
from typing import Dict, Any
import argparse

sys.path.insert(0, str(Path(__file__).parent.parent))

from esp32_firmguard.utils import load_config, setup_logging
from esp32_firmguard.models.dataset import DatasetBuilder
from esp32_firmguard.models.trainer import ModelTrainer
from sklearn.model_selection import GridSearchCV, RandomizedSearchCV
import xgboost as xgb


def hyperparameter_tuning(
    feature_matrix: pd.DataFrame,
    labels: pd.Series,
    method: str = "random",
    n_iter: int = 50
) -> Dict[str, Any]:
    """
    Perform hyperparameter tuning for XGBoost model.
    
    Args:
        feature_matrix: Feature matrix
        labels: Labels
        method: "grid" or "random"
        n_iter: Number of iterations for random search
    
    Returns:
        Best parameters and score
    """
    print("=" * 80)
    print("HYPERPARAMETER TUNING")
    print("=" * 80)
    print()
    
    # Parameter grid
    param_grid = {
        'n_estimators': [100, 200, 300],
        'max_depth': [4, 6, 8, 10],
        'learning_rate': [0.01, 0.05, 0.1, 0.2],
        'subsample': [0.6, 0.8, 1.0],
        'colsample_bytree': [0.6, 0.8, 1.0],
        'min_child_weight': [1, 3, 5],
        'gamma': [0, 0.1, 0.2],
        'reg_alpha': [0, 0.1, 0.5],
        'reg_lambda': [1, 1.5, 2.0],
    }
    
    # Calculate scale_pos_weight for imbalanced dataset
    n_positive = (labels == 1).sum()
    n_negative = (labels == 0).sum()
    scale_pos_weight = n_negative / n_positive if n_positive > 0 else 1.0
    
    # Base model
    base_model = xgb.XGBClassifier(
        objective='binary:logistic',
        eval_metric='logloss',
        random_state=42,
        scale_pos_weight=scale_pos_weight,
        use_label_encoder=False
    )
    
    # Scoring metric (F1 score for balanced evaluation)
    from sklearn.metrics import make_scorer, f1_score
    f1_scorer = make_scorer(f1_score)
    
    if method == "random":
        print(f"Randomized Search (n_iter={n_iter})...")
        search = RandomizedSearchCV(
            base_model,
            param_grid,
            n_iter=n_iter,
            scoring=f1_scorer,
            cv=5,
            n_jobs=-1,
            random_state=42,
            verbose=1
        )
    else:
        print("Grid Search...")
        # Reduced grid for grid search (too many combinations)
        reduced_grid = {
            'n_estimators': [200, 300],
            'max_depth': [6, 8],
            'learning_rate': [0.05, 0.1],
            'subsample': [0.8, 1.0],
            'colsample_bytree': [0.8, 1.0],
        }
        search = GridSearchCV(
            base_model,
            reduced_grid,
            scoring=f1_scorer,
            cv=5,
            n_jobs=-1,
            verbose=1
        )
    
    print(f"Training on {len(feature_matrix)} samples...")
    search.fit(feature_matrix, labels)
    
    print()
    print("=" * 80)
    print("BEST PARAMETERS")
    print("=" * 80)
    for param, value in search.best_params_.items():
        print(f"  {param}: {value}")
    print()
    print(f"Best CV Score (F1): {search.best_score_:.4f}")
    print("=" * 80)
    
    return {
        "best_params": search.best_params_,
        "best_score": float(search.best_score_),
        "best_model": search.best_estimator_
    }


def main():
    parser = argparse.ArgumentParser(description="Hyperparameter tuning for XGBoost")
    parser.add_argument("dataset", type=str, help="Path to dataset directory")
    parser.add_argument("-c", "--config", type=str, default="configs/config.yaml",
                       help="Path to config file")
    parser.add_argument("-m", "--method", type=str, default="random",
                       choices=["grid", "random"],
                       help="Search method")
    parser.add_argument("-n", "--n-iter", type=int, default=50,
                       help="Number of iterations for random search")
    parser.add_argument("-o", "--output", type=str,
                       help="Output JSON file for best parameters")
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
    
    # Hyperparameter tuning
    results = hyperparameter_tuning(
        feature_matrix,
        labels,
        method=args.method,
        n_iter=args.n_iter
    )
    
    # Save best parameters
    if args.output:
        output_data = {
            "best_params": results["best_params"],
            "best_score": results["best_score"]
        }
        with open(args.output, 'w') as f:
            json.dump(output_data, f, indent=2)
        print(f"\nBest parameters saved to: {args.output}")
    
    # Train final model with best parameters
    print("\nTraining final model with best parameters...")
    trainer = ModelTrainer(config)
    
    # Update config with best parameters
    for param, value in results["best_params"].items():
        config["model"][param] = value
    
    trainer.config = config
    trainer.model_config = config.get("model", {})
    
    metrics = trainer.train(feature_matrix, labels, validation_split=0.2)
    
    # Save model
    model_path = trainer.save_model("vulnerability_model_tuned.pkl")
    print(f"\nTuned model saved to: {model_path}")


if __name__ == "__main__":
    main()

