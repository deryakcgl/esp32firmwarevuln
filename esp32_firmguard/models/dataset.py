"""Dataset preparation for model training"""

import logging
from typing import Dict, Any, List, Optional
import pandas as pd
import numpy as np
from pathlib import Path

logger = logging.getLogger(__name__)


class DatasetBuilder:
    """Build feature matrices and labels for model training"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
    
    def build_feature_matrix(
        self,
        structural_features: pd.DataFrame,
        peripheral_features: pd.DataFrame,
        embedding_features: pd.DataFrame,
        cwe_labels: Dict[str, List[str]]
    ) -> pd.DataFrame:
        """
        Merge all feature DataFrames into a single feature matrix.
        
        Args:
            structural_features: DataFrame with structural features
            peripheral_features: DataFrame with peripheral features
            embedding_features: DataFrame with embedding features
            cwe_labels: Dictionary mapping func_id -> list of CWE IDs
        
        Returns:
            Combined feature matrix with all features
        """
        # Start with structural features
        if structural_features.empty:
            logger.warning("No structural features provided")
            feature_matrix = pd.DataFrame()
        else:
            feature_matrix = structural_features.copy()
        
        # Merge peripheral features
        if not peripheral_features.empty:
            feature_matrix = feature_matrix.join(peripheral_features, how='outer', rsuffix='_periph')
            # Remove duplicate index columns if any
            feature_matrix = feature_matrix.loc[:, ~feature_matrix.columns.duplicated()]
        
        # Merge embedding features
        if not embedding_features.empty:
            feature_matrix = feature_matrix.join(embedding_features, how='outer', rsuffix='_emb')
            feature_matrix = feature_matrix.loc[:, ~feature_matrix.columns.duplicated()]
        
        # Add CWE label features (one-hot encoding)
        cwe_features = self._encode_cwe_labels(cwe_labels, feature_matrix.index)
        if not cwe_features.empty:
            feature_matrix = feature_matrix.join(cwe_features, how='left')
        
        # Fill NaN values
        feature_matrix = feature_matrix.fillna(0)
        
        logger.info(f"Built feature matrix with shape: {feature_matrix.shape}")
        return feature_matrix
    
    def _encode_cwe_labels(self, cwe_labels: Dict[str, List[str]], func_ids: pd.Index) -> pd.DataFrame:
        """One-hot encode CWE labels"""
        # Get all unique CWE categories
        all_cwes = set()
        for labels in cwe_labels.values():
            all_cwes.update(labels)
        
        if not all_cwes:
            return pd.DataFrame(index=func_ids)
        
        # Create one-hot encoding
        cwe_df = pd.DataFrame(0, index=func_ids, columns=sorted(all_cwes))
        
        for func_id, labels in cwe_labels.items():
            if func_id in cwe_df.index:
                for cwe in labels:
                    if cwe in cwe_df.columns:
                        cwe_df.loc[func_id, cwe] = 1
        
        # Add aggregate features
        cwe_df['num_cwe_labels'] = cwe_df.sum(axis=1)
        cwe_df['has_cwe'] = (cwe_df['num_cwe_labels'] > 0).astype(int)
        
        return cwe_df
    
    def create_labels(self, cwe_labels: Dict[str, List[str]], func_ids: pd.Index) -> pd.Series:
        """
        Create binary labels (vulnerable=1, safe=0) from CWE labels.
        
        Args:
            cwe_labels: Dictionary mapping func_id -> list of CWE IDs
            func_ids: Index of function IDs
        
        Returns:
            Series with binary labels
        """
        labels = pd.Series(0, index=func_ids, dtype=int)
        
        for func_id, cwes in cwe_labels.items():
            if func_id in labels.index and len(cwes) > 0:
                labels.loc[func_id] = 1
        
        return labels
    
    def save_dataset(self, feature_matrix: pd.DataFrame, labels: pd.Series, output_path: Path) -> None:
        """Save dataset to disk"""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Save as CSV
        feature_matrix.to_csv(output_path / "features.csv")
        labels.to_csv(output_path / "labels.csv")
        
        logger.info(f"Saved dataset to {output_path}")
    
    def load_dataset(self, dataset_path: Path) -> tuple[pd.DataFrame, pd.Series]:
        """Load dataset from disk"""
        dataset_path = Path(dataset_path)
        
        feature_matrix = pd.read_csv(dataset_path / "features.csv", index_col=0)
        labels = pd.read_csv(dataset_path / "labels.csv", index_col=0, squeeze=True)
        
        logger.info(f"Loaded dataset from {dataset_path}")
        return feature_matrix, labels


