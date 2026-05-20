from __future__ import annotations

from typing import Dict, List, Sequence, Tuple

import pandas as pd

try:
    from sklearn.model_selection import GroupShuffleSplit

    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


def firmware_id_from_func_index(func_id: str) -> str:
    """Extract firmware prefix from prefixed func id (stem_func_001)."""
    if "_func_" in func_id:
        return func_id.rsplit("_func_", 1)[0]
    parts = func_id.split("_")
    if len(parts) >= 2 and parts[-1].isdigit():
        return "_".join(parts[:-1])
    return func_id


def split_by_firmware(
    feature_matrix: pd.DataFrame,
    labels: pd.Series,
    validation_split: float = 0.2,
    random_state: int = 42,
) -> Tuple[pd.DataFrame, pd.Series, pd.DataFrame, pd.Series, List[str], List[str]]:
    """
    Hold out entire firmware images for validation (no function leakage).

    Returns train/val matrices and labels plus firmware id lists.
    """
    groups = pd.Series(
        [firmware_id_from_func_index(str(i)) for i in feature_matrix.index],
        index=feature_matrix.index,
    )
    unique_fw = sorted(groups.unique())
    if len(unique_fw) < 2:
        # Single firmware: fall back to stratified function split
        from sklearn.model_selection import train_test_split

        y = labels.reindex(feature_matrix.index).fillna(0).astype(int)
        stratify = y if y.nunique() > 1 and y.sum() >= 2 and (y == 0).sum() >= 2 else None
        tr_x, va_x, tr_y, va_y = train_test_split(
            feature_matrix,
            y,
            test_size=validation_split,
            random_state=random_state,
            stratify=stratify,
        )
        return tr_x, tr_y, va_x, va_y, unique_fw, []

    if not SKLEARN_AVAILABLE:
        n_val_fw = max(1, int(len(unique_fw) * validation_split))
        val_fw = set(unique_fw[-n_val_fw:])
        train_mask = ~groups.isin(val_fw)
        val_mask = groups.isin(val_fw)
        return (
            feature_matrix.loc[train_mask],
            labels.loc[train_mask],
            feature_matrix.loc[val_mask],
            labels.loc[val_mask],
            [g for g in unique_fw if g not in val_fw],
            list(val_fw),
        )

    splitter = GroupShuffleSplit(
        n_splits=1,
        test_size=validation_split,
        random_state=random_state,
    )
    idx = feature_matrix.index.to_numpy()
    grp = groups.to_numpy()
    train_idx, val_idx = next(splitter.split(idx, groups=grp))

    train_fw = sorted(set(groups.iloc[train_idx]))
    val_fw = sorted(set(groups.iloc[val_idx]))
    return (
        feature_matrix.iloc[train_idx],
        labels.iloc[train_idx],
        feature_matrix.iloc[val_idx],
        labels.iloc[val_idx],
        train_fw,
        val_fw,
    )
