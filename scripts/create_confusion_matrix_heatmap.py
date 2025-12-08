#!/usr/bin/env python3
"""
Create confusion matrix heatmap for ESP32 FirmGuard evaluation results
"""

import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from pathlib import Path

# Confusion matrix values from evaluation results
# TP: 240 (9.6%), FP: 303 (12.1%), TN: 1,288 (51.5%), FN: 669 (26.8%)
TP = 240
FP = 303
TN = 1288
FN = 669

# Create confusion matrix
confusion_matrix = np.array([
    [TN, FP],  # Actual: Safe (0)
    [FN, TP]   # Actual: Vulnerable (1)
])

# Calculate percentages
total = TP + FP + TN + FN
confusion_matrix_pct = (confusion_matrix / total) * 100

# Create figure with two subplots
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))

# Set style
sns.set_style("whitegrid")
plt.rcParams['font.size'] = 12
plt.rcParams['font.family'] = 'DejaVu Sans'

# Plot 1: Absolute values
sns.heatmap(
    confusion_matrix,
    annot=True,
    fmt='d',
    cmap='Blues',
    cbar_kws={'label': 'Count'},
    xticklabels=['Predicted: Safe', 'Predicted: Vulnerable'],
    yticklabels=['Actual: Safe', 'Actual: Vulnerable'],
    ax=ax1,
    linewidths=2,
    linecolor='black',
    annot_kws={'size': 14, 'weight': 'bold'}
)
ax1.set_title('Confusion Matrix (Absolute Values)', fontsize=14, fontweight='bold', pad=20)
ax1.set_xlabel('Predicted Label', fontsize=12, fontweight='bold')
ax1.set_ylabel('Actual Label', fontsize=12, fontweight='bold')

# Add text annotations for percentages
for i in range(2):
    for j in range(2):
        pct = confusion_matrix_pct[i, j]
        ax1.text(j + 0.5, i + 0.7, f'({pct:.1f}%)', 
                ha='center', va='center', fontsize=10, color='darkblue', weight='bold')

# Plot 2: Percentage values
sns.heatmap(
    confusion_matrix_pct,
    annot=True,
    fmt='.1f',
    cmap='Oranges',
    cbar_kws={'label': 'Percentage (%)'},
    xticklabels=['Predicted: Safe', 'Predicted: Vulnerable'],
    yticklabels=['Actual: Safe', 'Actual: Vulnerable'],
    ax=ax2,
    linewidths=2,
    linecolor='black',
    annot_kws={'size': 14, 'weight': 'bold'}
)
ax2.set_title('Confusion Matrix (Percentages)', fontsize=14, fontweight='bold', pad=20)
ax2.set_xlabel('Predicted Label', fontsize=12, fontweight='bold')
ax2.set_ylabel('Actual Label', fontsize=12, fontweight='bold')

# Add text annotations for absolute values
for i in range(2):
    for j in range(2):
        val = confusion_matrix[i, j]
        ax2.text(j + 0.5, i + 0.7, f'({val})', 
                ha='center', va='center', fontsize=10, color='darkred', weight='bold')

# Add summary statistics
summary_text = f"""
Summary Statistics:
Total Samples: {total}
True Positives (TP): {TP} ({confusion_matrix_pct[1,1]:.1f}%)
True Negatives (TN): {TN} ({confusion_matrix_pct[0,0]:.1f}%)
False Positives (FP): {FP} ({confusion_matrix_pct[0,1]:.1f}%)
False Negatives (FN): {FN} ({confusion_matrix_pct[1,0]:.1f}%)

Precision: {TP/(TP+FP)*100:.2f}%
Recall: {TP/(TP+FN)*100:.2f}%
Accuracy: {(TP+TN)/total*100:.2f}%
"""

fig.suptitle('ESP32 FirmGuard: Confusion Matrix Analysis', 
             fontsize=16, fontweight='bold', y=1.02)

plt.tight_layout()

# Save figure
output_dir = Path('output/evaluation/visualizations')
output_dir.mkdir(parents=True, exist_ok=True)
output_path = output_dir / 'confusion_matrix_heatmap.png'

plt.savefig(output_path, dpi=300, bbox_inches='tight', facecolor='white')
print(f"✅ Confusion matrix heatmap saved to: {output_path}")

# Also create a single larger version
fig2, ax = plt.subplots(figsize=(10, 8))

sns.heatmap(
    confusion_matrix,
    annot=True,
    fmt='d',
    cmap='RdYlBu_r',
    cbar_kws={'label': 'Count'},
    xticklabels=['Predicted: Safe', 'Predicted: Vulnerable'],
    yticklabels=['Actual: Safe', 'Actual: Vulnerable'],
    ax=ax,
    linewidths=3,
    linecolor='black',
    annot_kws={'size': 18, 'weight': 'bold'}
)

# Add percentage annotations
for i in range(2):
    for j in range(2):
        pct = confusion_matrix_pct[i, j]
        ax.text(j + 0.5, i + 0.7, f'\n({pct:.1f}%)', 
                ha='center', va='center', fontsize=14, color='white', weight='bold')

ax.set_title('ESP32 FirmGuard: Confusion Matrix\n(Total: 2,500 functions)', 
             fontsize=16, fontweight='bold', pad=20)
ax.set_xlabel('Predicted Label', fontsize=14, fontweight='bold')
ax.set_ylabel('Actual Label', fontsize=14, fontweight='bold')

# Add metrics text box
metrics_text = f'Precision: {TP/(TP+FP)*100:.1f}%  |  Recall: {TP/(TP+FN)*100:.1f}%  |  Accuracy: {(TP+TN)/total*100:.1f}%'
ax.text(0.5, -0.15, metrics_text, ha='center', va='top', 
        transform=ax.transAxes, fontsize=12, 
        bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))

plt.tight_layout()

output_path2 = output_dir / 'confusion_matrix_heatmap_large.png'
plt.savefig(output_path2, dpi=300, bbox_inches='tight', facecolor='white')
print(f"✅ Large confusion matrix heatmap saved to: {output_path2}")

plt.close('all')
print("\n✅ All confusion matrix heatmaps created successfully!")

