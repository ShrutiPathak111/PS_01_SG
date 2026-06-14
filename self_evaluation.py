"""
self_evaluation.py
==================
Run this script to evaluate precision/recall against ground-truth labels.
This matches EXACTLY the self-evaluation code shown in the Problem Statement.

Usage:
    python self_evaluation.py

The script evaluates BOTH users and events against the label files.
If judges have their own label files, replace the CSV paths below.
"""
import pandas as pd
from sklearn.metrics import precision_score, recall_score, f1_score

print("=" * 55)
print("SELF-EVALUATION — Precision / Recall / F1")
print("=" * 55)

# ── EVENT EVALUATION (as shown in PS) ─────────────────────────────
print("\nEVENT ANOMALY DETECTION")
labels = pd.read_csv('data/identity_events_labels.csv')
predictions = pd.read_csv('reports/event_predictions.csv')

labels = labels.merge(
    predictions[['timestamp','user_id','predicted_anomaly']],
    on=['timestamp','user_id'], how='left'
)
labels['predicted_anomaly'] = labels['predicted_anomaly'].fillna(False)

y_true = labels['is_anomaly'].astype(int)
y_pred = labels['predicted_anomaly'].astype(int)

print(f"Precision: {precision_score(y_true, y_pred):.2%}")
print(f"Recall:    {recall_score(y_true, y_pred):.2%}")
print(f"F1 Score:  {f1_score(y_true, y_pred):.2f}")

# ── USER EVALUATION ────────────────────────────────────────────────
print("\nUSER ANOMALY DETECTION")
user_labels = pd.read_csv('data/identity_users_labels.csv')
user_preds  = pd.read_csv('reports/user_predictions.csv')

user_labels = user_labels.merge(
    user_preds[['user_id','predicted_anomaly']],
    on='user_id', how='left'
)
user_labels['predicted_anomaly'] = user_labels['predicted_anomaly'].fillna(False)

y_true_u = user_labels['is_anomaly'].astype(int)
y_pred_u  = user_labels['predicted_anomaly'].astype(int)

print(f"Precision: {precision_score(y_true_u, y_pred_u):.2%}")
print(f"Recall:    {recall_score(y_true_u, y_pred_u):.2%}")
print(f"F1 Score:  {f1_score(y_true_u, y_pred_u):.2f}")
