"""
evaluator.py — Precision / Recall / F1 computation against ground-truth label files.
Uses:
  data/identity_users_labels.csv   (columns: user_id, is_anomaly, anomaly_type, severity, explanation)
  data/identity_events_labels.csv  (columns: timestamp, user_id, is_anomaly, anomaly_type, ...)

Compatible with Python 3.8+
"""
from __future__ import annotations
import pandas as pd
from typing import Dict, List, Optional


def evaluate_users(user_results, labels_path):
    # type: (List[Dict], str) -> Dict
    """
    Compare pipeline user predictions vs ground-truth labels.
    Prediction: MEDIUM / HIGH / CRITICAL = anomaly.
    """
    labels    = pd.read_csv(labels_path)
    label_map = {}
    for _, row in labels.iterrows():
        label_map[str(row["user_id"])] = {
            "is_anomaly":   bool(row["is_anomaly"]),
            "anomaly_type": str(row.get("anomaly_type", "NONE")),
            "severity":     str(row.get("severity", "NONE")),
        }

    PRED_POS = {"CRITICAL", "HIGH", "MEDIUM"}
    y_true, y_pred, detail_rows = [], [], []

    for r in user_results:
        uid        = r["user_id"]
        label      = label_map.get(uid, {})
        true_anom  = label.get("is_anomaly", False)
        pred_anom  = r["risk_level"] in PRED_POS
        y_true.append(int(true_anom))
        y_pred.append(int(pred_anom))
        detail_rows.append({
            "user_id":      uid,
            "true_anomaly": true_anom,
            "pred_anomaly": pred_anom,
            "true_type":    label.get("anomaly_type", "NONE"),
            "true_sev":     label.get("severity", "NONE"),
            "pred_level":   r["risk_level"],
            "pred_score":   r["risk_score"],
        })

    return _compute_metrics(y_true, y_pred, detail_rows, "user")


def evaluate_events(event_results, labels_path):
    # type: (List[Dict], str) -> Dict
    """
    Compare pipeline event predictions vs ground-truth labels.
    Matches on positional order (labels and results are both ordered by CSV row).
    Falls back to (timestamp, user_id) matching when available.
    """
    labels = pd.read_csv(labels_path)
    PRED_POS = {"CRITICAL", "HIGH", "MEDIUM"}
    y_true, y_pred, detail_rows = [], [], []

    # Build list of label dicts in order
    label_list = []
    for _, row in labels.iterrows():
        label_list.append({
            "is_anomaly":   bool(row["is_anomaly"]),
            "anomaly_type": str(row.get("anomaly_type", "NONE")),
            "severity":     str(row.get("severity", "NONE")),
            "timestamp":    str(row.get("timestamp", "")),
            "user_id":      str(row.get("user_id", "")),
        })

    # Match by position (both derived from same CSV in same order)
    for i, r in enumerate(event_results):
        if i < len(label_list):
            label = label_list[i]
        else:
            label = {"is_anomaly": False, "anomaly_type": "NONE", "severity": "NONE"}

        true_anom = label.get("is_anomaly", False)
        pred_anom = r["risk_level"] in PRED_POS
        y_true.append(int(true_anom))
        y_pred.append(int(pred_anom))
        detail_rows.append({
            "event_id":     r.get("event_id", str(i)),
            "true_anomaly": true_anom,
            "pred_anomaly": pred_anom,
            "true_type":    label.get("anomaly_type", "NONE"),
            "pred_level":   r["risk_level"],
            "pred_score":   r["risk_score"],
        })

    return _compute_metrics(y_true, y_pred, detail_rows, "event")


def _compute_metrics(y_true, y_pred, detail_rows, entity):
    # type: (list, list, list, str) -> Dict
    tp = sum(t == 1 and p == 1 for t, p in zip(y_true, y_pred))
    tn = sum(t == 0 and p == 0 for t, p in zip(y_true, y_pred))
    fp = sum(t == 0 and p == 1 for t, p in zip(y_true, y_pred))
    fn = sum(t == 1 and p == 0 for t, p in zip(y_true, y_pred))

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = (2 * precision * recall / (precision + recall)
                 if (precision + recall) > 0 else 0.0)
    accuracy  = (tp + tn) / len(y_true) if y_true else 0.0

    return {
        "entity":    entity,
        "total":     len(y_true),
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "precision": round(precision, 4),
        "recall":    round(recall, 4),
        "f1":        round(f1, 4),
        "accuracy":  round(accuracy, 4),
        "rubric": {
            "precision_pts":  _pts_precision(precision),
            "recall_pts":     _pts_recall(recall),
            "f1_pts":         _pts_f1(f1),
            "total_pts":      _pts_precision(precision) + _pts_recall(recall) + _pts_f1(f1),
        },
        "false_positives": [r for r in detail_rows if not r["true_anomaly"] and r["pred_anomaly"]][:20],
        "false_negatives": [r for r in detail_rows if r["true_anomaly"] and not r["pred_anomaly"]][:20],
    }


def _pts_precision(p):  # type: (float) -> int
    if p >= 0.85: return 15
    if p >= 0.70: return 12
    if p >= 0.55: return 9
    return 0

def _pts_recall(r):  # type: (float) -> int
    if r >= 0.80: return 10
    if r >= 0.65: return 8
    if r >= 0.50: return 5
    return 0

def _pts_f1(f):  # type: (float) -> int
    if f >= 0.75: return 5
    if f >= 0.60: return 3
    return 0


def print_evaluation_report(user_metrics, event_metrics):
    # type: (Dict, Dict) -> None
    SEP = "-" * 60
    for m in (user_metrics, event_metrics):
        print("\n  {} EVALUATION ({} samples)".format(m["entity"].upper(), m["total"]))
        print("  " + SEP)
        print("  Precision : {:.2%}   ({} TP / {} predicted)".format(
            m["precision"], m["tp"], m["tp"] + m["fp"]))
        print("  Recall    : {:.2%}   ({} TP / {} actual)".format(
            m["recall"], m["tp"], m["tp"] + m["fn"]))
        print("  F1 Score  : {:.3f}".format(m["f1"]))
        print("  Accuracy  : {:.2%}".format(m["accuracy"]))
        print("  Confusion : TP={} TN={} FP={} FN={}".format(
            m["tp"], m["tn"], m["fp"], m["fn"]))
        r = m["rubric"]
        print("  Rubric    : Precision={}/15  Recall={}/10  F1={}/5  => {}/30".format(
            r["precision_pts"], r["recall_pts"], r["f1_pts"], r["total_pts"]))

        if m["false_positives"]:
            fps = m["false_positives"]
            print("  False Positives ({} total — over-flagged):".format(len(fps)))
            for fp in fps[:3]:
                uid = fp.get("user_id") or fp.get("event_id", "")
                print("    {} | predicted {} (score={}) | true=NORMAL".format(
                    uid, fp["pred_level"], fp["pred_score"]))

        if m["false_negatives"]:
            fns = m["false_negatives"]
            print("  False Negatives ({} total — missed anomalies):".format(len(fns)))
            for fn in fns[:3]:
                uid = fn.get("user_id") or fn.get("event_id", "")
                print("    {} | true_type={} | predicted={}".format(
                    uid, fn["true_type"], fn["pred_level"]))
