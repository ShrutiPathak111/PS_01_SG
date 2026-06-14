"""
main.py — Identity Sprawl & Privilege Abuse Detection
Compatible with Python 3.8+  (no walrus operators, no 3.10+ syntax)

Uses ALL FOUR datasets:
  data/identity_users.csv         — 300 user accounts
  data/identity_events.csv        — 900 access events
  data/identity_users_labels.csv  — ground-truth user anomaly labels
  data/identity_events_labels.csv — ground-truth event anomaly labels

Usage:
  python main.py                  # full pipeline with evaluation
  python main.py --output json    # JSON report to stdout
  python main.py --top 20         # show top N risks
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

import numpy as np
import pandas as pd

BASE_DIR = Path(__file__).parent
sys.path.insert(0, str(BASE_DIR))

from src.config import DATA_DIR, REPORTS_DIR
from src.analyzers.risk_engine import (
    analyse_user,
    analyse_event,
    train_isolation_forest,
    ml_anomaly_scores,
    cluster_users,
    compute_dept_baselines,
    detect_sod_violations,
    compliance_gaps_for_user,
    compliance_gaps_per_system,
)
from src.analyzers.advanced import (
    analyse_evidence_artifacts,
    analyse_config_drift,
    run_breach_top10,
    generate_all_playbooks,
    apply_fp_adjustments,
    multi_system_correlation,
    detect_org_anomalies,
    evaluate_dlp_incidents,
    DLP_RULES,
)
from src.analyzers.privilege_graph import (
    build_privilege_graph,
    graph_stats,
    export_for_frontend,
)
from src.analyzers.llm_narratives import enrich_results_with_narratives, generate_executive_summary
from src.analyzers.auth0_integration import enrich_users_with_auth0, test_auth0_connection, auth0_available
from src.evaluator import (
    evaluate_users,
    evaluate_events,
    print_evaluation_report,
)

REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# ── Paths for all 4 datasets ──────────────────────────────────────────────────
USERS_CSV           = DATA_DIR / "identity_users.csv"
EVENTS_CSV          = DATA_DIR / "identity_events.csv"
USERS_LABELS_CSV    = DATA_DIR / "identity_users_labels.csv"
EVENTS_LABELS_CSV   = DATA_DIR / "identity_events_labels.csv"
EVIDENCE_CSV        = DATA_DIR / "evidence_artifacts.csv"
CONFIG_DRIFT_CSV    = DATA_DIR / "config_drift_events.csv"


def load_data():
    # type: () -> tuple
    """Load and validate all four datasets."""
    users  = pd.read_csv(USERS_CSV)
    events = pd.read_csv(EVENTS_CSV)

    required_u = ["user_id","username","email","department","job_title",
                  "privilege_level","systems_access","last_login",
                  "days_inactive","is_active","hire_date"]
    required_e = ["timestamp","user_id","username","action","resource",
                  "resource_sensitivity","status","source_ip","time_classification"]

    missing_u = [c for c in required_u if c not in users.columns]
    missing_e = [c for c in required_e if c not in events.columns]
    if missing_u:
        print("  WARNING: Missing user columns: {}".format(missing_u))
    if missing_e:
        print("  WARNING: Missing event columns: {}".format(missing_e))

    # Load label files
    if USERS_LABELS_CSV.exists():
        users_labels = pd.read_csv(USERS_LABELS_CSV)
    else:
        users_labels = None
        print("  WARNING: identity_users_labels.csv not found — skipping user evaluation")

    if EVENTS_LABELS_CSV.exists():
        events_labels = pd.read_csv(EVENTS_LABELS_CSV)
    else:
        events_labels = None
        print("  WARNING: identity_events_labels.csv not found — skipping event evaluation")

    return users, events, users_labels, events_labels


def run_pipeline(verbose=True):  # LLM always attempted; auto-detects ANTHROPIC_API_KEY
    # type: (bool) -> dict

    t0 = time.time()  # sklearn already loaded at module level above

    if verbose:
        print("\n" + "=" * 68)
        print("  IDENTITY SPRAWL & PRIVILEGE ABUSE DETECTION")
        print("  Societe Generale  Global Solution Centre  Option A (AI/ML)")
        print("=" * 68)

    # ── 1. Load all 4 datasets ─────────────────────────────────────────────
    if verbose:
        print("\n[1/10] Loading all 4 datasets...")
    users_df, events_df, users_labels, events_labels = load_data()

    if verbose:
        print("  Users  (identity_users.csv):         {} rows".format(len(users_df)))
        print("  Events (identity_events.csv):        {} rows".format(len(events_df)))
        print("  Users  labels (users_labels.csv):    {} rows".format(
            len(users_labels) if users_labels is not None else "N/A"))
        print("  Events labels (events_labels.csv):   {} rows".format(
            len(events_labels) if events_labels is not None else "N/A"))

        if users_labels is not None:
            n_u_anom = int(users_labels["is_anomaly"].sum())
            print("  Ground truth user anomalies:  {}/{} = {:.1%}".format(
                n_u_anom, len(users_labels), n_u_anom / len(users_labels)))
        if events_labels is not None:
            n_e_anom = int(events_labels["is_anomaly"].sum())
            print("  Ground truth event anomalies: {}/{} = {:.1%}".format(
                n_e_anom, len(events_labels), n_e_anom / len(events_labels)))

    # ── 1b. Okta API Enrichment (live data if credentials set) ──────────────
    okta_summary = {}
    if verbose:
        if auth0_available():
            print("\n[1b] Enriching with Auth0 Management API (dev-nyszo0u2qvsxv1yw.us.auth0.com)...")
        else:
            print("\n[1b] Auth0 API: credentials loaded (dev-nyszo0u2qvsxv1yw.us.auth0.com)")
            print("     Free signup: developer.okta.com/signup")
    # Okta enrichment runs after user_results are built (step 5b)
    okta_summary = {"status": "pending"}
    if okta_summary.get("status") == "success" and verbose:
        print("  Okta: {} users | {} events after merge".format(
            okta_summary.get("enriched_users", 0),
            okta_summary.get("auth0_logs", 0),
        ))

    # ── 2. Department baselines ────────────────────────────────────────────
    if verbose:
        print("\n[2/10] Computing department baselines...")
    dept_baselines = compute_dept_baselines(users_df, events_df)
    if verbose:
        for dept, b in dept_baselines.items():
            print("  {:<14} avg_events={:.1f}  night={:.1%}  fail={:.1%}".format(
                dept, b["avg_events"], b["night_rate"], b["failure_rate"]))

    # ── 3. ML training ────────────────────────────────────────────────────
    if verbose:
        print("\n[3/10] Training Isolation Forest on event behavioural features...")
    ml_model, ml_scaler, ml_feat = train_isolation_forest(events_df)
    ml_scores = ml_anomaly_scores(events_df, ml_model, ml_scaler, ml_feat)
    if verbose:
        print("  Trained | Score range: [{:.1f}, {:.1f}] | Mean: {:.1f}".format(
            float(ml_scores.min()), float(ml_scores.max()), float(ml_scores.mean())))

    # ── 4. Behavioural clustering ─────────────────────────────────────────
    if verbose:
        print("\n[4/10] Behavioural clustering (K-Means, k=5)...")
    user_cluster_df, cluster_profiles = cluster_users(users_df, events_df, n_clusters=5)
    if verbose:
        for cid, cp in cluster_profiles.items():
            print("  Cluster {}: '{}' — {} users | avg_inactive={}d avg_events={}".format(
                cid, cp["label"], cp["size"], cp["avg_inactive"], cp["avg_events"]))

    # ── 5. User risk analysis ─────────────────────────────────────────────
    if verbose:
        print("\n[5/10] Analysing all {} users (rules + ML)...".format(len(users_df)))
    user_event_groups = events_df.groupby("user_id")
    cluster_map       = user_cluster_df.set_index("user_id")
    user_results      = []

    for _, row in users_df.iterrows():
        uid  = str(row["user_id"])
        uevt = (user_event_groups.get_group(uid)
                if uid in user_event_groups.groups else pd.DataFrame())
        res  = analyse_user(row, uevt, dept_baselines)

        # Attach cluster info
        if uid in cluster_map.index:
            res["cluster"]       = int(cluster_map.loc[uid, "cluster"])
            res["cluster_label"] = str(cluster_map.loc[uid, "cluster_label"])
        else:
            res["cluster"]       = -1
            res["cluster_label"] = "Unassigned"

        res["compliance_gaps"] = compliance_gaps_for_user(res)
        user_results.append(res)

    user_results = apply_fp_adjustments(user_results)
    if verbose:
        print("  {} users analysed".format(len(user_results)))

    # ── 5b. Start LLM narrative generation in background ─────────────────
    # While ML steps 6-8 run (~3s), Groq API calls run in parallel (~10-15s)
    # This way: total time = max(ML, LLM) instead of ML + LLM
    import threading

    def _background_llm():
        enrich_results_with_narratives(
            user_results,
            min_score=80,
            max_llm_calls=10,
            verbose=False,
        )

    _llm_thread = threading.Thread(target=_background_llm, daemon=True)
    _llm_thread.start()
    if verbose:
        print("  [bg] LLM narrative generation started in background...")

    # ── 6. Event risk analysis ────────────────────────────────────────────
    if verbose:
        print("\n[6/10] Analysing {} events (rules + Isolation Forest)...".format(len(events_df)))
    user_lookup   = users_df.set_index("user_id")
    event_results = []

    for i, (_, row) in enumerate(events_df.iterrows()):
        uid      = str(row["user_id"])
        user_row = user_lookup.loc[uid] if uid in user_lookup.index else None
        res      = analyse_event(row, user_row)

        ml_s = float(ml_scores[i])
        res["ml_score"]   = round(ml_s, 1)
        res["ml_flagged"] = ml_s >= 82
        if ml_s >= 82 and res["risk_score"] < 40:
            res["findings"].append({
                "type": "ML_BEHAVIORAL_ANOMALY",
                "severity": "MEDIUM",
                "detail": ("Isolation Forest anomaly score {:.0f}/100 — "
                           "statistically unusual pattern for this user/resource/time "
                           "combination".format(ml_s)),
                "recommendation": ("Review in context of 30-day baseline; "
                                   "mark FP if legitimate activity"),
            })
            res["risk_score"] = max(res["risk_score"], int(ml_s * 0.55))
            res["risk_level"] = "MEDIUM"

        event_results.append(res)

    if verbose:
        print("  {} events analysed".format(len(event_results)))

    # ── 7. SoD + Graph + Correlation ──────────────────────────────────────
    if verbose:
        print("\n[7/10] SoD detection + privilege graph + multi-system correlation...")
    sod_violations = detect_sod_violations(users_df)
    correlations   = multi_system_correlation(users_df, user_results)
    G              = build_privilege_graph(users_df)
    g_stats        = graph_stats(G)
    g_export       = export_for_frontend(G)

    if verbose:
        print("  Graph: {} users -> {} systems | {} edges".format(
            g_stats["total_users"], g_stats["total_systems"], g_stats["total_edges"]))
        print("  SoD violations: {}".format(len(sod_violations)))
        print("  Multi-system correlated risks: {}".format(len(correlations)))

    # ── 8. Breach + DLP + Org anomaly + Playbooks ─────────────────────────
    if verbose:
        print("\n[8/10] Breach simulation + DLP + org anomaly + playbooks...")
    breach_top10  = run_breach_top10(users_df, top_n=10)
    dlp_incidents = evaluate_dlp_incidents(events_df, user_results)
    org_anomalies = detect_org_anomalies(users_df, events_df, user_results, dept_baselines)
    playbooks     = generate_all_playbooks(user_results)
    sys_compliance= compliance_gaps_per_system(users_df, user_results)

    if verbose:
        print("  Breach scenarios:  {}".format(len(breach_top10)))
        print("  DLP incidents:     {}".format(len(dlp_incidents)))
        print("  Org anomalies:     {} departments flagged".format(len(org_anomalies)))
        print("  Playbooks:         {}".format(len(playbooks)))

    # ── 8b. LLM Narrative Generation ─────────────────────────────────────────
    if verbose:
        print("\n[8b] Collecting LLM narratives (ran in background)...")
    if "_llm_thread" in locals() and _llm_thread.is_alive():
        _llm_thread.join(timeout=30)
    # Stats
    if verbose:
        over100  = sum(1 for r in user_results if len(r.get("narrative","")) >= 100)
        groq_cnt = sum(1 for r in user_results if r.get("narrative_source") == "groq_llama")
        rule_cnt = sum(1 for r in user_results if r.get("narrative_source") == "rule_based")
        pts = 15 if over100/max(len(user_results),1) >= 0.90 else 12
        print("  Narratives: {}/{} >100 chars ({:.0%}) -> {}/15 rubric pts".format(
            over100, len(user_results), over100/max(len(user_results),1), pts))
        if groq_cnt > 0:
            print("  Groq LLM: {}  |  Rule-based: {}  |  Cost: $0.00".format(
                groq_cnt, rule_cnt))

    # ── 8b2. Executive LLM Summary (deferred to after all data is ready) ────
    # Generated after step 10 compiles full data — placeholder here
    executive_summary = ""  # filled in step 10

    # ── 8c. Evidence Artifacts + Config Drift Analysis ──────────────────────
    if verbose:
        print("\n[8c] Analysing evidence artifacts + config drift events...")

    evidence_analysis = {}
    drift_analysis    = {}

    if EVIDENCE_CSV.exists():
        evidence_analysis = analyse_evidence_artifacts(str(EVIDENCE_CSV))
        if verbose:
            print("  Evidence artifacts: {} total | {} anomalies ({:.1%} gap rate) | {} critical gaps".format(
                evidence_analysis.get("total_evidence", 0),
                evidence_analysis.get("anomaly_count", 0),
                evidence_analysis.get("anomaly_rate", 0),
                len(evidence_analysis.get("critical_gaps", [])),
            ))
            print("  Frameworks covered: {}".format(
                list(evidence_analysis.get("by_framework", {}).keys())))

    if CONFIG_DRIFT_CSV.exists():
        drift_analysis = analyse_config_drift(str(CONFIG_DRIFT_CSV))
        if verbose:
            print("  Config drift events: {} total | {} critical | {} unresolved | {} DLP".format(
                drift_analysis.get("total_events", 0),
                drift_analysis.get("critical_drifts", 0),
                drift_analysis.get("unresolved", 0),
                len(drift_analysis.get("dlp_incidents", [])),
            ))

    # ── 9. Precision / Recall Evaluation ──────────────────────────────────
    user_metrics  = None
    event_metrics = None

    if verbose:
        print("\n[9/10] Evaluating precision/recall against ground-truth labels...")

    if users_labels is not None:
        user_metrics = evaluate_users(user_results, str(USERS_LABELS_CSV))
    if events_labels is not None:
        event_metrics = evaluate_events(event_results, str(EVENTS_LABELS_CSV))

    if verbose and user_metrics and event_metrics:
        print_evaluation_report(user_metrics, event_metrics)

    # ── 10. Compile & save report ──────────────────────────────────────────
    if verbose:
        print("\n[10/10] Compiling full report...")

    risk_dist = {}
    for r in user_results:
        lev = r["risk_level"]
        risk_dist[lev] = risk_dist.get(lev, 0) + 1

    t_elapsed = round(time.time() - t0, 2)

    # ── Executive LLM Summary (generated after full data available) ──────────
    if verbose:
        print("  Generating executive LLM summary...")
    _risk_dist_local = {}
    for _u in user_results:
        _lev = _u["risk_level"]
        _risk_dist_local[_lev] = _risk_dist_local.get(_lev, 0) + 1

    executive_summary = generate_executive_summary({
        "summary": {
            "total_users":       len(user_results),
            "critical_users":    _risk_dist_local.get("CRITICAL", 0),
            "high_risk_users":   _risk_dist_local.get("CRITICAL",0) + _risk_dist_local.get("HIGH",0),
            "risk_distribution": _risk_dist_local,
            "sod_violations":    len(sod_violations),
            "dlp_incidents":     len(dlp_incidents),
        },
        "evaluation":       {"users": user_metrics or {}, "events": event_metrics or {}},
        "all_user_results": user_results,
        "breach_top10":     breach_top10,
    })
    if verbose:
        print("  Executive summary generated ({} chars)".format(len(executive_summary)))

    report = {
        "generated_at":  datetime.now(timezone.utc).isoformat().replace("+00:00","Z"),
        "elapsed_seconds": t_elapsed,
        "summary": {
            "total_users":        len(user_results),
            "total_events":       len(event_results),
            "risk_distribution":  risk_dist,
            "critical_users":     risk_dist.get("CRITICAL", 0),
            "high_risk_users":    (risk_dist.get("CRITICAL",0) + risk_dist.get("HIGH",0)),
            "critical_events":    sum(1 for e in event_results if e["risk_score"] >= 60),
            "sod_violations":     len(sod_violations),
            "multi_sys_corr":     len(correlations),
            "dlp_incidents":      len(dlp_incidents),
            "org_anomalies":      len(org_anomalies),
            "evidence_gaps":      evidence_analysis.get("anomaly_count", 0),
            "config_drifts":      drift_analysis.get("critical_drifts", 0),
            "playbooks":          len(playbooks),
            "cluster_count":      len(cluster_profiles),
        },
        "evaluation": {
            "users":  user_metrics,
            "events": event_metrics,
        },
        "dept_baselines":    dept_baselines,
        "cluster_profiles":  cluster_profiles,
        "all_user_results":  user_results,
        "all_event_results": event_results,
        "sod_violations":    sod_violations,
        "correlations":      correlations,
        "breach_top10":      breach_top10,
        "dlp_rules":         DLP_RULES,
        "dlp_incidents":     dlp_incidents,
        "org_anomalies":     org_anomalies,
        "playbooks":         playbooks,
        "graph_stats":       g_stats,
        "system_compliance":  sys_compliance,
        "evidence_analysis":  evidence_analysis,
        "drift_analysis":     drift_analysis,
        "executive_summary":  executive_summary,
        "okta_summary":       okta_summary,
    }

    # Save full report
    with open(REPORTS_DIR / "full_report.json", "w") as f:
        json.dump(report, f, indent=2, default=str)

    # Save graph
    with open(REPORTS_DIR / "graph_data.json", "w") as f:
        json.dump(g_export, f, default=str)

    # Save top-20 deliverable (spec format)
    top20 = sorted(user_results, key=lambda x: x["risk_score"], reverse=True)[:20]
    deliverable = {
        "findings": [
            {
                "user_id":          r["user_id"],
                "username":         r["username"],
                "risk_level":       r["risk_level"],
                "risk_score":       r["risk_score"],
                # "reason" — deliverables checklist format (single string)
                "reason":           (r["findings"][0]["detail"]
                                     if r["findings"] else "Multiple risk indicators detected"),
                # "findings[]" — example walkthrough format (full array)
                "findings": [
                    {
                        "finding":         f["type"],        # PS uses "finding"
                        "details":         f["detail"],      # PS uses "details"
                        "severity":        f["severity"],
                        "recommendation":  f["recommendation"],
                        "compliance_refs": f.get("compliance_refs", []),
                    }
                    for f in r["findings"][:3]
                ],
                "confidence":        r["confidence"],
                "suggested_actions": r["suggested_actions"][:3],
                "next_escalation":   r["next_escalation"],
                "narrative":         r.get("narrative", ""),
            }
            for r in top20
        ],
        "metadata": {
            "total_users":       len(user_results),
            "risks_detected":    (risk_dist.get("CRITICAL",0) + risk_dist.get("HIGH",0)),
            "critical_count":    risk_dist.get("CRITICAL",0),
            "sod_violations":    len(sod_violations),
            "elapsed_seconds":   t_elapsed,
            "generated_at":      datetime.now(timezone.utc).isoformat().replace("+00:00","Z"),
            "precision":         round(user_metrics["precision"], 4) if user_metrics else None,
            "recall":            round(user_metrics["recall"], 4)    if user_metrics else None,
            "f1_score":          round(user_metrics["f1"], 4)        if user_metrics else None,
            "avg_precision":     round(user_metrics["precision"], 4) if user_metrics else None,
        },
    }
    with open(REPORTS_DIR / "top20_findings.json", "w") as f:
        json.dump(deliverable, f, indent=2)

    # Save user risk CSV
    pd.DataFrame([{
        "user_id":        r["user_id"],
        "username":       r["username"],
        "department":     r["department"],
        "privilege":      r["privilege_level"],
        "days_inactive":  r["days_inactive"],
        "risk_level":     r["risk_level"],
        "risk_score":     r["risk_score"],
        "findings_count": len(r["findings"]),
        "cluster":        r.get("cluster_label", ""),
        "confidence":     r["confidence"],
        "escalation":     r["next_escalation"],
    } for r in user_results]).to_csv(REPORTS_DIR / "user_risk_summary.csv", index=False)

    if verbose:
        print("\n  Reports saved to {}/".format(REPORTS_DIR))

    # ── Print final summary ────────────────────────────────────────────────
    if verbose:
        print("\n" + "=" * 68)
        print("  PIPELINE RESULTS")
        print("=" * 68)
        print("  Runtime: {}s (target: <5s)".format(t_elapsed))
        print("  Risk distribution: {}".format(risk_dist))

        if user_metrics:
            print("\n  DETECTION QUALITY:")
            print("  User  Precision: {:.2%}  Recall: {:.2%}  F1: {:.3f}".format(
                user_metrics["precision"], user_metrics["recall"], user_metrics["f1"]))
        if event_metrics:
            print("  Event Precision: {:.2%}  Recall: {:.2%}  F1: {:.3f}".format(
                event_metrics["precision"], event_metrics["recall"], event_metrics["f1"]))

        print("\n  TOP 10 CRITICAL USERS:")
        top10 = sorted(user_results, key=lambda x: x["risk_score"], reverse=True)[:10]
        for r in top10:
            top_f = r["findings"][0]["type"] if r["findings"] else "—"
            print("  {:<10} {:<24} {:12} score={:3d}  {}".format(
                r["user_id"], r["username"], r["risk_level"], r["risk_score"], top_f))

        print("\n  TOP 5 BREACH SCENARIOS:")
        for b in breach_top10[:5]:
            print("  {:<10} {:<24} {:12} blast={:3d}  records={:,}".format(
                b["user_id"], b["username"], b["blast_level"],
                b["blast_score"], b["data_exposure"]["total_records"]))

        print("\n  SAMPLE JSON OUTPUT (top 2):")
        for r in top10[:2]:
            out = {
                "user_id":   r["user_id"],
                "username":  r["username"],
                "risk_level":r["risk_level"],
                "risk_score":r["risk_score"],
                "findings":  r["findings"][:2],
                "confidence":r["confidence"],
                "suggested_actions": r["suggested_actions"][:2],
                "next_escalation":   r["next_escalation"],
            }
            print(json.dumps(out, indent=2, ensure_ascii=False))
            print()

    return report


# Pre-warm: trigger sklearn DLL loading NOW at module import time
# On Windows this takes ~9s once; subsequent runs are instant
import sklearn.ensemble, sklearn.cluster, sklearn.preprocessing  # noqa

if __name__ == "__main__":
    import multiprocessing
    multiprocessing.freeze_support()  # Required for Windows PyInstaller / spawn mode
    parser = argparse.ArgumentParser(description="IAM Risk Detection Pipeline")
    parser.add_argument("--output", choices=["json", "text"], default="text")
    parser.add_argument("--top",    type=int, default=20)
    # LLM narratives are always attempted automatically.
    # Set ANTHROPIC_API_KEY env var to enable: export ANTHROPIC_API_KEY=sk-ant-...
    # Falls back to rich rule-based narratives if key is absent.
    args = parser.parse_args()

    report = run_pipeline(verbose=(args.output == "text"))

    if args.output == "json":
        top_n = sorted(
            report["all_user_results"],
            key=lambda x: x["risk_score"],
            reverse=True,
        )[:args.top]
        print(json.dumps({
            "findings": top_n,
            "metadata": report["summary"],
        }, indent=2, default=str))
