"""
advanced.py — All Level 1/2/3 bonus features:
  - Breach Impact Simulation
  - Automated Remediation Playbooks
  - Multi-System Correlation
  - False Positive Feedback Loop
  - Organizational Anomaly Detection
  - DLP Integration
"""

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

import pandas as pd

from src.config import (
    IDENTITY_SYSTEM_IMPACT, RESOURCE_IMPACT, LATERAL_PATHS,
    COMPLIANCE_MAP,
)
from src.analyzers.risk_engine import parse_systems

REPORTS_DIR = Path(__file__).parent.parent.parent / "reports"


# ══════════════════════════════════════════════════════════════════════════════
# BREACH IMPACT SIMULATOR
# ══════════════════════════════════════════════════════════════════════════════
def simulate_breach(user_row):  # type: (...) -> dict
    """
    Simulate what would be exposed if this user's credentials are compromised.
    Computes direct + lateral movement blast radius, GDPR exposure, financial impact.
    """
    if isinstance(user_row, pd.Series):
        user_row = user_row.to_dict()

    uid      = str(user_row.get("user_id", "UNKNOWN"))
    username = str(user_row.get("username", uid))
    priv     = str(user_row.get("privilege_level", "user"))
    dept     = str(user_row.get("department", ""))
    systems  = set(parse_systems(user_row.get("systems_access", "")))

    # Direct access from identity systems
    direct = {s for s in systems if s in IDENTITY_SYSTEM_IMPACT}

    # Lateral movement via attack chains
    lateral = set()
    for s in direct:
        for reachable in LATERAL_PATHS.get(s, []):
            if reachable not in direct and reachable in IDENTITY_SYSTEM_IMPACT:
                lateral.add(reachable)

    all_reachable_sys = direct | lateral

    # Aggregate impact metrics
    total_records  = 0
    gdpr_records   = 0
    max_fine       = 0
    total_fine_est = 0
    data_exposures = []
    system_impacts = []

    for s in all_reachable_sys:
        info = IDENTITY_SYSTEM_IMPACT[s]
        total_records  += info["records"]
        if info["gdpr"]: gdpr_records += info["records"]
        max_fine = max(max_fine, info["fine"])
        total_fine_est += info["fine"] * 0.25
        if info["desc"] not in data_exposures:
            data_exposures.append(info["desc"])
        system_impacts.append({
            "system":    s,
            "path":      "direct" if s in direct else "lateral_movement",
            "records":   info["records"],
            "gdpr":      info["gdpr"],
            "fine_risk": info["fine"],
            "desc":      info["desc"],
        })

    # Blast score (0-100)
    blast = 0
    blast += {"admin": 38, "power-user": 26, "service-account": 18, "user": 10}.get(priv, 10)
    blast += 30 if total_records > 1_000_000 else 20 if total_records > 100_000 else 10
    blast += 15 if gdpr_records > 0 else 0
    blast += 12 if len(lateral) > 0 else 0
    blast += 8  if "ADMIN_SYS" in direct else 0
    blast = min(blast, 100)

    blast_level = (
        "CATASTROPHIC" if blast >= 80 else
        "SEVERE"       if blast >= 60 else
        "HIGH"         if blast >= 40 else
        "MODERATE"
    )

    containment = [f"Immediately revoke {s} access" for s in sorted(direct)][:5]
    containment += ["Reset all credentials and active SSO sessions",
                    "Forensic review of audit logs from past 30 days"]
    if gdpr_records > 0:
        containment.append("⚠️ GDPR Art.33: Notify supervisory authority within 72 hours")

    return {
        "user_id":    uid,
        "username":   username,
        "department": dept,
        "privilege":  priv,
        "blast_radius": {
            "direct_systems":    sorted(direct),
            "lateral_movement":  sorted(lateral),
            "total_reachable":   len(all_reachable_sys),
        },
        "data_exposure": {
            "total_records":    total_records,
            "gdpr_records":     gdpr_records,
            "descriptions":     data_exposures[:5],
        },
        "financial_exposure": {
            "max_regulatory_fine":  max_fine,
            "estimated_total_fine": int(total_fine_est),
            "breach_cost_estimate": int(total_records * 0.18),
            "gdpr_72h_required":    gdpr_records > 0,
        },
        "blast_score":   blast,
        "blast_level":   blast_level,
        "system_impacts":sorted(system_impacts, key=lambda x: x["fine_risk"], reverse=True),
        "containment":   containment,
    }


def run_breach_top10(users_df, top_n=10):  # type: (pd.DataFrame, int) -> list
    results = [simulate_breach(row) for _, row in users_df.iterrows()]
    return sorted(results, key=lambda x: x["blast_score"], reverse=True)[:top_n]


# ══════════════════════════════════════════════════════════════════════════════
# AUTOMATED REMEDIATION PLAYBOOKS
# ══════════════════════════════════════════════════════════════════════════════
PLAYBOOK_TEMPLATES = {
    "STALE_PRIVILEGED_ACCOUNT": {
        "title":     "Stale Privileged Account Remediation",
        "urgency":   "HIGH",
        "sla_hours": 24,
        "owner":     "IAM Team + HR",
        "steps": [
            {"n":1,"action":"HR verification","owner":"HR","detail":"Check HRIS for active employment; confirm user has not departed","deadline_h":4,"verify":"HR confirms active/inactive status in ticket"},
            {"n":2,"action":"Manager confirmation","owner":"Manager","detail":"Email manager to confirm role still requires {privilege_level} access to {systems_count} systems","deadline_h":8,"verify":"Manager email confirmation attached"},
            {"n":3,"action":"Temporary suspension","owner":"IAM Team","detail":"If no manager response in 8h: disable account in {systems_list} pending review","deadline_h":12,"verify":"Account suspended; monitoring alert configured"},
            {"n":4,"action":"Access right-sizing","owner":"IAM Team","detail":"Remove excess {excess_systems} systems; retain only role-required access","deadline_h":24,"verify":"Access profile updated; peer review completed"},
            {"n":5,"action":"Post-remediation audit","owner":"Security","detail":"Review audit logs for suspicious activity during stale period; check for lateral movement","deadline_h":48,"verify":"Audit report filed; no unauthorized activity found"},
        ]
    },
    "SOD_VIOLATION": {
        "title":     "Separation of Duties Violation Remediation",
        "urgency":   "HIGH",
        "sla_hours": 72,
        "owner":     "IAM Team + CISO",
        "steps": [
            {"n":1,"action":"Document conflict","owner":"Security","detail":"Record {sys_a} + {sys_b} conflict in GRC system with risk rating HIGH","deadline_h":2,"verify":"GRC risk record created with ticket reference"},
            {"n":2,"action":"Risk decision","owner":"CISO","detail":"Business owner: accept risk with compensating controls OR remove one access right","deadline_h":24,"verify":"Signed decision record filed"},
            {"n":3,"action":"Remove conflicting access","owner":"IAM Team","detail":"Remove lower-priority access ({sys_b}); update role assignment in identity system","deadline_h":48,"verify":"User no longer holds both conflicting rights; SoD check passes"},
            {"n":4,"action":"Compensating control","owner":"Security","detail":"If risk accepted: enable enhanced SIEM monitoring; require dual approval for sensitive ops","deadline_h":72,"verify":"SIEM alert rule active; approval workflow enabled and tested"},
        ]
    },
    "OVER_PRIVILEGED": {
        "title":     "Over-Privileged Account Right-Sizing",
        "urgency":   "MEDIUM",
        "sla_hours": 168,
        "owner":     "IAM Team + Manager",
        "steps": [
            {"n":1,"action":"Generate usage report","owner":"IAM Team","detail":"Pull 90-day system access logs for {username}; identify which systems haven't been used","deadline_h":24,"verify":"Usage report generated and shared with manager"},
            {"n":2,"action":"Manager review","owner":"Manager","detail":"Manager approves removal of unused systems (currently {systems_count}, target: {max_systems})","deadline_h":72,"verify":"Signed approval in access review tool"},
            {"n":3,"action":"Remove excess access","owner":"IAM Team","detail":"Remove {excess_systems} unused systems; document business justification for retained access","deadline_h":120,"verify":"Access profile updated; user notified of changes"},
            {"n":4,"action":"Schedule recertification","owner":"IAM Team","detail":"Add to quarterly access recertification campaign; set 90-day review reminder","deadline_h":168,"verify":"User enrolled in next recertification cycle"},
        ]
    },
    "AFTER_HOURS_HIGH_RISK": {
        "title":     "After-Hours High-Risk Access Investigation",
        "urgency":   "CRITICAL",
        "sla_hours": 4,
        "owner":     "Security SOC",
        "steps": [
            {"n":1,"action":"Check change management","owner":"SOC","detail":"Verify if approved change window covers this timeframe in ServiceNow","deadline_h":0.5,"verify":"Change record found OR no record (escalate immediately)"},
            {"n":2,"action":"Verify on-call roster","owner":"SOC","detail":"Confirm user was scheduled on-call during the {time_classification} access period","deadline_h":1,"verify":"On-call roster confirms or denies; documented"},
            {"n":3,"action":"Direct user contact","owner":"SOC","detail":"Call/message user to verify activity was intentional and authorised","deadline_h":2,"verify":"User confirms activity OR cannot be reached (escalate)"},
            {"n":4,"action":"SIEM correlation","owner":"SOC","detail":"Cross-correlate with VPN logs, badge access, geographic location of source IP","deadline_h":3,"verify":"No anomalous geo-indicators OR suspicious — escalate to CISO"},
            {"n":5,"action":"Resolve or escalate","owner":"SOC Lead","detail":"If suspicious: isolate account, initiate IR process. If clean: document, close, tune rule","deadline_h":4,"verify":"Ticket closed with disposition: LEGITIMATE or INCIDENT"},
        ]
    },
    "BULK_DATA_EXPORT": {
        "title":     "Bulk Data Export Investigation",
        "urgency":   "CRITICAL",
        "sla_hours": 2,
        "owner":     "Security SOC + DLP Team",
        "steps": [
            {"n":1,"action":"DLP log review","owner":"DLP Team","detail":"Check DLP system for export destination, file type, data classification, volume","deadline_h":0.5,"verify":"DLP destination confirmed; data classification known"},
            {"n":2,"action":"Suspend export capability","owner":"IAM Team","detail":"Temporarily revoke export_data permission for {username} pending investigation","deadline_h":1,"verify":"Export capability suspended; SIEM alert active"},
            {"n":3,"action":"Notify data owner","owner":"SOC","detail":"Inform CISO and DPO of potential exfiltration from {resource}","deadline_h":1,"verify":"DPO notified; GDPR Art.33 72h clock started if personal data"},
            {"n":4,"action":"Forensic investigation","owner":"Security","detail":"Retrieve full export logs; determine exact volume, destination endpoint, and content","deadline_h":2,"verify":"Forensic report drafted; exfiltration confirmed or ruled out"},
        ]
    },
    "STALE_SERVICE_ACCOUNT": {
        "title":     "Stale Service Account Decommissioning",
        "urgency":   "HIGH",
        "sla_hours": 48,
        "owner":     "DevOps + IAM Team",
        "steps": [
            {"n":1,"action":"Identify owning team","owner":"IAM Team","detail":"Trace service account to application via CMDB; notify owning team","deadline_h":4,"verify":"Owner team identified and notified via ticket"},
            {"n":2,"action":"Dependency scan","owner":"DevOps","detail":"Scan CI/CD pipelines, cron jobs, and API configs for references to this account","deadline_h":12,"verify":"Dependency list confirmed; zero active callers found"},
            {"n":3,"action":"Rotate credentials","owner":"DevOps","detail":"Rotate password/API key first to surface any hidden consumers before disabling","deadline_h":24,"verify":"No new auth failures observed after rotation in monitoring window"},
            {"n":4,"action":"Disable and monitor","owner":"IAM Team","detail":"Disable account; monitor 48h for auth failures before permanent deletion","deadline_h":48,"verify":"Zero auth failures observed; account safe to delete"},
            {"n":5,"action":"Delete and document","owner":"IAM Team","detail":"Delete account; update CMDB with decommission date, owner, and replacement reference","deadline_h":96,"verify":"Account removed from all systems; CMDB record updated"},
        ]
    },
    "NO_MFA_PRIVILEGED": {
        "title":     "MFA Enforcement for Privileged Account",
        "urgency":   "HIGH",
        "sla_hours": 24,
        "owner":     "IAM Team",
        "steps": [
            {"n":1,"action":"Enroll in MFA system","owner":"IAM Team","detail":"Enroll {username} in Okta or Azure AD MFA; send enrollment link","deadline_h":2,"verify":"MFA enrollment invitation sent and acknowledged"},
            {"n":2,"action":"Enforce MFA policy","owner":"IAM Team","detail":"Enable conditional access policy requiring MFA for all {privilege_level} actions","deadline_h":4,"verify":"Conditional access policy active; tested with test account"},
            {"n":3,"action":"Block privileged access until enrolled","owner":"IAM Team","detail":"If not enrolled in 24h: block privileged system access; escalate to manager","deadline_h":24,"verify":"User enrolled or access blocked; manager notified"},
        ]
    },
    "DEFAULT": {
        "title":     "Security Risk Investigation",
        "urgency":   "MEDIUM",
        "sla_hours": 72,
        "owner":     "Security SOC",
        "steps": [
            {"n":1,"action":"Review finding details","owner":"SOC","detail":"Analyse the specific risk indicators identified for {username}","deadline_h":8,"verify":"Risk context documented in ticket"},
            {"n":2,"action":"Gather additional context","owner":"SOC","detail":"Check HR records, manager confirmation, and business justification","deadline_h":24,"verify":"Context gathered; risk rating confirmed or revised"},
            {"n":3,"action":"Remediate or close","owner":"IAM Team","detail":"Apply appropriate remediation action based on confirmed risk level","deadline_h":72,"verify":"Ticket resolved with disposition and action taken"},
        ]
    },
}


def generate_playbook(user_result, finding):  # type: (dict, dict) -> dict
    """Generate step-by-step remediation playbook for a specific finding."""
    ftype    = finding.get("type", "DEFAULT")
    template = PLAYBOOK_TEMPLATES.get(ftype, PLAYBOOK_TEMPLATES["DEFAULT"])

    uid      = user_result.get("user_id", "")
    username = user_result.get("username", uid)
    priv     = user_result.get("privilege_level", "user")
    systems  = user_result.get("systems", [])
    max_sys  = {"admin": 8, "power-user": 5, "user": 3, "service-account": 3}.get(priv, 3)

    context = {
        "username":       username,
        "privilege_level":priv,
        "systems_list":   ", ".join(systems[:4]),
        "systems_count":  str(len(systems)),
        "max_systems":    str(max_sys),
        "excess_systems": str(max(0, len(systems) - max_sys)),
        "sys_a":          systems[0] if systems else "SystemA",
        "sys_b":          systems[1] if len(systems) > 1 else "SystemB",
        "resource":       finding.get("detail", "")[:40],
        "time_classification": "off-hours",
    }

    steps = []
    for s in template["steps"]:
        detail = s["detail"]
        for k, v in context.items():
            detail = detail.replace("{" + k + "}", str(v))
        due = datetime.utcnow() + timedelta(hours=s["deadline_h"])
        steps.append({
            "step":     s["n"],
            "action":   s["action"],
            "owner":    s["owner"],
            "detail":   detail,
            "deadline": due.strftime("%Y-%m-%d %H:%M UTC"),
            "verify":   s["verify"],
            "status":   "PENDING",
        })

    return {
        "playbook_id":    f"PB-{uid}-{ftype[:8]}-{datetime.utcnow().strftime('%Y%m%d%H%M')}",
        "user_id":        uid,
        "username":       username,
        "finding_type":   ftype,
        "title":          template["title"],
        "urgency":        template["urgency"],
        "sla_hours":      template["sla_hours"],
        "owner":          template["owner"],
        "generated_at":   datetime.utcnow().isoformat() + "Z",
        "finding_detail": finding.get("detail", ""),
        "steps":          steps,
        "compliance":     finding.get("compliance_refs", []),
    }


def generate_all_playbooks(user_results):  # type: (list) -> list
    """Auto-generate playbooks for all HIGH/CRITICAL findings."""
    playbooks = []
    for result in user_results:
        if result["risk_score"] < 35:
            continue
        for finding in result.get("findings", []):
            if finding["severity"] in ("CRITICAL", "HIGH"):
                playbooks.append(generate_playbook(result, finding))
    return playbooks


# ══════════════════════════════════════════════════════════════════════════════
# FALSE POSITIVE FEEDBACK LOOP
# ══════════════════════════════════════════════════════════════════════════════
FP_STORE = Path(__file__).parent.parent.parent / "reports" / "fp_feedback.json"


def load_fp_store():  # type: () -> dict
    if FP_STORE.exists():
        with open(FP_STORE) as f:
            return json.load(f)
    return {"adjustments": {}, "feedback_log": [], "total_fps": 0, "total_tps": 0}


def record_feedback(user_id, finding_type, is_fp, reason=""):  # type: (...) -> dict
    """
    Record analyst feedback. Adjusts future scoring for this finding type.
    Implements a decay penalty: more FPs = lower scores for that finding type.
    """
    store = load_fp_store()
    store["feedback_log"].append({
        "user_id":      user_id,
        "finding_type": finding_type,
        "is_fp":        is_fp,
        "reason":       reason,
        "timestamp":    datetime.utcnow().isoformat() + "Z",
    })

    key = finding_type
    if key not in store["adjustments"]:
        store["adjustments"][key] = {"fp": 0, "tp": 0, "score_penalty": 0, "precision_est": 1.0}

    if is_fp:
        store["adjustments"][key]["fp"] += 1
        store["total_fps"] += 1
        # Penalty: +5 per FP, capped at 30
        store["adjustments"][key]["score_penalty"] = min(
            store["adjustments"][key]["score_penalty"] + 5, 30
        )
    else:
        store["adjustments"][key]["tp"] += 1
        store["total_tps"] += 1
        # Reward: reduce penalty if TPs come in
        store["adjustments"][key]["score_penalty"] = max(
            store["adjustments"][key]["score_penalty"] - 2, 0
        )

    # Estimate precision for this finding type
    fp = store["adjustments"][key]["fp"]
    tp = store["adjustments"][key]["tp"]
    if fp + tp > 0:
        store["adjustments"][key]["precision_est"] = round(tp / (tp + fp), 2)

    FP_STORE.parent.mkdir(parents=True, exist_ok=True)
    with open(FP_STORE, "w") as f:
        json.dump(store, f, indent=2)

    return store["adjustments"][key]


def apply_fp_adjustments(user_results):  # type: (list) -> list
    """Apply learned FP score penalties to reduce alert fatigue."""
    store = load_fp_store()
    adj   = store.get("adjustments", {})

    for result in user_results:
        penalty = 0
        for finding in result.get("findings", []):
            ft = finding["type"]
            if ft in adj:
                pen = adj[ft].get("score_penalty", 0)
                penalty += pen
                if pen > 0:
                    finding["fp_adjusted"] = True
                    finding["fp_penalty"]  = pen

        if penalty > 0:
            old_score = result["risk_score"]
            result["risk_score"] = max(0, result["risk_score"] - penalty)
            result["fp_adjusted"] = True
            result["fp_total_penalty"] = penalty
            result["fp_original_score"] = old_score
            # Recalculate risk level
            s = result["risk_score"]
            result["risk_level"] = (
                "CRITICAL" if s >= 80 else "HIGH" if s >= 60 else
                "MEDIUM"   if s >= 35 else "LOW"  if s >= 15 else "INFORMATIONAL"
            )

    return user_results


# ══════════════════════════════════════════════════════════════════════════════
# MULTI-SYSTEM CORRELATION
# ══════════════════════════════════════════════════════════════════════════════
CRITICAL_IDENTITY_SYSTEMS = {"PROD_DB", "ADMIN_SYS", "SIEM", "AWS_IAM", "Azure_AD"}


def multi_system_correlation(users_df, user_results):  # type: (pd.DataFrame, list) -> list
    """
    Identifies users whose risk spans multiple critical systems.
    These represent the highest lateral movement risk.
    """
    result_map = {r["user_id"]: r for r in user_results}
    correlations = []

    for _, row in users_df.iterrows():
        uid = str(row["user_id"])
        res = result_map.get(uid)
        if not res or res["risk_score"] < 35:
            continue

        systems = set(parse_systems(row.get("systems_access", "")))
        critical_held = systems & CRITICAL_IDENTITY_SYSTEMS
        if len(critical_held) >= 2:
            # Assess blast path
            lateral_reach = set()
            for s in critical_held:
                for reachable in LATERAL_PATHS.get(s, []):
                    if reachable not in critical_held:
                        lateral_reach.add(reachable)

            correlations.append({
                "user_id":         uid,
                "username":        res.get("username", uid),
                "department":      res.get("department", ""),
                "privilege":       res.get("privilege_level", ""),
                "critical_systems":sorted(critical_held),
                "system_count":    len(critical_held),
                "lateral_reach":   sorted(lateral_reach),
                "risk_score":      res["risk_score"],
                "risk_level":      res["risk_level"],
                "finding":         "MULTI_CRITICAL_SYSTEM_RISK",
                "detail":          f"High-risk user spans {len(critical_held)} critical systems: "
                                   f"{', '.join(sorted(critical_held))}. "
                                   f"Lateral movement could reach: {', '.join(sorted(lateral_reach)) or 'none'}",
                "recommendation":  "Immediate access review; verify each critical system need; "
                                   "add to enhanced monitoring in SIEM",
            })

    return sorted(correlations, key=lambda x: (x["system_count"], x["risk_score"]), reverse=True)


# ══════════════════════════════════════════════════════════════════════════════
# ORGANIZATIONAL ANOMALY DETECTION
# ══════════════════════════════════════════════════════════════════════════════
def detect_org_anomalies(users_df, events_df, user_results, dept_baselines):
    # type: (pd.DataFrame, pd.DataFrame, list, dict) -> list
    """
    Department-level anomaly detection.
    Flags departments with abnormal risk concentrations or access patterns.
    """
    user_dept = users_df[["user_id", "department"]].set_index("user_id")
    result_map = {r["user_id"]: r for r in user_results}

    ev = events_df.copy()
    ev["dept"] = ev["user_id"].map(user_dept["department"])

    dept_anomalies = []
    for dept, grp in ev.groupby("dept"):
        if dept not in dept_baselines:
            continue

        bl = dept_baselines[dept]

        # Compute current period metrics
        night_rate_now   = grp["time_classification"].isin(["night","unusual_hours"]).mean()
        failure_rate_now = (grp["status"] == "failure").mean()
        export_rate_now  = (grp["action"] == "export_data").mean()
        high_sens_now    = (grp["resource_sensitivity"] == "high").mean()

        issues = []

        # Night rate anomaly
        bl_night = bl["night_rate"]
        if bl_night > 0 and night_rate_now > bl_night * 2.0:
            issues.append(f"Night access rate {night_rate_now:.1%} vs baseline {bl_night:.1%}")

        # Failure rate anomaly
        bl_fail = bl["failure_rate"]
        if failure_rate_now > max(bl_fail * 3.0, 0.15):
            issues.append(f"Failure rate {failure_rate_now:.1%} vs baseline {bl_fail:.1%}")

        # Count risk users in dept
        dept_users = users_df[users_df["department"] == dept]["user_id"].tolist()
        dept_risks = [result_map.get(u) for u in dept_users if result_map.get(u)]
        critical_in_dept = sum(1 for r in dept_risks if r and r["risk_level"] in ("CRITICAL","HIGH"))
        risk_rate = critical_in_dept / max(len(dept_users), 1)

        if risk_rate > 0.30:
            issues.append(f"{critical_in_dept}/{len(dept_users)} users ({risk_rate:.0%}) are HIGH/CRITICAL risk")

        if not issues:
            continue

        severity = "HIGH" if len(issues) >= 2 or risk_rate > 0.4 else "MEDIUM"
        dept_anomalies.append({
            "department":      dept,
            "severity":        severity,
            "issues":          issues,
            "night_rate":      round(night_rate_now, 3),
            "failure_rate":    round(failure_rate_now, 3),
            "export_rate":     round(export_rate_now, 3),
            "high_sens_rate":  round(high_sens_now, 3),
            "critical_users":  critical_in_dept,
            "total_users":     len(dept_users),
            "risk_rate":       round(risk_rate, 3),
            "baseline":        bl,
            "recommendation":  f"Conduct department-wide access review for {dept}; "
                               f"review {critical_in_dept} flagged accounts with department head",
        })

    return sorted(dept_anomalies, key=lambda x: x["risk_rate"], reverse=True)


# ══════════════════════════════════════════════════════════════════════════════
# DLP INTEGRATION
# ══════════════════════════════════════════════════════════════════════════════
DLP_RULES = [
    {
        "id":       "DLP-001",
        "name":     "Block export for CRITICAL risk users",
        "trigger":  "user risk_score >= 80",
        "action":   "BLOCK",
        "resource": "*",
        "active":   True,
        "severity": "CRITICAL",
    },
    {
        "id":       "DLP-002",
        "name":     "Rate-limit export for HIGH risk users",
        "trigger":  "user risk_score 60-79 AND action=export_data",
        "action":   "THROTTLE + ALERT",
        "resource": "*",
        "active":   True,
        "severity": "HIGH",
    },
    {
        "id":       "DLP-003",
        "name":     "Alert on night-time high-sensitivity export",
        "trigger":  "time_classification IN (night, unusual_hours) AND action=export_data AND resource_sensitivity=high",
        "action":   "ALERT + LOG",
        "resource": "Customer_Vault, PROD_DB, HRIS, GL_System",
        "active":   True,
        "severity": "HIGH",
    },
    {
        "id":       "DLP-004",
        "name":     "MFA challenge on Customer_Vault access",
        "trigger":  "resource=Customer_Vault AND privilege_level != admin",
        "action":   "MFA_PROMPT",
        "resource": "Customer_Vault",
        "active":   True,
        "severity": "MEDIUM",
    },
    {
        "id":       "DLP-005",
        "name":     "Block PROD_DB access for stale admins",
        "trigger":  "STALE_PRIVILEGED_ACCOUNT AND resource=PROD_DB",
        "action":   "BLOCK",
        "resource": "PROD_DB",
        "active":   True,
        "severity": "HIGH",
    },
    {
        "id":       "DLP-006",
        "name":     "Quarantine SoD violators from critical resources",
        "trigger":  "SOD_VIOLATION AND resource IN (PROD_DB, Admin_Console, SIEM)",
        "action":   "QUARANTINE",
        "resource": "PROD_DB, Admin_Console, SIEM",
        "active":   False,  # Pending approval
        "severity": "HIGH",
    },
    {
        "id":       "DLP-007",
        "name":     "Deep scan all bulk exports from Data_Lake",
        "trigger":  "resource=Data_Lake AND action=export_data AND records > 10000",
        "action":   "SCAN + HOLD",
        "resource": "Data_Lake",
        "active":   True,
        "severity": "MEDIUM",
    },
]


def evaluate_dlp_incidents(events_df, user_results):
    # type: (pd.DataFrame, list) -> list
    """Match events against DLP rules and generate incident list."""
    result_map = {r["user_id"]: r for r in user_results}
    incidents  = []

    for _, row in events_df.iterrows():
        uid    = str(row["user_id"])
        res    = result_map.get(uid, {})
        score  = res.get("risk_score", 0)
        action = str(row["action"])
        sens   = str(row["resource_sensitivity"])
        time_c = str(row["time_classification"])
        res_   = str(row["resource"])

        triggered = []
        if score >= 80:
            triggered.append("DLP-001")
        if 60 <= score < 80 and action == "export_data":
            triggered.append("DLP-002")
        if time_c in ("night","unusual_hours") and action == "export_data" and sens == "high":
            triggered.append("DLP-003")
        if res_ == "Customer_Vault":
            triggered.append("DLP-004")
        if any(f.get("type") == "STALE_PRIVILEGED_ACCOUNT" for f in res.get("findings", [])) and res_ == "PROD_DB":
            triggered.append("DLP-005")
        if res_ == "Data_Lake" and action == "export_data":
            triggered.append("DLP-007")

        if triggered:
            rule_actions = [r["action"] for r in DLP_RULES if r["id"] in triggered and r["active"]]
            incidents.append({
                "timestamp":    str(row["timestamp"]),
                "user_id":      uid,
                "username":     str(row.get("username", uid)),
                "resource":     res_,
                "action":       action,
                "sensitivity":  sens,
                "time_class":   time_c,
                "rules_hit":    triggered,
                "dlp_actions":  rule_actions,
                "user_score":   score,
                "severity":     res.get("risk_level", "LOW"),
            })

    return sorted(incidents, key=lambda x: x["user_score"], reverse=True)


# ══════════════════════════════════════════════════════════════════════════════
# EVIDENCE ARTIFACTS & CONFIG DRIFT INTEGRATION
# New datasets: evidence_artifacts.csv + config_drift_events.csv
# ══════════════════════════════════════════════════════════════════════════════

def analyse_evidence_artifacts(evidence_path):
    # type: (str) -> dict
    """
    Analyse evidence_artifacts.csv for compliance gaps.
    Returns summary of gaps per framework and anomaly type.
    """
    import pandas as pd
    try:
        ea = pd.read_csv(evidence_path)
    except Exception:
        return {}

    result = {
        "total_evidence":     len(ea),
        "anomaly_count":      int(ea['anomaly_marker'].notna().sum()),
        "anomaly_rate":       round(ea['anomaly_marker'].notna().mean(), 3),
        "avg_confidence":     round(ea['confidence_score'].mean(), 3),
        "by_framework":       {},
        "by_anomaly_type":    {},
        "critical_gaps":      [],
        "stale_evidence":     [],
    }

    # Per framework summary
    for fw, grp in ea.groupby('framework'):
        anom = grp['anomaly_marker'].notna()
        result["by_framework"][fw] = {
            "total":       int(len(grp)),
            "anomalies":   int(anom.sum()),
            "gap_rate":    round(anom.mean(), 3),
            "avg_conf":    round(grp['confidence_score'].mean(), 3),
            "needs_update":int((grp['status'] == 'Needs_Update').sum()),
            "rejected":    int((grp['status'] == 'Rejected').sum()),
        }

    # Per anomaly type
    for atype, grp in ea[ea['anomaly_marker'].notna()].groupby('anomaly_marker'):
        result["by_anomaly_type"][atype] = {
            "count":      int(len(grp)),
            "frameworks": grp['framework'].value_counts().to_dict(),
            "avg_conf":   round(grp['confidence_score'].mean(), 3),
        }

    # Critical gaps: low confidence + anomaly + not approved
    critical = ea[
        (ea['anomaly_marker'].notna()) &
        (ea['confidence_score'] < 0.6) &
        (ea['status'] != 'Approved')
    ]
    result["critical_gaps"] = critical[
        ['evidence_id','framework','anomaly_marker','confidence_score','status','requirement_description']
    ].head(20).to_dict('records')

    # Stale evidence (freshness_days > 90)
    stale = ea[ea['freshness_days'] > 90]
    result["stale_evidence"] = stale[
        ['evidence_id','framework','freshness_days','status']
    ].head(20).to_dict('records')

    return result


def analyse_config_drift(drift_path, user_lookup=None):
    # type: (str, dict) -> dict
    """
    Analyse config_drift_events.csv for unauthorized/critical changes.
    Links drift events to user risk scores where operator_email matches.
    """
    import pandas as pd
    try:
        cd = pd.read_csv(drift_path)
    except Exception:
        return {}

    result = {
        "total_events":      len(cd),
        "critical_drifts":   int((cd['severity'].isin(['Critical','High'])).sum()),
        "unresolved":        int((cd['status'].isin(['Drifted','Under_Review'])).sum()),
        "unapproved":        int(cd['approver_name'].isna().sum()),
        "by_control_type":   {},
        "by_compliance":     {},
        "high_risk_changes": [],
        "dlp_incidents":     [],
    }

    # Per control type
    for ct, grp in cd.groupby('control_type'):
        result["by_control_type"][ct] = {
            "total":    int(len(grp)),
            "critical": int(grp['severity'].isin(['Critical','High']).sum()),
            "drifted":  int((grp['status'] == 'Drifted').sum()),
        }

    # Per compliance framework
    for cf, grp in cd[cd['compliance_impact'].notna()].groupby('compliance_impact'):
        result["by_compliance"][cf] = {
            "total":    int(len(grp)),
            "critical": int(grp['severity'].isin(['Critical','High']).sum()),
        }

    # High-risk changes: Critical/High severity + Drifted/Under_Review
    high_risk = cd[
        cd['severity'].isin(['Critical','High']) &
        cd['status'].isin(['Drifted','Under_Review'])
    ].copy()
    result["high_risk_changes"] = high_risk[
        ['drift_event_id','control_name','control_type','severity',
         'change_reason','operator_name','status','compliance_impact']
    ].head(20).to_dict('records')

    # DLP-specific incidents
    dlp = cd[cd['control_type'] == 'DLP'].copy()
    result["dlp_incidents"] = dlp[
        ['drift_event_id','control_name','baseline_value','current_value',
         'severity','status','operator_name','compliance_impact']
    ].head(20).to_dict('records')

    return result
