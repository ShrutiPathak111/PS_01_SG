"""
risk_engine.py — Hybrid Rule-Based + ML Risk Scoring
Matches the REAL CSV schema exactly.
Produces structured findings with compliance refs, remediation steps, and confidence scores.

PERFORMANCE NOTES (vs original):
  - parse_systems() is memoised: the same `systems_access` strings repeat across many
    users/rows, so repeated splitting is wasted work.
  - escalation_text() no longer rebuilds its lookup dict on every call.
  - analyse_user(): the duplicated `status == "failure"` filter (computed twice in the
    original) is now computed once and reused — both original findings are preserved
    exactly as before.
  - cluster_users() and compute_dept_baselines(): the per-group Python lambdas
    (`lambda x: (x == "...").sum()`, etc.) are replaced with vectorized boolean columns
    computed once over the whole frame, then aggregated with native sum/mean. This
    produces numerically identical results but avoids one Python function call per
    group per column.
  - The ML pieces (build_event_features, train_isolation_forest, ml_anomaly_scores,
    and the KMeans/StandardScaler/IsolationForest calls themselves) are unchanged.
"""

import json
from datetime import datetime
from functools import lru_cache
from typing import Optional

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.cluster import KMeans
from sklearn.preprocessing import LabelEncoder, StandardScaler

from src.config import (
    STALE_THRESHOLDS, MAX_SYSTEMS_PER_PRIV, PRIVILEGE_RANK,
    CRITICAL_IDENTITY_SYSTEMS, HIGH_RISK_IDENTITY_SYSTEMS,
    CRITICAL_RESOURCES, HIGH_RISK_ACTIONS,
    DEPT_EXPECTED_RESOURCES, DEPT_EXPECTED_SYSTEMS,
    BROAD_ACCESS_DEPTS, SOD_PAIRS, COMPLIANCE_MAP, SEVERITY_SCORE,
    IDENTITY_SYSTEM_IMPACT, RESOURCE_IMPACT,
)

ANALYSIS_DATE = datetime(2026, 4, 20)


# ── Helpers ───────────────────────────────────────────────────────────────────
@lru_cache(maxsize=None)
def _parse_systems_str(raw: str):
    """Cached split of a non-empty systems_access string."""
    return tuple(s.strip() for s in raw.split("|") if s.strip())


def parse_systems(raw):  # type: (...) -> List[str]
    """
    Same behaviour as before: returns [] for NaN/empty/"nan"/"None", otherwise the
    "|"-delimited, whitespace-trimmed list of system names.

    The actual split work is memoised via _parse_systems_str because the same
    systems_access strings recur across many users (e.g. shared role templates).
    """
    if pd.isna(raw) or str(raw).strip() in ("", "nan", "None"):
        return []
    return list(_parse_systems_str(str(raw)))


def severity_from_score(s: int) -> str:
    if s >= 80: return "CRITICAL"
    if s >= 60: return "HIGH"
    if s >= 35: return "MEDIUM"
    if s >= 15: return "LOW"
    return "INFORMATIONAL"


def compliance_refs(finding_type):  # type: (str) -> List[str]
    return COMPLIANCE_MAP.get(finding_type, ["NIST AU-6"])


# Hoisted out of escalation_text() so the dict is built once, not on every call.
_ESCALATION_TEXT = {
    "CRITICAL":      "🔴 IMMEDIATE — Security manager + CISO notification required",
    "HIGH":          "🟠 Within 24 hours — Team lead review required",
    "MEDIUM":        "🟡 Within 1 week — Schedule access review",
    "LOW":           "🟢 Next quarterly review — Add to monitoring",
    "INFORMATIONAL": "⚪ Log only — No action required",
}


def escalation_text(risk_level: str) -> str:
    return _ESCALATION_TEXT.get(risk_level, "⚪ Log only")


# ── User Analysis ─────────────────────────────────────────────────────────────
def analyse_user(
    row: pd.Series,
    user_events: pd.DataFrame,
    dept_baselines: dict = None,
) -> dict:
    """
    Full risk analysis for a single user.
    Returns structured finding JSON matching the expected output format from the problem spec.
    """
    findings = []
    score    = 0.0

    # Extract fields from real CSV
    uid          = str(row["user_id"])
    username     = str(row.get("username", uid))
    email        = str(row.get("email", ""))
    dept         = str(row.get("department", "")) if not pd.isna(row.get("department", "")) else ""
    job_title    = str(row.get("job_title", ""))
    priv         = str(row.get("privilege_level", "user")).lower()
    systems      = parse_systems(row.get("systems_access", ""))
    days_inactive= int(row.get("days_inactive", 0)) if not pd.isna(row.get("days_inactive", 0)) else 0
    is_active    = bool(row.get("is_active", True))

    hire_date_str = str(row.get("hire_date", "")) if not pd.isna(row.get("hire_date", "")) else ""
    try:
        hire_dt     = datetime.strptime(hire_date_str, "%Y-%m-%d")
        tenure_days = (ANALYSIS_DATE - hire_dt).days
    except Exception:
        tenure_days = 365

    is_new_hire    = tenure_days < 30
    is_contractor  = priv == "service-account"  # approximate from data

    # ── Finding 1: Stale account ──────────────────────────────────────────────
    stale_threshold = STALE_THRESHOLDS.get(priv, 45)
    if days_inactive > stale_threshold:
        if is_new_hire:
            # New hire exception: might not have logged in yet
            findings.append(_finding(
                "STALE_PRIVILEGED_ACCOUNT", "INFORMATIONAL",
                f"Account inactive {days_inactive} days but hired {tenure_days} days ago — new hire exception",
                "Confirm onboarding completed; verify first login within 30 days",
            ))
            score += 6
        elif priv == "service-account":
            sev = "HIGH" if days_inactive > stale_threshold * 2 else "MEDIUM"
            findings.append(_finding(
                "STALE_SERVICE_ACCOUNT", sev,
                f"Service account inactive {days_inactive} days — {days_inactive - stale_threshold}d "
                f"beyond the {stale_threshold}d service account threshold. Inactive service accounts "
                f"often indicate decommissioned applications whose credentials were never revoked, "
                f"creating a persistent backdoor that is difficult to detect through normal monitoring.",
                "Trace to owning application via CMDB; rotate credentials to surface hidden consumers; "
                "disable account if no auth failures observed after 48h; delete after 30-day monitoring "
                "window; update CMDB with decommission date",
            ))
            score += SEVERITY_SCORE[sev] * 0.65
        elif priv in ("admin", "power-user"):
            sev = "CRITICAL" if days_inactive > stale_threshold * 2.5 else "HIGH"
            findings.append(_finding(
                "STALE_PRIVILEGED_ACCOUNT", sev,
                f"{priv.replace('-',' ').title()} account inactive {days_inactive} days "
                f"({days_inactive - stale_threshold}d beyond the {stale_threshold}d threshold). "
                f"Privileged accounts left unmonitored create an undetected attack window — "
                f"a threat actor could use these credentials for weeks without triggering activity-based alerts. "
                f"Access to {len(systems)} system(s) amplifies the blast radius.",
                "Cross-reference with HR payroll system immediately; if employee departed, revoke all "
                "access within 2 hours; if on leave, implement temporary access suspension with "
                "manager approval; document in identity governance system",
            ))
            score += SEVERITY_SCORE[sev] * 0.72
        else:
            findings.append(_finding(
                "STALE_PRIVILEGED_ACCOUNT", "LOW",
                f"User account inactive {days_inactive} days — activity pattern suggests disuse or role change. "
                f"Stale accounts pose risk if credentials are compromised without detection.",
                "Verify with manager if still required; disable if inactive for business reason; "
                "clean up access entitlements during next quarterly review",
            ))
            score += 18

    # ── Finding 2: Over-privileged (system count) ──────────────────────────────
    max_sys = MAX_SYSTEMS_PER_PRIV.get(priv, 3)
    if len(systems) > max_sys:
        excess = len(systems) - max_sys
        is_broad_dept = dept in BROAD_ACCESS_DEPTS
        if is_broad_dept and priv == "admin":
            # IT/Security admins legitimately need broad access — informational only
            findings.append(_finding(
                "OVER_PRIVILEGED", "INFORMATIONAL",
                f"{dept} admin has {len(systems)} systems ({systems}) — broad access is expected "
                f"for this role and department. All {len(systems)} systems may be required for "
                f"day-to-day security and infrastructure operations.",
                "Conduct annual access review to confirm each system is still operationally required; "
                "document justification for each access right; ensure access is reviewed by department head",
            ))
            score += 6
        else:
            sev = "HIGH" if excess > 3 else "MEDIUM"
            findings.append(_finding(
                "OVER_PRIVILEGED", sev,
                f"{priv} account has {len(systems)} systems — {excess} beyond expected maximum of "
                f"{max_sys} for {priv} level in {dept or 'unknown department'}. "
                f"Excess systems include {', '.join(sorted(set(systems))[:3])}. "
                f"Violates least-privilege principle; each unneeded system increases blast radius.",
                f"Remove {excess} excess system access rights based on last 90-day usage report; "
                f"manager must sign off on retained access; schedule quarterly recertification",
            ))
            score += 20 + (excess * 6)

    # ── Finding 3: Critical system access for standard users ──────────────────
    critical_held = [s for s in systems if s in CRITICAL_IDENTITY_SYSTEMS]
    if critical_held and priv == "user" and dept not in BROAD_ACCESS_DEPTS:
        _crit_str = ", ".join(critical_held)
        findings.append(_finding(
            "CROSS_DEPT_SYSTEM_ACCESS", "HIGH",
            f"Standard user in {dept or 'unknown department'} ({job_title}) holds access to critical "
            f"identity systems: {', '.join(critical_held)}. These systems control authentication, "
            f"authorisation, and audit logs. A standard user role should not have admin-level "
            f"system access — this pattern matches insider threat and privilege escalation indicators.",
            f"Raise access review ticket immediately; validate business justification with department "
            f"head and CISO; remove access to {_crit_str} unless documented exceptional approval; "
            f"add to enhanced SIEM monitoring during review period",
        ))
        score += 48

    # ── Finding 3a: Role exception note for broad-access departments ─────────
    # PS example shows CTO_ROLE_EXCEPTION as INFORMATIONAL — we do equivalent
    if priv in ("admin", "power-user") and dept in BROAD_ACCESS_DEPTS:
        findings.append(_finding(
            "ROLE_EXCEPTION", "INFORMATIONAL",
            f"{dept} {priv} typically requires broad access for operational duties — "
            f"this account's {len(systems)} system access is expected for a {dept} role. "
            f"Flag only if policy has changed or account owner has departed.",
            f"Confirm {dept} role still requires this level of access; "
            f"verify with HR that account owner is still employed in this role; "
            f"review annually as part of {dept} access certification",
        ))

    # ── Finding 3b: Orphaned account (no department assignment) ─────────────
    if not dept or dept.lower() in ("", "nan", "none"):
        findings.append(_finding(
            "ORPHANED_ACCOUNT", "HIGH",
            f"Account has no department assignment — a strong indicator of an offboarding orphan. "
            f"Orphaned accounts with {priv} privilege and access to {len(systems)} systems "
            f"represent unmonitored privileged access with no accountable owner.",
            "Cross-reference with HR HRIS immediately; if employee has departed, revoke all "
            "access within 24 hours; escalate to CISO if access cannot be attributed to active staff",
        ))
        score += 55

    # ── Finding 4: No MFA-capable system for privileged accounts ─────────────
    if priv in ("admin", "power-user"):
        mfa_systems = {"Okta", "Azure_AD"}
        if not (mfa_systems & set(systems)):
            findings.append(_finding(
                "NO_MFA_PRIVILEGED", "HIGH",
                f"{priv} account has no MFA-capable system (Okta/Azure_AD) in access list — "
                f"admin actions unprotected by second factor",
                "Enroll in Okta or Azure AD MFA immediately; block privileged actions until enrolled",
            ))
            score += 42

    # ── Finding 4b: SoD violations (attach to user findings) ────────────────
    sys_set = set(systems)
    for sod_a, sod_b in SOD_PAIRS:
        if sod_a in sys_set and sod_b in sys_set:
            findings.append(_finding(
                "SOD_VIOLATION", "HIGH",
                f"Holds conflicting access pair [{sod_a} + {sod_b}] — this violates separation of duties. "
                f"With {sod_a} access, the user can modify data; with {sod_b}, they can alter audit logs "
                f"that would record those modifications, creating an undetectable fraud pathway. "
                f"Violates NIST AC-5, SOX Sec.404, and PCI-DSS Req.6.4.",
                f"Remove access to one of ({sod_a}, {sod_b}) immediately; if business critical, "
                "add compensating control with dual-approval workflow and enhanced SIEM monitoring; "
                "document in GRC system as accepted risk with executive sign-off",
            ))
            score += 45
            break  # Only report first SoD violation per user

    # ── Finding 5: Service account interactive login (from events) ────────────
    if priv == "service-account" and not user_events.empty:
        interactive = user_events[user_events["action"] == "login"]
        if len(interactive) >= 2:
            findings.append(_finding(
                "SERVICE_ACCOUNT_INTERACTIVE", "MEDIUM",
                f"Service account has {len(interactive)} interactive logins — service accounts should use "
                f"non-interactive API/certificate authentication only. Interactive logins indicate "
                f"possible shared credential misuse or manual access that bypasses privileged access controls.",
                "Convert to managed identity or service principal; restrict to certificate or API-key "
                "authentication; rotate all credentials immediately; audit all sessions",
            ))
            score += 28

    # ── Finding 6: Behavioural analysis from events ───────────────────────────
    if not user_events.empty:
        # After-hours high-risk actions
        night_high = user_events[
            user_events["time_classification"].isin(["night", "unusual_hours"]) &
            (user_events["resource_sensitivity"] == "high") &
            user_events["action"].isin(HIGH_RISK_ACTIONS)
        ]
        if len(night_high) >= 2:  # require 2+ events with expanded dataset
            resources_hit = night_high["resource"].unique()[:3]
            sev = "CRITICAL" if len(night_high) >= 4 else "HIGH"
            findings.append(_finding(
                "AFTER_HOURS_HIGH_RISK", sev,
                f"{len(night_high)} high-risk action(s) on sensitive resources during off-hours "
                f"({', '.join(resources_hit)}) — possible unauthorized access or compromised account",
                "Cross-check against change management; verify with on-call roster; escalate if unexplained",
            ))
            score += SEVERITY_SCORE[sev] * 0.60

        # Repeated authentication failures — computed once, reused by the two
        # REPEATED_AUTH_FAILURE checks below (both preserved exactly as before;
        # only the redundant `status == "failure"` filter has been de-duplicated).
        failure_mask = user_events["status"] == "failure"
        failures     = user_events[failure_mask]

        if len(failures) >= 3:  # require 3+ failures with expanded dataset
            resources_failed = failures["resource"].unique()[:3]
            sev = "HIGH" if len(failures) >= 4 else "MEDIUM"
            findings.append(_finding(
                "REPEATED_AUTH_FAILURE", sev,
                f"{len(failures)} authentication failures detected across {len(resources_failed)} "
                f"resource(s) ({', '.join(resources_failed)}) in the analysis period. "
                f"Pattern indicates either credential brute-force, expired/rotated passwords not "
                f"propagated, or misconfigured service accounts attempting unauthorised access.",
                "Review all failure logs to determine if manual or automated; if brute-force pattern, "
                "implement temporary IP block and alert SOC; verify credential validity and rotation; "
                "consider temporary account lockout pending investigation",
            ))
            score += 30 if sev == "HIGH" else 18

        # Bulk exports
        exports = user_events[user_events["action"] == "export_data"]
        high_exports = exports[exports["resource_sensitivity"] == "high"]
        if len(exports) >= 5 or len(high_exports) >= 2:  # raised threshold for larger dataset
            sev = "CRITICAL" if len(high_exports) >= 2 else "HIGH" if len(high_exports) == 1 else "MEDIUM"
            findings.append(_finding(
                "BULK_DATA_EXPORT", sev,
                f"{len(exports)} export events ({len(high_exports)} on high-sensitivity resources "
                f"including {', '.join(exports['resource'].unique()[:3])}) in analysis window",
                "Review DLP policy; require approval workflow for sensitive exports; check data destination",
            ))
            score += SEVERITY_SCORE[sev] * 0.68

        # Repeated authentication failures (second check — same `failures` frame reused)
        if len(failures) >= 3:
            sev = "HIGH" if len(failures) >= 5 else "MEDIUM"
            findings.append(_finding(
                "REPEATED_AUTH_FAILURE", sev,
                f"{len(failures)} failed access attempts — possible brute force, locked account, "
                f"or misconfigured service credential",
                "Review failure logs; consider temporary lockout; verify credential validity if service account",
            ))
            score += 22 + len(failures) * 3

        # Department-level anomaly (more events than peers)
        if dept_baselines and dept in dept_baselines:
            baseline = dept_baselines[dept]
            user_count = len(user_events)
            avg = baseline.get("avg_events", 3)
            std = max(baseline.get("std_events", 1), 0.5)
            z_score = (user_count - avg) / std
            if z_score > 2.5:
                findings.append(_finding(
                    "DEPT_LEVEL_ANOMALY", "MEDIUM",
                    f"{user_count} events vs dept average {avg:.1f} ± {std:.1f} "
                    f"({z_score:.1f}σ above norm for {dept}) — statistically anomalous activity volume",
                    "Investigate activity spike; cross-reference with peer accounts; verify no account sharing",
                ))
                score += 18

        # Cross-department resource access (events-level)
        if dept and dept in DEPT_EXPECTED_RESOURCES:
            expected_res = DEPT_EXPECTED_RESOURCES[dept]
            cross_res = user_events[
                ~user_events["resource"].isin(expected_res) &
                user_events["resource"].isin(CRITICAL_RESOURCES) &
                (user_events["resource_sensitivity"] == "high")
            ]
            if not cross_res.empty and priv == "user":
                findings.append(_finding(
                    "CROSS_DEPT_RESOURCE_ACCESS", "MEDIUM",
                    f"Standard user accessed {len(cross_res)} high-sensitivity resources outside "
                    f"{dept} scope: {', '.join(cross_res['resource'].unique()[:3])}",
                    "Verify business justification; raise access review ticket; review entitlements",
                ))
                score += 25

    # ── Final scoring ─────────────────────────────────────────────────────────
    final_score = min(int(score), 100)
    risk_level  = severity_from_score(final_score)

    # Confidence: drops when data is incomplete
    confidence  = 0.92
    if not hire_date_str:               confidence -= 0.08
    if user_events.empty:               confidence -= 0.10
    if pd.isna(row.get("last_login")): confidence -= 0.08
    confidence = max(round(confidence, 2), 0.40)

    # Aggregate suggested actions from HIGH+ findings
    actions = [f["recommendation"] for f in findings if f["severity"] in ("CRITICAL", "HIGH")]
    if not actions:
        actions = ["Continue automated monitoring — no immediate action required"]
    if risk_level == "CRITICAL":
        actions.append("Security manager review required immediately")

    # All compliance refs
    all_compliance = list({ref for f in findings for ref in f.get("compliance_refs", [])})

    return {
        "user_id":         uid,
        "username":        username,
        "email":           email,
        "department":      dept,
        "job_title":       job_title,
        "privilege_level": priv,
        "systems":         systems,
        "days_inactive":   days_inactive,
        "tenure_days":     tenure_days,
        "risk_level":      risk_level,
        "risk_score":      final_score,
        "findings":        findings,
        "confidence":      confidence,
        "suggested_actions": actions[:5],
        "next_escalation": escalation_text(risk_level),
        "compliance_refs": all_compliance,
    }


def _finding(type_: str, severity: str, detail: str, recommendation: str) -> dict:
    return {
        "type":            type_,
        "severity":        severity,
        "detail":          detail,
        "recommendation":  recommendation,
        "compliance_refs": compliance_refs(type_),
    }


# ── Event Analysis ────────────────────────────────────────────────────────────
def analyse_event(row, user_row=None):
    # type: (pd.Series, Optional[pd.Series]) -> dict
    """
    Precision-tuned event risk analysis.
    Rules calibrated against ground-truth labels to maximise BOTH precision AND recall.

    True positive patterns from label analysis:
      CROSS_DEPT_ACCESS    -> admin_operation OR sql_query on critical resource by standard user
                              (NOT file_access/login/api_call - those are normal)
      BULK_DATA_EXPORT     -> export_data HIGH sensitivity (any time)
                              OR export_data off-hours MEDIUM sensitivity
                              (NOT medium sensitivity during business hours - too many FPs)
      AFTER_HOURS_HIGH_RISK -> high-risk action + high sensitivity + night/unusual + non-oncall
      AFTER_HOURS_ADMIN    -> admin_operation during off-hours, non-oncall dept
      AUTH_FAILURE         -> login failure only (not api_call/file_access failures)
    """
    findings = []
    score    = 0.0

    action      = str(row.get("action", ""))
    resource    = str(row.get("resource", ""))
    sensitivity = str(row.get("resource_sensitivity", "low"))
    time_cls    = str(row.get("time_classification", "business_hours"))
    status      = str(row.get("status", "success"))

    priv     = str(user_row.get("privilege_level", "user")) if user_row is not None else "user"
    dept     = str(user_row.get("department", "")) if user_row is not None else ""
    off_hrs  = time_cls in ("night", "unusual_hours", "weekend")
    is_night = time_cls in ("night", "unusual_hours")
    on_call  = dept in ("Security", "IT", "Engineering", "Operations")

    # ── Rule 1: CROSS_DEPT_ACCESS ─────────────────────────────────────────────
    # Only admin_operation + sql_query trigger this (not file_access/login/api_call)
    if (priv == "user"
            and resource in CRITICAL_RESOURCES
            and action in ("admin_operation", "sql_query")):
        sev = "HIGH" if sensitivity == "high" else "MEDIUM"
        findings.append({
            "type":            "CROSS_DEPT_RESOURCE_ACCESS",
            "severity":        sev,
            "detail":          (
                f"Standard user performing {action} on critical resource {resource} "
                f"({sensitivity} sensitivity) in {dept or 'unknown'} department. "
                f"Admin and SQL operations on critical systems require elevated privilege — "
                f"this does not match a standard user role entitlement."
            ),
            "recommendation":  (
                f"Validate business justification with {dept or 'department'} manager; "
                f"raise access review ticket; verify no privilege escalation occurred"
            ),
            "compliance_refs": compliance_refs("CROSS_DEPT_RESOURCE_ACCESS"),
        })
        score += 62 if sev == "HIGH" else 42

    # ── Rule 2: BULK_DATA_EXPORT ──────────────────────────────────────────────
    # HIGH sensitivity: always flag | MEDIUM sensitivity: only off-hours
    # LOW sensitivity or MEDIUM during business hours: NOT flagged (FP pattern)
    if action == "export_data":
        if sensitivity == "high":
            sev    = "HIGH"
            detail = (
                f"Export from {resource} (HIGH sensitivity)"
                + (f" during {time_cls} — off-hours high-sens export is critical risk" if off_hrs
                   else " — high-sensitivity data export requires DLP compliance review")
            )
            score += 62
            findings.append({
                "type":            "BULK_DATA_EXPORT",
                "severity":        sev,
                "detail":          detail,
                "recommendation":  (
                    "Verify DLP policy compliance; confirm data destination and recipient; "
                    "check approval workflow; review against authorised export schedule"
                ),
                "compliance_refs": compliance_refs("BULK_DATA_EXPORT"),
            })
        elif sensitivity == "medium" and off_hrs:
            findings.append({
                "type":            "BULK_DATA_EXPORT",
                "severity":        "MEDIUM",
                "detail":          (
                    f"Export from {resource} (medium sensitivity) during {time_cls}. "
                    f"Off-hours medium-sensitivity exports warrant DLP review."
                ),
                "recommendation":  (
                    "Confirm business justification for off-hours export; "
                    "verify data destination; review DLP policy compliance"
                ),
                "compliance_refs": compliance_refs("BULK_DATA_EXPORT"),
            })
            score += 42
        # else: low sensitivity or medium during business hours = NOT flagged

    # ── Rule 3: AFTER_HOURS_HIGH_RISK ────────────────────────────────────────
    # high-risk action + high sensitivity + night/unusual + non-oncall dept
    if (is_night
            and sensitivity == "high"
            and action in HIGH_RISK_ACTIONS
            and not on_call):
        if not any(f["type"] == "AFTER_HOURS_HIGH_RISK" for f in findings):
            findings.append({
                "type":            "AFTER_HOURS_HIGH_RISK",
                "severity":        "HIGH",
                "detail":          (
                    f"{action} on {resource} (high sensitivity) during {time_cls} "
                    f"by {priv} in {dept or 'unknown'} — high-risk operation on sensitive "
                    f"resource outside business hours requires approved change window."
                ),
                "recommendation":  (
                    "Cross-check ServiceNow change calendar; "
                    "verify on-call roster; escalate to SOC if unexplained"
                ),
                "compliance_refs": compliance_refs("AFTER_HOURS_HIGH_RISK"),
            })
            score += 65

    # ── Rule 4: AFTER_HOURS_ADMIN ─────────────────────────────────────────────
    # admin_operation during off-hours by any privilege, non-oncall dept
    if (action == "admin_operation"
            and off_hrs
            and not on_call):
        if not any(f["type"] == "AFTER_HOURS_HIGH_RISK" for f in findings):
            sev = "HIGH" if is_night else "MEDIUM"
            findings.append({
                "type":            "AFTER_HOURS_HIGH_RISK",
                "severity":        sev,
                "detail":          (
                    f"Admin operation on {resource} during {time_cls}. "
                    f"Administrative changes outside business hours require an approved "
                    f"change window — unapproved admin ops may bypass standard audit controls."
                ),
                "recommendation":  (
                    "Verify approved change window in ServiceNow; "
                    "if no change record exists raise urgent ticket and notify SOC"
                ),
                "compliance_refs": compliance_refs("AFTER_HOURS_HIGH_RISK"),
            })
            score += 55 if sev == "HIGH" else 38

    # ── Rule 5: AUTH_FAILURE (login only) ────────────────────────────────────
    # Labels show AUTH_FAILURE only for login failures, not api_call/file_access
    if status == "failure" and action == "login":
        findings.append({
            "type":            "REPEATED_AUTH_FAILURE",
            "severity":        "MEDIUM",
            "detail":          (
                f"Failed login on {resource} ({sensitivity} sensitivity). "
                f"Login failures indicate potential brute-force, expired credentials, "
                f"or misconfigured service attempting unauthorised access."
            ),
            "recommendation":  (
                "Monitor for repeated failures; verify credential validity; "
                "consider temporary lockout if failure pattern continues across sessions"
            ),
            "compliance_refs": compliance_refs("REPEATED_AUTH_FAILURE"),
        })
        score += 38

    # ── Rule 6: SQL on PROD_DB off-hours ─────────────────────────────────────
    if (action == "sql_query"
            and resource == "PROD_DB"
            and off_hrs
            and not on_call):
        if not any(f["type"] == "AFTER_HOURS_HIGH_RISK" for f in findings):
            findings.append({
                "type":            "AFTER_HOURS_HIGH_RISK",
                "severity":        "HIGH",
                "detail":          (
                    f"SQL query on PROD_DB during {time_cls}. "
                    f"Direct production database access outside business hours "
                    f"requires DBA authorisation and change management record."
                ),
                "recommendation":  (
                    "Verify scheduled job or emergency DBA access; "
                    "check change management record; DBA team review required"
                ),
                "compliance_refs": compliance_refs("AFTER_HOURS_HIGH_RISK"),
            })
            score += 60

    final_score = min(int(score), 100)
    return {
        "event_id":   str(row.get("timestamp", "")) + "_" + str(row.get("user_id", "")),
        "user_id":    str(row.get("user_id", "")),
        "timestamp":  str(row.get("timestamp", "")),
        "action":     action,
        "resource":   resource,
        "sensitivity":sensitivity,
        "time_class": time_cls,
        "status":     status,
        "source_ip":  str(row.get("source_ip", "")),
        "risk_level": severity_from_score(final_score),
        "risk_score": final_score,
        "findings":   findings,
    }


# ── ML feature pipeline (unchanged) ────────────────────────────────────────────
def build_event_features(events_df):  # type: (pd.DataFrame) -> tuple
    df = events_df.copy()
    le = {}
    for col in ("action", "resource", "time_classification", "resource_sensitivity"):
        le[col] = LabelEncoder()
        df[f"{col}_code"] = le[col].fit_transform(df[col].fillna("unknown"))

    df["is_failure"]    = (df["status"] == "failure").astype(int)
    df["is_night"]      = df["time_classification"].isin(["night", "unusual_hours"]).astype(int)
    df["is_high_sens"]  = (df["resource_sensitivity"] == "high").astype(int)
    df["is_admin_act"]  = (df["action"] == "admin_operation").astype(int)
    df["is_export"]     = (df["action"] == "export_data").astype(int)
    df["is_sql"]        = (df["action"] == "sql_query").astype(int)
    df["is_crit_res"]   = df["resource"].isin(CRITICAL_RESOURCES).astype(int)
    df["is_weekend"]    = (df["time_classification"] == "weekend").astype(int)

    feat_cols = [
        "action_code", "resource_code", "time_classification_code",
        "resource_sensitivity_code", "is_failure", "is_night", "is_high_sens",
        "is_admin_act", "is_export", "is_sql", "is_crit_res", "is_weekend",
    ]
    return df[feat_cols], feat_cols


def train_isolation_forest(events_df):  # type: (pd.DataFrame) -> tuple
    X, feat_cols = build_event_features(events_df)
    scaler = StandardScaler()
    Xs     = scaler.fit_transform(X)
    model  = IsolationForest(n_estimators=100, contamination=0.15, random_state=42, n_jobs=1)
    model.fit(Xs)
    return model, scaler, feat_cols


def ml_anomaly_scores(events_df, model, scaler, feat_cols):  # type: (...) -> np.ndarray
    """Return anomaly scores 0-100 (higher = more anomalous)."""
    X, _ = build_event_features(events_df)
    Xs   = scaler.transform(X[feat_cols])
    raw  = model.decision_function(Xs)
    # Normalise: more negative = more anomalous → higher score
    scores = 100 * (1 - (raw - raw.min()) / (raw.max() - raw.min() + 1e-9))
    return scores


# ── Behavioural Clustering ────────────────────────────────────────────────────
def cluster_users(users_df, events_df, n_clusters=5):  # type: (pd.DataFrame, pd.DataFrame, int) -> tuple

    # Precompute the boolean flags ONCE, vectorized over the whole events frame,
    # instead of running a Python lambda per column per user-group. The resulting
    # per-user sums are numerically identical to the original
    # `lambda x: (x == "...").sum()` aggregations.
    ev = events_df.assign(
        _is_night     = events_df["time_classification"].isin(["night", "unusual_hours"]),
        _is_export    = events_df["action"] == "export_data",
        _is_admin     = events_df["action"] == "admin_operation",
        _is_failure   = events_df["status"] == "failure",
        _is_high_sens = events_df["resource_sensitivity"] == "high",
        _is_sql       = events_df["action"] == "sql_query",
    )

    uev = ev.groupby("user_id").agg(
        total_events     = ("action", "count"),
        unique_resources = ("resource", "nunique"),
        night_events     = ("_is_night", "sum"),
        export_count     = ("_is_export", "sum"),
        admin_count      = ("_is_admin", "sum"),
        failure_count    = ("_is_failure", "sum"),
        high_sens_count  = ("_is_high_sens", "sum"),
        sql_count        = ("_is_sql", "sum"),
    ).reset_index()

    merged = users_df.merge(uev, on="user_id", how="left").fillna(0)
    merged["priv_rank"]    = merged["privilege_level"].map(PRIVILEGE_RANK).fillna(1)
    merged["system_count"] = merged["systems_access"].apply(lambda x: len(parse_systems(x)))

    feature_cols = [
        "priv_rank", "system_count", "days_inactive",
        "total_events", "night_events", "export_count",
        "admin_count", "failure_count", "high_sens_count",
        "unique_resources", "sql_count",
    ]
    X      = merged[feature_cols].astype(float)
    scaler = StandardScaler()
    Xs     = scaler.fit_transform(X)

    kmeans = KMeans(n_clusters=n_clusters, random_state=42, n_init=5)
    merged["cluster"] = kmeans.fit_predict(Xs)

    # Name clusters by dominant characteristics
    cluster_profiles = {}
    for cid in range(n_clusters):
        sub = merged[merged["cluster"] == cid]
        label = _cluster_label(sub)
        cluster_profiles[cid] = {
            "id":               cid,
            "label":            label,
            "size":             len(sub),
            "user_ids":         sub["user_id"].tolist(),
            "avg_inactive":     round(sub["days_inactive"].mean(), 1),
            "avg_events":       round(sub["total_events"].mean(), 1),
            "avg_night":        round(sub["night_events"].mean(), 1),
            "avg_exports":      round(sub["export_count"].mean(), 1),
            "avg_admin":        round(sub["admin_count"].mean(), 1),
            "dominant_priv":    sub["privilege_level"].mode()[0] if len(sub) > 0 else "user",
            "avg_system_count": round(sub["system_count"].mean(), 1),
        }

    merged["cluster_label"] = merged["cluster"].map(lambda c: cluster_profiles[c]["label"])
    return merged, cluster_profiles


def _cluster_label(sub: pd.DataFrame) -> str:
    dominant_priv = sub["privilege_level"].mode()[0] if len(sub) > 0 else "user"
    avg_inactive  = sub["days_inactive"].mean()
    avg_admin     = sub.get("admin_count", pd.Series([0])).mean()
    avg_export    = sub.get("export_count", pd.Series([0])).mean()
    avg_night     = sub.get("night_events", pd.Series([0])).mean()
    avg_sys       = sub.get("system_count", pd.Series([0])).mean()

    if dominant_priv == "admin" and avg_inactive > 25:     return "Stale Admins"
    if dominant_priv == "admin" and avg_admin > 3:         return "Active Admins"
    if avg_export > 2:                                     return "Heavy Exporters"
    if avg_night > 2:                                       return "Night Operators"
    if avg_sys > 5 and dominant_priv == "power-user":      return "Power Brokers"
    if dominant_priv == "service-account":                 return "Service Accounts"
    return "Normal Users"


# ── Department Baselines ──────────────────────────────────────────────────────
def compute_dept_baselines(users_df, events_df):  # type: (pd.DataFrame, pd.DataFrame) -> dict
    user_dept = users_df[["user_id", "department"]].set_index("user_id")
    ev = events_df.assign(department=events_df["user_id"].map(user_dept["department"]))

    # Precompute boolean flags once (vectorized) instead of recomputing the same
    # comparison inside a lambda for every department group.
    ev = ev.assign(
        _is_night     = ev["time_classification"].isin(["night", "unusual_hours"]),
        _is_failure   = ev["status"] == "failure",
        _is_export    = ev["action"] == "export_data",
        _is_admin     = ev["action"] == "admin_operation",
        _is_high_sens = ev["resource_sensitivity"] == "high",
    )

    dept_agg = ev.groupby("department").agg(
        total_events   = ("action", "count"),
        night_rate     = ("_is_night", "mean"),
        failure_rate   = ("_is_failure", "mean"),
        export_rate    = ("_is_export", "mean"),
        admin_rate     = ("_is_admin", "mean"),
        high_sens_rate = ("_is_high_sens", "mean"),
    )

    per_user_counts = ev.groupby(["department", "user_id"]).size()
    per_user_stats  = per_user_counts.groupby("department").agg(
        avg_events    = "mean",
        std_events    = "std",
        users_in_dept = "count",
    )

    baselines = {}
    for dept in dept_agg.index:
        row = dept_agg.loc[dept]
        pu  = per_user_stats.loc[dept]
        std = pu["std_events"]
        baselines[dept] = {
            "avg_events":     round(pu["avg_events"], 2),
            "std_events":     round(std, 2) if pu["users_in_dept"] > 1 and not pd.isna(std) else 1.0,
            "night_rate":     round(row["night_rate"], 3),
            "failure_rate":   round(row["failure_rate"], 3),
            "export_rate":    round(row["export_rate"], 3),
            "admin_rate":     round(row["admin_rate"], 3),
            "high_sens_rate": round(row["high_sens_rate"], 3),
            "total_events":   int(row["total_events"]),
            "users_in_dept":  int(pu["users_in_dept"]),
        }
    return baselines


# ── SoD Detection ─────────────────────────────────────────────────────────────
def detect_sod_violations(users_df):  # type: (pd.DataFrame) -> list
    violations = []
    for _, row in users_df.iterrows():
        # parse_systems is memoised, so repeated systems_access strings
        # (common across users sharing a role template) are split only once.
        systems = set(parse_systems(row.get("systems_access", "")))
        for sys_a, sys_b in SOD_PAIRS:
            if sys_a in systems and sys_b in systems:
                violations.append({
                    "user_id":        str(row["user_id"]),
                    "username":       str(row.get("username", row["user_id"])),
                    "department":     str(row.get("department", "")),
                    "privilege":      str(row.get("privilege_level", "")),
                    "systems":        [sys_a, sys_b],
                    "severity":       "HIGH",
                    "finding":        "SOD_VIOLATION",
                    "detail":         f"Holds both {sys_a} AND {sys_b} — separation of duties conflict. "
                                      f"Could modify {sys_a} data and then alter {sys_b} audit records.",
                    "recommendation": f"Remove access to one of ({sys_a}, {sys_b}); implement role segregation",
                    "compliance":     COMPLIANCE_MAP["SOD_VIOLATION"],
                })
    return violations


# ── Compliance Gap Analysis ───────────────────────────────────────────────────
def compliance_gaps_for_user(user_result):  # type: (dict) -> dict
    """Per-user compliance gap breakdown by framework."""
    gaps = {}
    for f in user_result.get("findings", []):
        for ref in f.get("compliance_refs", []):
            fw = ref.split(" ")[0]
            if fw not in gaps:
                gaps[fw] = []
            gaps[fw].append({
                "control":   ref,
                "finding":   f["type"],
                "severity":  f["severity"],
            })
    return gaps


def compliance_gaps_per_system(users_df: pd.DataFrame, user_results: list) -> dict:
    """Per-system compliance violation aggregation."""
    sys_gaps = {}
    result_map = {r["user_id"]: r for r in user_results}

    for _, row in users_df.iterrows():
        uid = str(row["user_id"])
        res = result_map.get(uid, {})
        for f in res.get("findings", []):
            for sys in parse_systems(row.get("systems_access", "")):
                if sys not in sys_gaps:
                    sys_gaps[sys] = {"violations": [], "sev_counts": {}}
                sys_gaps[sys]["violations"].append({
                    "user_id":  uid,
                    "finding":  f["type"],
                    "severity": f["severity"],
                })
                sc = sys_gaps[sys]["sev_counts"]
                sc[f["severity"]] = sc.get(f["severity"], 0) + 1

    return sys_gaps