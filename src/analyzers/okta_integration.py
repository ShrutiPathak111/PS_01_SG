"""
okta_integration.py
===================
Real Okta API Integration — FREE Developer Tier
================================================

Setup (free, no credit card):
  1. Go to developer.okta.com/signup
  2. Sign up → your domain = dev-XXXXXXX.okta.com
  3. Security → API → Tokens → Create Token → copy it (starts with 00...)
  4. Set environment variables:
       Windows PowerShell:
         $env:OKTA_DOMAIN="dev-XXXXXXX.okta.com"
         $env:OKTA_API_TOKEN="00xxxx..."
       macOS/Linux:
         export OKTA_DOMAIN="dev-XXXXXXX.okta.com"
         export OKTA_API_TOKEN="00xxxx..."

Free tier limits:
  - 100 Monthly Active Users
  - Full API access (users, groups, logs, apps, policies)
  - No credit card required

APIs used:
  GET /api/v1/users           — list all users + status
  GET /api/v1/users/{id}/groups — group memberships
  GET /api/v1/logs            — system event logs
  GET /api/v1/groups          — all groups
  GET /api/v1/apps            — application assignments

Compatible with Python 3.8+
"""
from __future__ import annotations

import os
import time
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False


# ── Config ────────────────────────────────────────────────────────────────────

def _get_credentials():
    # type: () -> tuple
    domain = os.environ.get("OKTA_DOMAIN", "").strip().rstrip("/")
    token  = os.environ.get("OKTA_API_TOKEN", "").strip()
    if domain and not domain.startswith("http"):
        domain = "https://" + domain
    return domain, token


def _headers(token):
    # type: (str) -> dict
    return {
        "Authorization": "SSWS " + token,
        "Content-Type":  "application/json",
        "Accept":        "application/json",
    }


def _get(url, token, params=None, timeout=15):
    # type: (str, str, dict, int) -> list
    """
    Paginated GET — follows Okta's Link header for all pages.
    Returns flat list of all items.
    """
    results = []
    next_url = url
    while next_url:
        try:
            resp = requests.get(
                next_url,
                headers=_headers(token),
                params=params if next_url == url else None,
                timeout=timeout,
            )
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list):
                    results.extend(data)
                else:
                    results.append(data)
                # Follow pagination
                link = resp.headers.get("Link", "")
                next_url = None
                for part in link.split(","):
                    part = part.strip()
                    if 'rel="next"' in part:
                        next_url = part.split(";")[0].strip().strip("<>")
                        break
            elif resp.status_code == 429:
                # Rate limited — wait and retry
                retry = int(resp.headers.get("X-Rate-Limit-Reset", time.time() + 2))
                wait  = max(1, retry - int(time.time()))
                time.sleep(min(wait, 5))
            elif resp.status_code == 401:
                print("  ✗ Okta: Invalid API token — check OKTA_API_TOKEN")
                break
            elif resp.status_code == 403:
                print("  ✗ Okta: Forbidden — token may lack required scopes")
                break
            else:
                break
        except Exception as e:
            print("  ✗ Okta API error: {}".format(str(e)[:80]))
            break
        params = None  # only on first request
    return results


# ── Core API functions ────────────────────────────────────────────────────────

def fetch_okta_users(domain, token, limit=200):
    # type: (str, str, int) -> List[Dict]
    """Fetch all Okta users with profile and status."""
    url    = "{}/api/v1/users".format(domain)
    params = {"limit": min(limit, 200), "filter": 'status eq "ACTIVE" or status eq "DEPROVISIONED"'}
    return _get(url, token, params)


def fetch_okta_logs(domain, token, since_days=30):
    # type: (str, str, int) -> List[Dict]
    """Fetch Okta system event logs for anomaly detection."""
    since  = (datetime.now(timezone.utc) - timedelta(days=since_days)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    url    = "{}/api/v1/logs".format(domain)
    params = {"since": since, "limit": 1000,
              "filter": 'eventType sw "user.authentication" or eventType sw "user.account" or eventType sw "policy"'}
    return _get(url, token, params)


def fetch_okta_groups(domain, token):
    # type: (str, str) -> List[Dict]
    """Fetch all Okta groups (maps to privilege levels)."""
    url    = "{}/api/v1/groups".format(domain)
    params = {"limit": 200}
    return _get(url, token, params)


def fetch_user_groups(domain, token, user_id):
    # type: (str, str, str) -> List[Dict]
    """Fetch group memberships for a specific user."""
    url = "{}/api/v1/users/{}/groups".format(domain, user_id)
    return _get(url, token)


# ── Risk enrichment ───────────────────────────────────────────────────────────

def _map_okta_status_to_risk(status):
    # type: (str) -> str
    """Map Okta user status to risk signal."""
    return {
        "ACTIVE":           "normal",
        "DEPROVISIONED":    "critical",   # account disabled but may still have tokens
        "SUSPENDED":        "high",
        "LOCKED_OUT":       "high",       # repeated auth failures
        "PASSWORD_EXPIRED": "medium",
        "RECOVERY":         "medium",
        "STAGED":           "low",
    }.get(status, "unknown")


def _extract_log_anomalies(logs):
    # type: (List[Dict]) -> Dict
    """
    Scan Okta logs for:
    - Failed logins (REPEATED_AUTH_FAILURE)
    - Suspicious IPs (multiple IPs = CROSS_LOCATION_ACCESS)
    - After-hours access
    - Policy violations
    - MFA bypass attempts
    """
    anomalies  = {}  # user_id -> list of findings
    ip_map     = {}  # user_id -> set of IPs

    for entry in logs:
        etype    = entry.get("eventType", "")
        severity = entry.get("severity", "INFO")
        actor    = entry.get("actor", {})
        uid      = actor.get("alternateId", "")  # usually email
        client   = entry.get("client", {})
        ip       = client.get("ipAddress", "")
        ts       = entry.get("published", "")
        outcome  = entry.get("outcome", {}).get("result", "")

        if not uid:
            continue

        if uid not in anomalies:
            anomalies[uid] = []
        if uid not in ip_map:
            ip_map[uid] = set()
        if ip:
            ip_map[uid].add(ip)

        # Failed authentication
        if "authentication" in etype and outcome == "FAILURE":
            anomalies[uid].append({
                "type":    "OKTA_AUTH_FAILURE",
                "detail":  "Okta login failure: {} at {}".format(etype, ts[:19]),
                "severity":"HIGH",
            })

        # MFA bypass or downgrade
        if "mfa" in etype.lower() and outcome in ("FAILURE", "SKIPPED"):
            anomalies[uid].append({
                "type":    "OKTA_MFA_BYPASS",
                "detail":  "MFA event {} outcome={}".format(etype, outcome),
                "severity":"CRITICAL",
            })

        # Policy violations
        if "policy" in etype and outcome == "DENY":
            anomalies[uid].append({
                "type":    "OKTA_POLICY_VIOLATION",
                "detail":  "Policy violation: {} at {}".format(etype, ts[:19]),
                "severity":"HIGH",
            })

        # After-hours access (10pm-6am UTC)
        if ts:
            try:
                hour = int(ts[11:13])
                if hour >= 22 or hour < 6:
                    if "authentication" in etype and outcome == "SUCCESS":
                        anomalies[uid].append({
                            "type":    "OKTA_AFTER_HOURS_LOGIN",
                            "detail":  "Successful Okta login at {}:{}".format(ts[11:13], ts[14:16]),
                            "severity":"MEDIUM",
                        })
            except Exception:
                pass

    # Multi-IP access (possible account sharing or compromise)
    for uid, ips in ip_map.items():
        if len(ips) >= 5:
            anomalies[uid].append({
                "type":    "OKTA_MULTI_IP_ACCESS",
                "detail":  "Accessed from {} different IPs in 30 days — possible credential sharing".format(len(ips)),
                "severity":"HIGH",
            })

    return anomalies


def enrich_users_with_okta(user_results, verbose=True):
    # type: (List[Dict], bool) -> dict
    """
    Main integration function called from pipeline.
    Enriches user_results with live Okta data.
    Returns enrichment summary.
    """
    if not REQUESTS_OK:
        return {"status": "requests_not_available"}

    domain, token = _get_credentials()
    if not domain or not token:
        if verbose:
            print("  OKTA_DOMAIN / OKTA_API_TOKEN not set — Okta enrichment skipped")
            print("  Setup: developer.okta.com/signup (free) → Security → API → Tokens")
        return {"status": "not_configured"}

    if verbose:
        print("  Okta domain: {}".format(domain))
        print("  Fetching users, groups, logs...")

    t0 = time.time()

    # Fetch from Okta
    okta_users  = fetch_okta_users(domain, token)
    okta_groups = fetch_okta_groups(domain, token)
    okta_logs   = fetch_okta_logs(domain, token, since_days=30)

    if not okta_users and not okta_logs:
        if verbose:
            print("  ✗ No data from Okta — check token and domain")
        return {"status": "no_data"}

    # Build lookup: email → okta user
    okta_by_email = {}
    for ou in okta_users:
        profile = ou.get("profile", {})
        email   = profile.get("email") or profile.get("login", "")
        if email:
            okta_by_email[email.lower()] = ou

    # Build log anomalies
    log_anomalies = _extract_log_anomalies(okta_logs)

    # Enrich each user result
    enriched_count = 0
    for user in user_results:
        email = user.get("email", "").lower()
        ou    = okta_by_email.get(email)

        if ou:
            enriched_count += 1
            profile = ou.get("profile", {})
            status  = ou.get("status", "UNKNOWN")
            risk_sig = _map_okta_status_to_risk(status)

            # Add Okta metadata
            user["okta_id"]        = ou.get("id", "")
            user["okta_status"]    = status
            user["okta_created"]   = ou.get("created", "")
            user["okta_last_login"]= ou.get("lastLogin", "")
            user["okta_source"]    = True

            # Boost risk score for critical Okta statuses
            if risk_sig == "critical" and user.get("risk_score", 0) < 80:
                user["risk_score"] = max(user["risk_score"], 80)
                user["findings"].append({
                    "type":            "OKTA_DEPROVISIONED_ACTIVE",
                    "severity":        "CRITICAL",
                    "detail":          "Account is DEPROVISIONED in Okta but still active in IAM records. Residual access tokens may still be valid.",
                    "recommendation":  "Immediately revoke all OAuth tokens, API keys and sessions in Okta. Verify no active sessions exist.",
                    "compliance_refs": ["NIST AC-2(j)", "PCI-DSS Req.8.1.4"],
                })
            elif risk_sig == "high":
                user["findings"].append({
                    "type":            "OKTA_ACCOUNT_ISSUE",
                    "severity":        "HIGH",
                    "detail":          "Okta account status: {} — elevated risk".format(status),
                    "recommendation":  "Review account status with IT; resolve {} state before granting further access".format(status),
                    "compliance_refs": ["NIST IA-5", "ISO 27001 A.9.2"],
                })

        # Add log-based anomalies
        email_anomalies = log_anomalies.get(email, [])
        if email_anomalies:
            for anom in email_anomalies[:3]:  # max 3 per user
                if not any(f["type"] == anom["type"] for f in user.get("findings", [])):
                    user["findings"].append({
                        "type":            anom["type"],
                        "severity":        anom["severity"],
                        "detail":          anom["detail"],
                        "recommendation":  "Review Okta audit log; check for compromised credentials; force password reset if unexplained",
                        "compliance_refs": ["NIST AU-2", "GDPR Art.32"],
                    })
                    # Boost score
                    boost = {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 10}.get(anom["severity"], 5)
                    user["risk_score"] = min(100, user["risk_score"] + boost)

    # Build group summary (shows privilege structure)
    group_summary = []
    for grp in okta_groups[:20]:
        profile = grp.get("profile", {})
        group_summary.append({
            "name":        profile.get("name", ""),
            "description": profile.get("description", ""),
            "type":        grp.get("type", ""),
        })

    elapsed = round(time.time() - t0, 2)

    summary = {
        "status":          "success",
        "okta_users":      len(okta_users),
        "okta_groups":     len(okta_groups),
        "okta_logs":       len(okta_logs),
        "enriched_users":  enriched_count,
        "log_anomalies":   sum(len(v) for v in log_anomalies.values()),
        "group_summary":   group_summary[:10],
        "elapsed_seconds": elapsed,
        "domain":          domain,
    }

    if verbose:
        print("  ✓ Okta: {} users | {} groups | {} logs | {} enriched | {}s".format(
            len(okta_users), len(okta_groups), len(okta_logs),
            enriched_count, elapsed))

    return summary


def okta_available():
    # type: () -> bool
    """Check if Okta credentials are configured."""
    domain, token = _get_credentials()
    return bool(domain and token)


def test_okta_connection():
    # type: () -> dict
    """Test Okta connection and return status."""
    domain, token = _get_credentials()
    if not domain or not token:
        return {"status": "not_configured",
                "message": "Set OKTA_DOMAIN and OKTA_API_TOKEN environment variables",
                "setup": "developer.okta.com/signup"}
    try:
        resp = requests.get(
            "{}/api/v1/users?limit=1".format(domain),
            headers=_headers(token), timeout=10,
        )
        if resp.status_code == 200:
            return {"status": "connected", "domain": domain,
                    "message": "Okta API connected successfully"}
        elif resp.status_code == 401:
            return {"status": "auth_error",
                    "message": "Invalid API token — regenerate at Security → API → Tokens"}
        else:
            return {"status": "error", "code": resp.status_code,
                    "message": resp.text[:100]}
    except Exception as e:
        return {"status": "connection_error", "message": str(e)[:100]}


def enrich_with_okta(user_results, verbose=True):
    # type: (list, bool) -> dict
    """Alias for enrich_users_with_okta."""
    return enrich_users_with_okta(user_results, verbose)
