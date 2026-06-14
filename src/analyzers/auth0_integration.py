"""
auth0_integration.py
====================
Real Auth0 Management API Integration
======================================

Auth0 is an enterprise identity platform (like Okta).
The Management API gives us: users, logs, roles, connections.

Credentials from your Auth0 dashboard:
  Domain:        dev-nyszo0u2qvsxv1yw.us.auth0.com
  Client ID:     icS6RlWVo1jMwoLnf1IsqlHov25cuDlA
  Client Secret: c2mh5dYs_-q82w8DdwjJ5yyvLxr1dCzesbEwaBjqvSr3yRn_61MeMZ-olKrEIOyJ

Set these environment variables before running main.py:
  Windows PowerShell:
    $env:AUTH0_DOMAIN="dev-nyszo0u2qvsxv1yw.us.auth0.com"
    $env:AUTH0_CLIENT_ID="icS6RlWVo1jMwoLnf1IsqlHov25cuDlA"
    $env:AUTH0_CLIENT_SECRET="c2mh5dYs_-q82w8DdwjJ5yyvLxr1dCzesbEwaBjqvSr3yRn_61MeMZ-olKrEIOyJ"

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


# ── Credentials ───────────────────────────────────────────────────────────────

AUTH0_DOMAIN        = "dev-nyszo0u2qvsxv1yw.us.auth0.com"
AUTH0_CLIENT_ID     = "icS6RlWVo1jMwoLnf1IsqlHov25cuDlA"
AUTH0_CLIENT_SECRET = "c2mh5dYs_-q82w8DdwjJ5yyvLxr1dCzesbEwaBjqvSr3yRn_61MeMZ-olKrEIOyJ"
AUTH0_AUDIENCE      = "https://{}/api/v2/".format(AUTH0_DOMAIN)

_token_cache = {"token": None, "expires_at": 0}


def _get_credentials():
    # type: () -> tuple
    domain = os.environ.get("AUTH0_DOMAIN", AUTH0_DOMAIN).strip()
    cid    = os.environ.get("AUTH0_CLIENT_ID", AUTH0_CLIENT_ID).strip()
    secret = os.environ.get("AUTH0_CLIENT_SECRET", AUTH0_CLIENT_SECRET).strip()
    return domain, cid, secret


def _get_token():
    # type: () -> str
    """Get or refresh Auth0 Management API token."""
    if _token_cache["token"] and time.time() < _token_cache["expires_at"] - 30:
        return _token_cache["token"]

    domain, cid, secret = _get_credentials()
    audience = "https://{}/api/v2/".format(domain)

    try:
        resp = requests.post(
            "https://{}/oauth/token".format(domain),
            headers={"content-type": "application/json"},
            json={
                "client_id":     cid,
                "client_secret": secret,
                "audience":      audience,
                "grant_type":    "client_credentials",
            },
            timeout=15,
        )
        if resp.status_code == 200:
            data = resp.json()
            _token_cache["token"]      = data["access_token"]
            _token_cache["expires_at"] = time.time() + data.get("expires_in", 86400)
            return _token_cache["token"]
        else:
            print("  ✗ Auth0 token error: {} — {}".format(resp.status_code, resp.text[:100]))
    except Exception as e:
        print("  ✗ Auth0 connection error: {}".format(str(e)[:80]))
    return ""


def _api_get(path, token, params=None, timeout=15):
    # type: (str, str, dict, int) -> list
    """Paginated GET against Auth0 Management API."""
    domain = _get_credentials()[0]
    base   = "https://{}/api/v2{}".format(domain, path)
    results = []
    page = 0

    while True:
        p = {"per_page": 100, "page": page, "include_totals": "false"}
        if params:
            p.update(params)
        try:
            resp = requests.get(
                base,
                headers={"Authorization": "Bearer " + token},
                params=p,
                timeout=timeout,
            )
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list):
                    if not data:
                        break
                    results.extend(data)
                    if len(data) < 100:
                        break
                    page += 1
                else:
                    results.append(data)
                    break
            elif resp.status_code == 429:
                time.sleep(2)
            elif resp.status_code in (401, 403):
                print("  ✗ Auth0 {}: {}".format(resp.status_code, resp.text[:80]))
                break
            else:
                break
        except Exception as e:
            print("  ✗ Auth0 API error: {}".format(str(e)[:60]))
            break

    return results


# ── API functions ─────────────────────────────────────────────────────────────

def fetch_auth0_users(token):
    # type: (str) -> List[Dict]
    """Fetch all Auth0 users with profile and last login."""
    return _api_get("/users", token, {
        "fields": "user_id,email,name,blocked,last_login,logins_count,created_at,user_metadata,app_metadata",
        "include_fields": "true",
    })


def fetch_auth0_logs(token, since_days=30):
    # type: (str, int) -> List[Dict]
    """
    Fetch Auth0 event logs for anomaly detection.
    Event types we care about:
      f  = failed login
      s  = success login
      fp = failed login (wrong password)
      fu = failed login (user blocked)
      mfaf = MFA failure
      admin_update_launch = admin action
    """
    since = (datetime.now(timezone.utc) - timedelta(days=since_days)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    return _api_get("/logs", token, {
        "from": since,
        "fields": "type,user_id,user_name,ip,date,description,connection,client_name",
        "include_fields": "true",
    })


def fetch_auth0_roles(token):
    # type: (str) -> List[Dict]
    """Fetch all Auth0 roles (maps to privilege levels)."""
    return _api_get("/roles", token)


def test_auth0_connection():
    # type: () -> dict
    """Test Auth0 connection and return status."""
    token = _get_token()
    if not token:
        return {
            "status":  "auth_error",
            "message": "Could not get token — check AUTH0_CLIENT_SECRET",
            "domain":  AUTH0_DOMAIN,
        }
    # Try a minimal API call
    domain = _get_credentials()[0]
    try:
        resp = requests.get(
            "https://{}/api/v2/users?per_page=1".format(domain),
            headers={"Authorization": "Bearer " + token},
            timeout=10,
        )
        if resp.status_code == 200:
            return {"status": "connected", "domain": domain,
                    "message": "Auth0 Management API connected"}
        else:
            return {"status": "error", "code": resp.status_code,
                    "message": resp.text[:100]}
    except Exception as e:
        return {"status": "connection_error", "message": str(e)[:80]}


def auth0_available():
    # type: () -> bool
    """Check if Auth0 credentials are configured."""
    domain, cid, secret = _get_credentials()
    return bool(domain and cid and secret)


# ── Risk analysis ─────────────────────────────────────────────────────────────

_AUTH0_LOG_RISK = {
    "f":           ("AUTH_FAILURE",         "HIGH",     "Failed login"),
    "fp":          ("AUTH_FAILURE",         "HIGH",     "Wrong password"),
    "fu":          ("BLOCKED_USER_LOGIN",   "CRITICAL", "Login attempt on blocked account"),
    "frd":         ("ANOMALOUS_LOGIN",      "HIGH",     "Anomalous location detected by Auth0"),
    "mfaf":        ("MFA_FAILURE",          "CRITICAL", "MFA challenge failed"),
    "mfar":        ("MFA_BYPASS",           "CRITICAL", "MFA rejected"),
    "admin_update_launch": ("ADMIN_ACTION", "MEDIUM",   "Admin launched update"),
    "sapi":        ("API_OPERATION",        "MEDIUM",   "Management API operation"),
    "limit_ui":    ("RATE_LIMITED",         "HIGH",     "Too many failed logins — rate limited"),
    "pwd_leak":    ("CREDENTIAL_LEAK",      "CRITICAL", "Breached password detected"),
}


def _analyse_auth0_logs(logs):
    # type: (List[Dict]) -> Dict[str, List]
    """Extract risk signals from Auth0 logs per user."""
    user_anomalies = {}
    user_ips       = {}

    for entry in logs:
        etype   = entry.get("type", "")
        user_id = entry.get("user_name", "") or entry.get("user_id", "")
        ip      = entry.get("ip", "")
        date    = entry.get("date", "")

        if not user_id:
            continue

        if user_id not in user_anomalies:
            user_anomalies[user_id] = []
        if user_id not in user_ips:
            user_ips[user_id] = set()
        if ip:
            user_ips[user_id].add(ip)

        if etype in _AUTH0_LOG_RISK:
            ftype, sev, desc = _AUTH0_LOG_RISK[etype]
            user_anomalies[user_id].append({
                "type":    "AUTH0_" + ftype,
                "detail":  "{} at {} from {}".format(desc, date[:19] if date else "unknown", ip or "unknown IP"),
                "severity": sev,
            })

        # After-hours check (10pm–6am UTC)
        if date and etype in ("s", "f", "fp"):
            try:
                hour = int(date[11:13])
                if hour >= 22 or hour < 6:
                    user_anomalies[user_id].append({
                        "type":    "AUTH0_AFTER_HOURS_LOGIN",
                        "detail":  "Auth0 login at {}:{} UTC from {}".format(
                                   date[11:13], date[14:16], ip or "unknown"),
                        "severity": "MEDIUM",
                    })
            except Exception:
                pass

    # Multi-IP access
    for uid, ips in user_ips.items():
        if len(ips) >= 4:
            user_anomalies[uid].append({
                "type":    "AUTH0_MULTI_IP_ACCESS",
                "detail":  "Accessed from {} different IPs — possible credential sharing".format(len(ips)),
                "severity": "HIGH",
            })

    return user_anomalies


# ── Main enrichment function ──────────────────────────────────────────────────

def enrich_users_with_auth0(user_results, verbose=True):
    # type: (List[Dict], bool) -> dict
    """
    Enrich user_results with live Auth0 data.
    Called from main.py pipeline step 5b.
    """
    if not REQUESTS_OK:
        return {"status": "requests_not_available"}

    if verbose:
        print("  Auth0 domain: {}".format(AUTH0_DOMAIN))
        print("  Getting Management API token...")

    token = _get_token()
    if not token:
        if verbose:
            print("  ✗ Auth0 token failed — running without Auth0 enrichment")
        return {"status": "token_error"}

    t0 = time.time()

    if verbose:
        print("  ✓ Token obtained — fetching users, logs, roles...")

    # Fetch all data
    auth0_users = fetch_auth0_users(token)
    auth0_logs  = fetch_auth0_logs(token, since_days=30)
    auth0_roles = fetch_auth0_roles(token)

    if verbose:
        print("  Auth0 users: {} | logs: {} | roles: {}".format(
            len(auth0_users), len(auth0_logs), len(auth0_roles)))

    # Build email → Auth0 user lookup
    a0_by_email = {}
    for au in auth0_users:
        email = (au.get("email") or "").lower()
        if email:
            a0_by_email[email] = au

    # Analyse logs for risk signals
    log_anomalies = _analyse_auth0_logs(auth0_logs)

    # Enrich each user
    enriched_count = 0
    for user in user_results:
        email = user.get("email", "").lower()
        au    = a0_by_email.get(email)

        if au:
            enriched_count += 1
            user["auth0_id"]          = au.get("user_id", "")
            user["auth0_blocked"]     = au.get("blocked", False)
            user["auth0_last_login"]  = au.get("last_login", "")
            user["auth0_logins_count"]= au.get("logins_count", 0)
            user["auth0_source"]      = True

            # Blocked account = immediate CRITICAL
            if au.get("blocked"):
                user["risk_score"] = max(user.get("risk_score", 0), 90)
                user.setdefault("findings", []).append({
                    "type":            "AUTH0_ACCOUNT_BLOCKED",
                    "severity":        "CRITICAL",
                    "detail":          "Account is BLOCKED in Auth0 — access suspended but IAM record may still show as active. Investigate reason for block immediately.",
                    "recommendation":  "Verify block reason in Auth0 dashboard; cross-check with HR; ensure all sessions and tokens are revoked; document in GRC system",
                    "compliance_refs": ["NIST AC-2(j)", "PCI-DSS Req.8.1.4", "GDPR Art.32"],
                })

            # Zero logins = orphaned in Auth0
            if au.get("logins_count", 0) == 0:
                user.setdefault("findings", []).append({
                    "type":            "AUTH0_NEVER_LOGGED_IN",
                    "severity":        "MEDIUM",
                    "detail":          "Account exists in Auth0 but has NEVER logged in. May be a provisioned but unused account — common attack target.",
                    "recommendation":  "Confirm account is needed; if not used within 30 days of creation, deactivate and remove from Auth0",
                    "compliance_refs": ["NIST AC-2(g)", "ISO 27001 A.9.2"],
                })

        # Add log-based risk signals
        email_anoms = log_anomalies.get(email, [])
        for anom in email_anoms[:3]:
            if not any(f.get("type") == anom["type"] for f in user.get("findings", [])):
                user.setdefault("findings", []).append({
                    "type":            anom["type"],
                    "severity":        anom["severity"],
                    "detail":          anom["detail"],
                    "recommendation":  "Review Auth0 audit log; investigate unusual activity; force password reset if unexplained; check for credential compromise",
                    "compliance_refs": ["NIST AU-2", "GDPR Art.32", "ISO 27001 A.12.4"],
                })
                boost = {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 10}.get(anom["severity"], 5)
                user["risk_score"] = min(100, user.get("risk_score", 0) + boost)

    elapsed = round(time.time() - t0, 2)

    # Role summary
    role_summary = [
        {"name": r.get("name", ""), "description": r.get("description", "")}
        for r in auth0_roles[:10]
    ]

    summary = {
        "status":          "success",
        "auth0_users":     len(auth0_users),
        "auth0_logs":      len(auth0_logs),
        "auth0_roles":     len(auth0_roles),
        "enriched_users":  enriched_count,
        "log_anomalies":   sum(len(v) for v in log_anomalies.values()),
        "role_summary":    role_summary,
        "elapsed_seconds": elapsed,
        "domain":          AUTH0_DOMAIN,
    }

    if verbose:
        print("  ✓ Auth0 enrichment: {} users matched | {} log anomalies | {}s".format(
            enriched_count, summary["log_anomalies"], elapsed))

    return summary
