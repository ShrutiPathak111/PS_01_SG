"""
config.py — All constants, thresholds, and mappings for the IAM Risk system.
Built specifically for the real CSV schema from the uploaded datasets.

Users CSV columns:
  user_id, username, email, department, job_title, privilege_level,
  systems_access (pipe-separated), last_login, days_inactive, is_active, hire_date

Events CSV columns:
  timestamp, user_id, username, action, resource, resource_sensitivity,
  status, source_ip, time_classification
"""

from pathlib import Path

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR   = Path(__file__).parent
DATA_DIR   = BASE_DIR.parent / "data"
REPORTS_DIR= BASE_DIR.parent / "reports"

# ── Privilege hierarchy ───────────────────────────────────────────────────────
PRIVILEGE_RANK = {
    "user":            1,
    "service-account": 2,
    "power-user":      3,
    "admin":           4,
}

# Max days inactive before flagging (by privilege level)
STALE_THRESHOLDS = {
    "admin":           20,   # Admins should be logging in frequently
    "power-user":      30,
    "service-account": 25,   # Service accounts should be active
    "user":            45,
}

# Maximum expected system count per privilege level
MAX_SYSTEMS_PER_PRIV = {
    "user":            3,
    "power-user":      5,
    "admin":           8,    # Admins legitimately need more, but still a limit
    "service-account": 3,
}

# ── Systems from real CSV ─────────────────────────────────────────────────────
ALL_IDENTITY_SYSTEMS = [
    "AD", "Azure_AD", "AWS_IAM", "GCP", "Okta",
    "SIEM", "PROD_DB", "ADMIN_SYS", "Salesforce",
    "ServiceNow", "EMAIL", "VPN",
]

CRITICAL_IDENTITY_SYSTEMS = {"PROD_DB", "ADMIN_SYS", "SIEM", "AWS_IAM", "Azure_AD"}
HIGH_RISK_IDENTITY_SYSTEMS = {"Okta", "AD", "GCP", "VPN"}

# ── Resources from real events CSV ────────────────────────────────────────────
ALL_RESOURCES = [
    "HRIS", "Data_Lake", "BI_Tool", "File_Share",
    "Email_Archive", "GL_System", "Admin_Console",
    "SIEM", "PROD_DB", "Customer_Vault",
]
CRITICAL_RESOURCES = {"PROD_DB", "Admin_Console", "SIEM", "Customer_Vault", "HRIS"}

# ── Actions from real events CSV ──────────────────────────────────────────────
HIGH_RISK_ACTIONS = {"admin_operation", "export_data", "sql_query"}
ALL_ACTIONS = {"admin_operation", "sql_query", "export_data", "api_call", "file_access", "login"}

# ── Department → expected resources (for cross-dept access detection) ─────────
# Based on business logic per the problem statement
DEPT_EXPECTED_RESOURCES = {
    "Finance":     {"GL_System", "Data_Lake", "BI_Tool", "Email_Archive"},
    "HR":          {"HRIS", "Email_Archive", "File_Share"},
    "IT":          {"Admin_Console", "SIEM", "PROD_DB", "Data_Lake", "File_Share"},
    "Security":    {"SIEM", "Admin_Console", "Email_Archive", "PROD_DB"},
    "Engineering": {"PROD_DB", "Data_Lake", "BI_Tool", "File_Share"},
    "Legal":       {"Email_Archive", "File_Share", "HRIS"},
    "Marketing":   {"BI_Tool", "Data_Lake", "File_Share", "Email_Archive"},
    "Sales":       {"BI_Tool", "Email_Archive", "Customer_Vault", "File_Share"},
    "Operations":  {"File_Share", "BI_Tool", "Data_Lake", "Email_Archive"},
    "Executive":   {"BI_Tool", "Data_Lake", "Email_Archive", "HRIS", "GL_System"},
    "Support":     {"HRIS", "File_Share", "Email_Archive", "Customer_Vault"},
    "Compliance":  {"SIEM", "Email_Archive", "GL_System", "Data_Lake", "HRIS"},
}

# ── Department → expected identity systems ─────────────────────────────────────
DEPT_EXPECTED_SYSTEMS = {
    "Finance":     {"Azure_AD", "EMAIL", "Salesforce"},
    "HR":          {"AD", "EMAIL", "Okta"},
    "IT":          {"AD", "Azure_AD", "ADMIN_SYS", "SIEM", "VPN"},
    "Security":    {"SIEM", "Azure_AD", "AWS_IAM", "AD"},
    "Engineering": {"AD", "Azure_AD", "AWS_IAM", "GCP"},
    "Legal":       {"AD", "EMAIL", "Salesforce"},
    "Marketing":   {"Salesforce", "EMAIL", "Azure_AD"},
    "Sales":       {"Salesforce", "EMAIL", "Azure_AD", "Okta"},
    "Operations":  {"ServiceNow", "AD", "EMAIL"},
    "Executive":   {"AD", "EMAIL", "Salesforce", "Azure_AD"},
    "Support":     {"ServiceNow", "EMAIL", "Salesforce"},
    "Compliance":  {"SIEM", "EMAIL", "ServiceNow"},
}

# Departments that legitimately need broad access
BROAD_ACCESS_DEPTS  = {"Security", "IT"}
ADMIN_EXCEPTION_DEPTS = {"Security", "IT"}

# ── SoD conflict pairs — no user should hold BOTH ─────────────────────────────
SOD_PAIRS = [
    ("PROD_DB",   "ADMIN_SYS"),   # Modify data + admin console
    ("SIEM",      "AD"),          # Audit logs + directory admin = cover tracks
    ("PROD_DB",   "SIEM"),        # Modify prod + audit own actions
    ("AWS_IAM",   "ADMIN_SYS"),   # Cloud IAM + local admin
    ("Okta",      "ADMIN_SYS"),   # SSO admin + system admin
    ("Azure_AD",  "PROD_DB"),     # Cloud identity + prod DB
]

# ── Compliance framework mapping per finding type ──────────────────────────────
COMPLIANCE_MAP = {
    "STALE_PRIVILEGED_ACCOUNT":    ["NIST AC-2(j)", "GDPR Art.32", "PCI-DSS Req.8.1.4"],
    "STALE_SERVICE_ACCOUNT":       ["NIST AC-2(g)", "NIST AC-6", "PCI-DSS Req.8.5"],
    "OVER_PRIVILEGED":             ["NIST AC-6 (PoLP)", "GDPR Art.25", "ISO 27001 A.9.2"],
    "ORPHANED_ACCOUNT":            ["NIST AC-2(j)", "SOX", "GDPR Art.32"],
    "CROSS_DEPT_SYSTEM_ACCESS":    ["NIST AC-3", "GDPR Art.25", "PCI-DSS Req.7"],
    "CROSS_DEPT_RESOURCE_ACCESS":  ["NIST AC-3", "ISO 27001 A.9.1"],
    "SOD_VIOLATION":               ["NIST AC-5", "SOX Sec.404", "PCI-DSS Req.6.4"],
    "AFTER_HOURS_HIGH_RISK":       ["NIST AU-12", "GDPR Art.32", "ISO 27001 A.12.4"],
    "BULK_DATA_EXPORT":            ["NIST AU-2", "GDPR Art.32", "PCI-DSS Req.10"],
    "REPEATED_AUTH_FAILURE":       ["NIST AC-7", "GDPR Art.32", "PCI-DSS Req.8.1.6"],
    "SERVICE_ACCOUNT_INTERACTIVE": ["NIST AC-6", "PCI-DSS Req.8.5.1"],
    "ML_BEHAVIORAL_ANOMALY":       ["NIST AU-6", "ISO 27001 A.12.4"],
    "NO_MFA_PRIVILEGED":           ["NIST IA-2", "NIST IA-5", "PCI-DSS Req.8.3"],
    "DEPT_LEVEL_ANOMALY":          ["NIST AU-6", "ISO 27001 A.12.4"],
    "HIGH_FAILURE_RATE":           ["NIST AC-7", "ISO 27001 A.9.4"],
}

# ── Risk scoring weights ──────────────────────────────────────────────────────
SEVERITY_SCORE = {
    "CRITICAL":      90,
    "HIGH":          65,
    "MEDIUM":        40,
    "LOW":           18,
    "INFORMATIONAL":  6,
}

# ── Blast radius data for breach simulation ────────────────────────────────────
# Systems from identity_users.csv systems_access column
IDENTITY_SYSTEM_IMPACT = {
    "AD":         {"records": 50_000,  "gdpr": True,  "fine": 500_000,   "desc": "On-prem AD: all user accounts & credentials"},
    "Azure_AD":   {"records": 50_000,  "gdpr": True,  "fine": 1_000_000, "desc": "Cloud identity: SSO sessions, MFA configs"},
    "AWS_IAM":    {"records": 0,       "gdpr": False, "fine": 2_000_000, "desc": "Cloud IAM: full AWS resource access"},
    "GCP":        {"records": 0,       "gdpr": False, "fine": 2_000_000, "desc": "GCP: Cloud Storage, BigQuery, Compute"},
    "Okta":       {"records": 50_000,  "gdpr": True,  "fine": 1_500_000, "desc": "SSO hub: lateral movement to all connected apps"},
    "SIEM":       {"records": 500_000, "gdpr": False, "fine": 3_000_000, "desc": "Security logs: attacker can disable alerts"},
    "PROD_DB":    {"records": 2_000_000,"gdpr": True, "fine": 5_000_000, "desc": "Production DB: customer PII & financial records"},
    "ADMIN_SYS":  {"records": 0,       "gdpr": False, "fine": 4_000_000, "desc": "Full system admin: install, create accounts"},
    "Salesforce": {"records": 200_000, "gdpr": True,  "fine": 2_000_000, "desc": "CRM: customer contacts, deals, pipeline"},
    "ServiceNow": {"records": 100_000, "gdpr": True,  "fine": 500_000,   "desc": "ITSM: change requests, CI/CD configs"},
    "EMAIL":      {"records": 500_000, "gdpr": True,  "fine": 1_000_000, "desc": "Corporate email: phishing pivot vector"},
    "VPN":        {"records": 0,       "gdpr": False, "fine": 1_000_000, "desc": "Full internal network access"},
}

# Resources from identity_events.csv
RESOURCE_IMPACT = {
    "HRIS":           {"records": 5_000,    "gdpr": True,  "fine": 1_000_000, "desc": "HR records: salaries, perf reviews, health data"},
    "Data_Lake":      {"records": 10_000_000,"gdpr": True, "fine": 5_000_000, "desc": "All raw analytics: customer behaviour, transactions"},
    "BI_Tool":        {"records": 500_000,  "gdpr": True,  "fine": 500_000,   "desc": "Business intelligence: KPIs, executive dashboards"},
    "File_Share":     {"records": 100_000,  "gdpr": True,  "fine": 500_000,   "desc": "Corporate files: contracts, IP, employee docs"},
    "Email_Archive":  {"records": 2_000_000,"gdpr": True,  "fine": 2_000_000, "desc": "Full email history: M&A data, legal, strategy"},
    "GL_System":      {"records": 50_000,   "gdpr": False, "fine": 3_000_000, "desc": "General ledger: all financial transactions"},
    "Admin_Console":  {"records": 0,        "gdpr": False, "fine": 5_000_000, "desc": "Infrastructure admin: servers, network, policies"},
    "SIEM":           {"records": 500_000,  "gdpr": False, "fine": 3_000_000, "desc": "Security events: cover tracks, disable alerting"},
    "PROD_DB":        {"records": 2_000_000,"gdpr": True,  "fine": 5_000_000, "desc": "Production data: customer PII & transactions"},
    "Customer_Vault": {"records": 500_000,  "gdpr": True,  "fine": 8_000_000, "desc": "Customer PII vault: SSNs, payment cards, accounts"},
}

# Lateral movement: if you have system A, you can reach system B
LATERAL_PATHS = {
    "AD":         ["Azure_AD", "PROD_DB", "EMAIL"],
    "Azure_AD":   ["Okta", "Salesforce", "SIEM"],
    "AWS_IAM":    ["PROD_DB", "ADMIN_SYS", "GCP"],
    "ADMIN_SYS":  ["PROD_DB", "SIEM", "AD"],
    "Okta":       ["Azure_AD", "Salesforce", "ServiceNow"],
    "VPN":        ["PROD_DB", "Admin_Console"],
    "GCP":        ["AWS_IAM", "PROD_DB"],
    "SIEM":       ["AD", "PROD_DB"],
}
