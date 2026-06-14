"""
privilege_graph.py — NetworkX privilege graph from real identity_users.csv data.
Systems: AD, Azure_AD, AWS_IAM, GCP, Okta, SIEM, PROD_DB, ADMIN_SYS,
         Salesforce, ServiceNow, EMAIL, VPN
"""

import networkx as nx
import pandas as pd
from src.config import SOD_PAIRS
from src.analyzers.risk_engine import parse_systems

CRITICAL_SYSTEMS = {"PROD_DB", "ADMIN_SYS", "SIEM", "AWS_IAM", "Azure_AD"}

SYSTEM_CATEGORIES = {
    "AD":         "identity",   "Azure_AD":   "identity",
    "AWS_IAM":    "cloud",      "GCP":        "cloud",
    "Okta":       "sso",        "SIEM":       "security",
    "PROD_DB":    "database",   "ADMIN_SYS":  "admin",
    "Salesforce": "saas",       "ServiceNow": "itsm",
    "EMAIL":      "comms",      "VPN":        "network",
}

CATEGORY_COLORS = {
    "identity": "#0a84ff",  "cloud":   "#bf5af2",
    "sso":      "#5ac8fa",  "security":"#ff2d55",
    "database": "#ff9500",  "admin":   "#e8001d",
    "saas":     "#32d74b",  "itsm":    "#ffd60a",
    "comms":    "#636366",  "network": "#8e8e93",
}

PRIV_COLORS = {
    "admin": "#ff2d55", "power-user": "#ff9500",
    "service-account": "#bf5af2", "user": "#374555",
}


def build_privilege_graph(users_df):  # type: (pd.DataFrame) -> nx.DiGraph
    G = nx.DiGraph()

    for _, row in users_df.iterrows():
        uid      = str(row["user_id"])
        priv     = str(row.get("privilege_level", "user"))
        dept     = str(row.get("department", "Unknown"))
        inactive = int(row.get("days_inactive", 0)) if not pd.isna(row.get("days_inactive", 0)) else 0

        G.add_node(uid,
                   node_type="user",
                   privilege=priv,
                   department=dept,
                   days_inactive=inactive,
                   username=str(row.get("username", uid)),
                   color=PRIV_COLORS.get(priv, "#374555"))

        for sys in parse_systems(row.get("systems_access", "")):
            if not G.has_node(sys):
                cat = SYSTEM_CATEGORIES.get(sys, "other")
                G.add_node(sys,
                           node_type="system",
                           category=cat,
                           critical=sys in CRITICAL_SYSTEMS,
                           color=CATEGORY_COLORS.get(cat, "#636366"))
            G.add_edge(uid, sys, privilege=priv, dept=dept)

    return G


def graph_stats(G):  # type: (nx.DiGraph) -> dict
    users   = [n for n, d in G.nodes(data=True) if d.get("node_type") == "user"]
    systems = [n for n, d in G.nodes(data=True) if d.get("node_type") == "system"]
    critical= [n for n, d in G.nodes(data=True)
               if d.get("node_type") == "system" and d.get("critical")]

    top_users   = sorted([(n, G.out_degree(n)) for n in users],   key=lambda x: x[1], reverse=True)[:10]
    top_systems = sorted([(n, G.in_degree(n))  for n in systems],  key=lambda x: x[1], reverse=True)
    admin_exp   = sorted([(n, G.out_degree(n)) for n in users
                          if G.nodes[n].get("privilege") == "admin"],
                         key=lambda x: x[1], reverse=True)[:5]

    return {
        "total_users":       len(users),
        "total_systems":     len(systems),
        "critical_systems":  len(critical),
        "total_edges":       G.number_of_edges(),
        "avg_sys_per_user":  round(G.number_of_edges() / max(len(users), 1), 2),
        "top_users":         top_users,
        "top_systems":       top_systems,
        "admin_exposure":    admin_exp,
    }


def detect_sod_graph(G):  # type: (nx.DiGraph) -> list
    violations = []
    for node, data in G.nodes(data=True):
        if data.get("node_type") != "user":
            continue
        systems = set(G.successors(node))
        for a, b in SOD_PAIRS:
            if a in systems and b in systems:
                violations.append({
                    "user": node,
                    "username": data.get("username", node),
                    "dept": data.get("department", ""),
                    "systems": [a, b],
                    "severity": "HIGH",
                })
    return violations


def export_for_frontend(G):  # type: (nx.DiGraph) -> dict
    """JSON-serialisable graph for D3/Canvas rendering in dashboard."""
    nodes, links = [], []

    for n, d in G.nodes(data=True):
        if d.get("node_type") == "user":
            nodes.append({
                "id": n, "type": "user",
                "label": d.get("username", n)[:18],
                "privilege": d.get("privilege", "user"),
                "department": d.get("department", ""),
                "days_inactive": d.get("days_inactive", 0),
                "degree": G.out_degree(n),
                "color": d.get("color", "#374555"),
            })
        else:
            nodes.append({
                "id": n, "type": "system",
                "label": n,
                "category": d.get("category", "other"),
                "critical": d.get("critical", False),
                "color": d.get("color", "#636366"),
                "degree": G.in_degree(n),
            })

    for u, v, d in G.edges(data=True):
        links.append({
            "source": u, "target": v,
            "privilege": d.get("privilege", ""),
            "dept": d.get("dept", ""),
        })

    return {"nodes": nodes, "links": links}
