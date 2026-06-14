"""
api/server.py — REST API for IAM Risk Dashboard
Run: python src/api/server.py
Open: http://localhost:5050
"""
import json
import sys
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent.parent
sys.path.insert(0, str(BASE_DIR))

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS, cross_origin

app  = Flask(__name__)
CORS(app)

REPORTS = BASE_DIR / "reports"
DASH    = BASE_DIR / "dashboard"
_cache  = {}


def load():
    if "report" not in _cache:
        rp = REPORTS / "full_report.json"
        if rp.exists():
            with open(rp) as f: _cache["report"] = json.load(f)
        gp = REPORTS / "graph_data.json"
        if gp.exists():
            with open(gp) as f: _cache["graph"] = json.load(f)
    return _cache


@app.route("/")
def home(): return send_from_directory(DASH, "index.html")

@app.route("/data.js")
def data_js(): return send_from_directory(DASH, "data.js")

@app.route("/api/summary")
def summary():
    c = load(); return jsonify(c["report"]["summary"]) if "report" in c else (jsonify({}), 503)

@app.route("/api/users")
def users():
    c = load()
    if "report" not in c: return jsonify([]), 503
    res = c["report"]["all_user_results"]
    if f := request.args.get("risk_level"): res = [r for r in res if r["risk_level"] == f.upper()]
    if d := request.args.get("department"):  res = [r for r in res if r.get("department") == d]
    limit = int(request.args.get("limit", 100))
    return jsonify(sorted(res, key=lambda x: x["risk_score"], reverse=True)[:limit])

@app.route("/api/users/<uid>")
def user_detail(uid):
    c = load()
    if "report" not in c: return jsonify({}), 503
    u = next((r for r in c["report"]["all_user_results"] if r["user_id"] == uid), None)
    return jsonify(u) if u else (jsonify({"error": "Not found"}), 404)

@app.route("/api/events")
def events():
    c = load()
    if "report" not in c: return jsonify([]), 503
    res = c["report"]["all_event_results"]
    if f := request.args.get("risk_level"): res = [r for r in res if r["risk_level"] == f.upper()]
    limit = int(request.args.get("limit", 100))
    return jsonify(sorted(res, key=lambda x: x["risk_score"], reverse=True)[:limit])

@app.route("/api/sod")
def sod():
    c = load(); return jsonify(c["report"]["sod_violations"]) if "report" in c else jsonify([])

@app.route("/api/breach")
def breach():
    c = load(); return jsonify(c["report"]["breach_top10"]) if "report" in c else jsonify([])

@app.route("/api/graph")
def graph():
    c = load(); return jsonify(c.get("graph", {}))

@app.route("/api/playbooks")
def playbooks():
    c = load(); return jsonify(c["report"]["playbooks"]) if "report" in c else jsonify([])

@app.route("/api/dlp")
def dlp():
    c = load()
    if "report" not in c: return jsonify([]), 503
    return jsonify({"rules": c["report"]["dlp_rules"], "incidents": c["report"]["dlp_incidents"][:50]})

@app.route("/api/org_anomalies")
def org_anomalies():
    c = load(); return jsonify(c["report"]["org_anomalies"]) if "report" in c else jsonify([])

@app.route("/api/okta/status", methods=["GET"])
@cross_origin()
def okta_status():
    """Check Okta connection status."""
    from src.analyzers.auth0_integration import test_auth0_connection, auth0_available
    return jsonify(test_auth0_connection())


@app.route("/api/okta/users", methods=["GET"])
@cross_origin()
def okta_users_live():
    """Fetch live users from Okta (if connected)."""
    from src.analyzers.auth0_integration import fetch_auth0_users, _get_token, auth0_available
    if not auth0_available():
        return jsonify({"error": "Okta not configured", "setup": "Set OKTA_DOMAIN + OKTA_API_TOKEN"}), 400
    users = fetch_okta_users(limit=50)
    return jsonify({"users": users, "count": len(users)})


@app.route("/api/okta/logs", methods=["GET"])
@cross_origin()
def okta_logs_live():
    """Fetch live access logs from Okta (if connected)."""
    from src.analyzers.auth0_integration import fetch_auth0_logs, _get_token, auth0_available
    if not auth0_available():
        return jsonify({"error": "Okta not configured"}), 400
    events = fetch_okta_logs(limit=100)
    return jsonify({"events": events, "count": len(events)})


@app.route("/api/feedback", methods=["POST"])
def feedback():
    from src.analyzers.advanced import record_feedback
    d = request.json
    result = record_feedback(d.get("user_id",""), d.get("finding_type",""), d.get("is_fp",True), d.get("reason",""))
    _cache.clear()
    return jsonify({"ok": True, "adjustment": result})

@app.route("/api/health")
def health():
    c = load(); return jsonify({"status": "ok", "report_ready": "report" in c})


if __name__ == "__main__":
    print("🚀 IAM Risk API: http://localhost:5050")
    print("   Dashboard:   http://localhost:5050/")
    print("   Run main.py first to generate reports!")
    app.run(debug=True, port=5050)
