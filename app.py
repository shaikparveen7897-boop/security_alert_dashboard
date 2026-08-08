import os
import json
import secrets
from datetime import datetime, timezone
from flask import (
    Flask, jsonify, render_template, request, Response,
    session, redirect, url_for, send_file
)
from flask_cors import CORS

import analyzer
import data_generator
import excel_report
from auth import verify_login, current_user, login_required

app = Flask(__name__)
CORS(app)

# Secret key for signed session cookies (dashboard login).
# Set SECRET_KEY in the environment for a real deployment; falls back to a
# random key per process start, which is fine for this prototype/demo stage.
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# In-memory storage for login events during prototype stage
EVENTS = data_generator.generate_initial_events()


# ----------------------------------------------------------------------
# Authentication - only Security Department members can view the dashboard
# ----------------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    """Login page - only Security Department members can access the dashboard."""
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = verify_login(username, password)
        if user:
            session["username"] = user["username"]
            session["full_name"] = user["full_name"]
            session["role"] = user["role"]
            next_url = request.args.get("next") or url_for("index")
            return redirect(next_url)
        error = "Invalid username or password."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ----------------------------------------------------------------------
# Dashboard (protected)
# ----------------------------------------------------------------------

@app.route("/")
@login_required
def index():
    """Renders the main Sentry Security Operations Console dashboard."""
    return render_template("index.html", user=current_user())


@app.route("/api/summary", methods=["GET"])
@login_required
def api_summary():
    """Returns summary stats of login events and threats."""
    res = analyzer.summary(EVENTS)
    return jsonify(res)


@app.route("/api/timeline", methods=["GET"])
@login_required
def api_timeline():
    """Returns hourly success vs failed login timeline for line chart."""
    res = analyzer.hourly_timeline(EVENTS, hours=24)
    return jsonify(res)


@app.route("/api/suspicious-ips", methods=["GET"])
@login_required
def api_suspicious_ips():
    """Returns list of flagged suspicious IPs with threat metadata."""
    res = analyzer.detect_suspicious_ips(EVENTS)
    return jsonify(res)


@app.route("/api/alerts", methods=["GET"])
@login_required
def api_alerts():
    """Returns time-ordered feed of failed login alerts from flagged IPs."""
    limit = request.args.get("limit", default=25, type=int)
    res = analyzer.recent_alerts(EVENTS, limit=limit)
    return jsonify(res)


@app.route("/api/simulate-attack", methods=["POST"])
@login_required
def api_simulate_attack():
    """
    Simulates a fresh brute-force attack burst live on demand.
    Appends new attack events to in-memory list and returns status.
    """
    global EVENTS
    new_attack_events = data_generator.simulate_attack()
    EVENTS.extend(new_attack_events)
    EVENTS.sort(key=lambda x: x["timestamp"])

    current_summary = analyzer.summary(EVENTS)

    return jsonify({
        "status": "success",
        "message": f"Simulated new attack burst: {len(new_attack_events)} failed login attempts injected.",
        "injected_count": len(new_attack_events),
        "total_events": len(EVENTS),
        "suspicious_ip_count": current_summary["suspicious_ip_count"]
    })


@app.route("/api/export-report", methods=["GET"])
@login_required
def api_export_report():
    """
    Generates a downloadable JSON results report summarizing the current
    detection run - the concrete 'output' evidence for the project review,
    separate from the live dashboard demo. Supports optional ?start= and
    ?end= ISO timestamps to scope the report to a specific time window.
    """
    start_iso = request.args.get("start")
    end_iso = request.args.get("end")
    scoped_events = analyzer.filter_events_by_range(EVENTS, start_iso, end_iso)
    scoped_suspicious = analyzer.detect_suspicious_ips(scoped_events)

    report = {
        "report_generated_at": datetime.now(timezone.utc).isoformat(),
        "project": "Sentry - Security Alert Dashboard",
        "report_range": {"start": start_iso, "end": end_iso},
        "detection_rule": "Flag any IP with 5+ failed login attempts within a 15-minute sliding window",
        "summary": analyzer.summary(scoped_events),
        "flagged_ips": scoped_suspicious,
        "sample_alerts": analyzer.recent_alerts(scoped_events, limit=10),
    }
    body = json.dumps(report, indent=2)
    return Response(
        body,
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=sentry_results_report.json"},
    )


@app.route("/api/export-excel", methods=["GET"])
@login_required
def api_export_excel():
    """
    Generates a downloadable, formatted .xlsx report of login events -
    columns: timestamp, username, IP, location, status, reason, flagged.
    Supports optional ?start= and ?end= ISO timestamps to scope the
    report to a specific time window instead of the full dataset.
    """
    start_iso = request.args.get("start")
    end_iso = request.args.get("end")
    scoped_events = analyzer.filter_events_by_range(EVENTS, start_iso, end_iso)
    scoped_suspicious = analyzer.detect_suspicious_ips(scoped_events)

    buffer = excel_report.build_report(
        scoped_events,
        scoped_suspicious,
        generated_by=current_user()["full_name"],
        start_iso=start_iso,
        end_iso=end_iso,
    )

    filename = f"sentry_login_report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M')}.xlsx"
    return send_file(
        buffer,
        as_attachment=True,
        download_name=filename,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )


# ----------------------------------------------------------------------
# Live demo: the monitored system's own login page (NOT the dashboard).
# Deliberately unprotected - it represents the target system being
# watched, so presenters can intentionally fail a login here and watch
# it appear on the Sentry dashboard in real time.
# ----------------------------------------------------------------------

@app.route("/system-login", methods=["GET", "POST"])
def system_login():
    global EVENTS
    result = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        client_ip = request.remote_addr or "127.0.0.1"

        event, success = data_generator.record_manual_login(username, password, client_ip)
        EVENTS.append(event)
        EVENTS.sort(key=lambda x: x["timestamp"])

        result = {
            "success": success,
            "username": event["username"],
            "reason": event["reason"],
            "timestamp": event["timestamp"],
        }

    return render_template("system_login.html", result=result)


@app.route("/system-login/trigger-detection", methods=["POST"])
def system_login_trigger_detection():
    """
    Live-demo convenience: fires 5 rapid failed login attempts for the given
    username from this machine's IP, so a presenter can show real-time
    threshold detection kicking in without manually mistyping a password
    five times on stage.
    """
    global EVENTS
    username = request.form.get("username", "demo.user")
    client_ip = request.remote_addr or "127.0.0.1"

    burst_count = 6
    for _ in range(burst_count):
        event, _ = data_generator.record_manual_login(username, "wrong-password", client_ip)
        EVENTS.append(event)

    EVENTS.sort(key=lambda x: x["timestamp"])

    result = {
        "success": False,
        "username": username,
        "reason": f"{burst_count} rapid failed attempts injected — check the Sentry dashboard now",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "burst": True,
    }
    return render_template("system_login.html", result=result)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 3000))
    # Debug mode is OFF by default so the reloader can't restart mid-demo.
    # Set FLASK_DEBUG=1 in the environment while actively developing.
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=port, debug=debug_mode)
