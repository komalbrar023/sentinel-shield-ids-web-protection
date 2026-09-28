from flask import Flask, render_template, request

from modules.security_logger import (
    log_request,
    log_security_event,
    detect_suspicious_request
)

app = Flask(__name__)


# ==========================================
# REQUEST MONITORING
# ==========================================

@app.before_request
def monitor_request():

    suspicious, pattern, severity = detect_suspicious_request(
        request.path
    )

    if suspicious:

        log_security_event(
            "SUSPICIOUS_REQUEST",
            request.remote_addr,
            f"Pattern detected: {pattern} | Path: {request.path}",
            severity
        )


# ==========================================
# REQUEST LOGGING
# ==========================================

@app.after_request
def record_request(response):

    log_request(
        request.method,
        request.path,
        request.remote_addr,
        response.status_code
    )

    return response


# ==========================================
# DASHBOARD
# ==========================================
@app.route("/")
def home():

    total_requests = 0
    security_alerts = 0

    ip_alerts = {}

    high_threats = 0
    medium_threats = 0
    low_threats = 0

    try:

        with open("logs/security.log", "r") as log_file:

            for line in log_file:

                # Count normal requests
                if "REQUEST |" in line:
                    total_requests += 1

                # Count security alerts
                if "SECURITY_EVENT" in line:

                    security_alerts += 1

                    # Count threat severity
                    if "Severity=HIGH" in line:
                        high_threats += 1

                    elif "Severity=MEDIUM" in line:
                        medium_threats += 1

                    elif "Severity=LOW" in line:
                        low_threats += 1

                    # Extract IP address
                    parts = line.split("|")

                    ip_address = "Unknown"

                    for part in parts:

                        if "IP=" in part:

                            ip_address = part.split("IP=")[1].strip()

                    # Count alerts for each IP
                    ip_alerts[ip_address] = (
                        ip_alerts.get(ip_address, 0) + 1
                    )

    except FileNotFoundError:

        pass


    # Recent security events

    recent_events = []

    try:

        with open("logs/security.log", "r") as log_file:

            for line in log_file:

                if "SECURITY_EVENT" in line:

                    recent_events.append(line.strip())

    except FileNotFoundError:

        pass


    return render_template(
        "index.html",

        total_requests=total_requests,

        security_alerts=security_alerts,

        ip_alerts=ip_alerts,

        high_threats=high_threats,

        medium_threats=medium_threats,

        low_threats=low_threats,

        recent_events=recent_events[-5:]
    )
# ==========================================
# TEST ROUTES
# ==========================================

@app.route("/admin")
def admin():

    return "Admin page"


@app.route("/login")
def login():

    return "Login page"
# ==========================================
# THREAT TESTING PAGE
# ==========================================

@app.route("/test")
def threat_test():

    return render_template("test.html")

# ==========================================
# SECURITY ALERTS PAGE
# ==========================================

@app.route("/alerts")
def alerts():

    alerts_list = []

    try:

        with open("logs/security.log", "r") as log_file:

            for line in log_file:

                if "SECURITY_EVENT" in line:

                    alerts_list.append(
                        line.strip()
                    )


    except FileNotFoundError:

        pass


    return render_template(
        "alerts.html",

        alerts=alerts_list[-20:]
    )


# ==========================================
# START APPLICATION
# ==========================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )
