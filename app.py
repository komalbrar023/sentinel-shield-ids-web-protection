import os
from flask import Flask, render_template, request
import time
from modules.security_logger import (
    log_request,
    log_security_event,
    detect_suspicious_request
)

app = Flask(__name__)


# ==========================================
# RATE LIMITING
# ==========================================

request_history = {}

RATE_LIMIT = 10
RATE_WINDOW = 10

def check_rate_limit(ip_address):

    current_time = time.time()

    if ip_address not in request_history:
        request_history[ip_address] = []

    request_history[ip_address] = [
        timestamp
        for timestamp in request_history[ip_address]
        if current_time - timestamp < RATE_WINDOW
    ]

    if len(request_history[ip_address]) >= RATE_LIMIT:
        return True

    request_history[ip_address].append(current_time)

    return False

# ==========================================
# REQUEST MONITORING
# ==========================================

@app.before_request
def monitor_request():

    ip_address = request.remote_addr

    # Ignore static files
    if request.path.startswith("/static/"):
        return

    # Check request rate
    if check_rate_limit(ip_address):

        log_security_event(
            "RATE_LIMIT_EXCEEDED",
            ip_address,
            f"More than {RATE_LIMIT} requests within {RATE_WINDOW} seconds | Path: {request.path}",
            "HIGH"
        )

        return "Too Many Requests - Rate limit exceeded", 429

    request_data = request.path + "?" + request.query_string.decode()

    is_suspicious, pattern, severity, category = detect_suspicious_request(request_data)

    if is_suspicious:

        log_security_event(
            "SUSPICIOUS_REQUEST",
            ip_address,
            f"Category={category} | Pattern detected: {pattern} | Path: {request.path}",
            severity
        )
        return "Request blocked by Sentinel Shield", 403

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
    
    category_counts = {}
    try:

        with open("logs/security.log", "r") as log_file:

            for line in log_file:

                # Count normal requests
                if "REQUEST |" in line:
                    total_requests += 1

                # Count security alerts
                if "SECURITY_EVENT" in line:

                    security_alerts += 1

                    if "Category=" in line:
                        category = line.split("Category=")[1].split("|")[0].strip()

                        category_counts[category] = (
                            category_counts.get(category, 0) + 1
                        )

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

        category_counts=category_counts,

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
    port=int(os.environ.get("PORT", 5000)),
    debug=False
)
