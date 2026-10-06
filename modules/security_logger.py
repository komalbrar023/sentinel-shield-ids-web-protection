import logging
import os
from urllib.parse import unquote
LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "security.log")

os.makedirs(LOG_DIR, exist_ok=True)

logger = logging.getLogger("SentinelShield")
logger.setLevel(logging.INFO)

if not logger.handlers:
    file_handler = logging.FileHandler(LOG_FILE)

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(message)s"
    )

    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)


def log_request(method, path, ip_address, status_code):

    message = (
        f"REQUEST | Method={method} | "
        f"Path={path} | IP={ip_address} | "
        f"Status={status_code}"
    )

    logger.info(message)


def get_threat_severity(pattern):

    high_patterns = [
        "union select",
        "' or '1'='1",
        "<script>",
        "etc/passwd",
        "; whoami",
        "&& whoami",
        "| whoami"
    ]

    medium_patterns = [
        "/admin",
        "/wp-admin",
        "/phpmyadmin",
        "../"
    ]

    pattern_lower = pattern.lower()

    for item in high_patterns:
        if item in pattern_lower:
            return "HIGH"

    for item in medium_patterns:
        if item in pattern_lower:
            return "MEDIUM"

    return "LOW"


def log_security_event(event_type, ip_address, details, severity="LOW"):

    message = (
        f"SECURITY_EVENT | "
        f"Severity={severity} | "
        f"Type={event_type} | "
        f"IP={ip_address} | "
        f"Details={details}"
    )

    logger.warning(message)

def detect_suspicious_request(path):

    suspicious_patterns = [

        # SQL Injection
        ("union select", "SQL Injection"),
        ("' or '1'='1", "SQL Injection"),

        # Cross-Site Scripting
        ("<script>", "Cross-Site Scripting"),

        # Directory Traversal
        ("../", "Directory Traversal"),

        # Local File Inclusion
        ("etc/passwd", "Local File Inclusion"),

        # Command Injection
        ("; whoami", "Command Injection"),
        ("&& whoami", "Command Injection"),
        ("| whoami", "Command Injection"),
       
         # Suspicious administrative access
        ("/admin", "Suspicious Administrative Access"),
        ("/login", "Suspicious Login Access"),
        ("/wp-admin", "Suspicious Administrative Access"),
        ("/phpmyadmin", "Suspicious Database Access")
    ]

    path_lower = unquote(path).lower()

    for pattern, category in suspicious_patterns:

        if pattern in path_lower:

            severity = get_threat_severity(pattern)

            return True, pattern, severity, category

    return False, None, None, None
