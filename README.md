# 🛡️ Sentinel Shield

### Advanced Intrusion Detection & Web Protection System

Sentinel Shield is a Python and Flask-based web security project designed to monitor HTTP requests, detect suspicious activity, block common web attack patterns, apply rate limiting, and record security events for analysis.

The project was developed as a cybersecurity practical project to understand basic Web Application Firewall (WAF) concepts, intrusion detection, request monitoring, logging, and security event analysis.

---

## 🎯 Project Objectives

* Monitor incoming HTTP requests
* Detect suspicious and malicious request patterns
* Identify common web attacks
* Block detected malicious requests
* Apply IP-based rate limiting
* Classify threats by severity
* Record security events with timestamps and IP addresses
* Track suspicious IP activity
* Display security information through a web dashboard

---

## 🧰 Technologies Used

* Python
* Flask
* HTML
* CSS
* Jinja2 Templates
* Linux / Kali Linux
* cURL
* Python Logging
* Git

---

## 🏗️ Project Architecture

```text
Client Request
      │
      ▼
   Flask App
      │
      ▼
Request Monitoring
      │
      ├── Rate Limit Check
      │
      └── Suspicious Request Detection
                  │
                  ▼
             Pattern Matching
                  │
       ┌──────────┼──────────┐
       ▼          ▼          ▼
    Allowed     Detected    Rate Limit
       │          │          │
       ▼          ▼          ▼
    HTTP 200    HTTP 403    HTTP 429
                  │
                  ▼
           Security Logging
                  │
                  ▼
          Security Dashboard
```

---

## 🔍 Attack Detection

Sentinel Shield uses pattern/signature-based detection to identify suspicious requests.

### Supported Detection Categories

| Attack / Activity              | Example Pattern | Response |
| ------------------------------ | --------------- | -------- |
| SQL Injection                  | `union select`  | HTTP 403 |
| Cross-Site Scripting           | `<script>`      | HTTP 403 |
| Directory Traversal            | `../`           | HTTP 403 |
| Local File Inclusion           | `etc/passwd`    | HTTP 403 |
| Command Injection              | `; whoami`      | HTTP 403 |
| Administrative Access          | `/admin`        | HTTP 403 |
| WordPress Admin Access         | `/wp-admin`     | HTTP 403 |
| Database Administration Access | `/phpmyadmin`   | HTTP 403 |

---

## 🚦 Rate Limiting

The application includes IP-based request rate limiting.

Current configuration:

* Maximum requests: **10**
* Time window: **10 seconds**
* Exceeded limit response: **HTTP 429**

During testing:

```text
Request 1  → HTTP 200
Request 2  → HTTP 200
...
Request 10 → HTTP 200
Request 11 → HTTP 429
```

---

## 🚨 Threat Severity Classification

Detected events are classified according to configured rules.

### HIGH

Examples include:

* SQL Injection
* Cross-Site Scripting
* Local File Inclusion
* Command Injection
* Rate Limit Exceeded

### MEDIUM

Examples include:

* Directory Traversal
* Suspicious Administrative Access
* Suspicious Database Access

### LOW

Used for events that do not match the higher-severity rules.

---

## 📊 Security Dashboard

The dashboard provides:

* System protection status
* Total request count
* Security alert count
* Threat severity summary
* Attack category distribution
* Threat distribution
* Suspicious IP addresses
* Recent security events
* Security feature status

---

## 📝 Security Logging

Security events are stored in:

```text
logs/security.log
```

The log records information such as:

* Timestamp
* Event type
* Severity
* IP address
* Attack category
* Detected pattern
* Request path
* HTTP response status

Example:

```text
SECURITY_EVENT | Severity=HIGH |
Type=SUSPICIOUS_REQUEST |
IP=127.0.0.1 |
Details=Category=Command Injection |
Pattern detected: ; whoami |
Path: /test
```

---

## 🧪 Testing

The project was tested locally using cURL requests.

### SQL Injection

```text
HTTP 403 FORBIDDEN
Request blocked by Sentinel Shield
```

### Cross-Site Scripting

```text
HTTP 403 FORBIDDEN
Request blocked by Sentinel Shield
```

### Directory Traversal

```text
HTTP 403 FORBIDDEN
Request blocked by Sentinel Shield
```

### Command Injection

```text
HTTP 403 FORBIDDEN
Request blocked by Sentinel Shield
```

### Rate Limiting

```text
Requests 1–10 → HTTP 200
Request 11    → HTTP 429
```

These tests demonstrate that the configured detection and rate-limiting mechanisms responded as expected on the local test cases.

---

## 📁 Project Structure

```text
sentinel-shield/
│
├── app.py
├── README.md
├── requirements.txt
├── .gitignore
│
├── modules/
│   └── security_logger.py
│
├── templates/
│   ├── index.html
│   ├── alerts.html
│   └── test.html
│
├── static/
│   └── favicon.svg
│
└── logs/
    └── security.log
```

---

## ▶️ How to Run

Clone or open the project directory:

```bash
cd sentinel-shield
```

Create/activate the virtual environment:

```bash
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the application:

```bash
python app.py
```

Open the dashboard:

```text
http://127.0.0.1:5000/
```

Security alerts:

```text
http://127.0.0.1:5000/alerts
```

---

## 📌 Limitations

This project is a learning and practical cybersecurity implementation.

The current detection system is primarily based on predefined patterns/signatures. It is not intended to replace a production WAF or enterprise IDS/IPS.

Possible future improvements include:

* More comprehensive attack signatures
* Better false-positive handling
* Persistent database storage
* Authentication and authorization
* Advanced anomaly detection
* More detailed analytics
* Automated reporting
* Integration with external security monitoring systems

---

## 📚 Project Purpose

This project was developed to gain practical experience with:

* Web security
* Intrusion detection
* WAF concepts
* HTTP request monitoring
* Security logging
* Threat classification
* Rate limiting
* Linux cybersecurity tools
* Flask-based security applications

---

## 👩‍💻 Author

**Komaljeet Kaur**

Cybersecurity & Forensics Graduate
