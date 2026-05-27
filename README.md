# Log Analyzer (Python SOC Detection Tool)

## 🧠 Overview

This project is a Python-based SOC (Security Operations Center) log analysis tool designed to detect suspicious authentication and system activity from structured log files.

The tool simulates core SOC detection workflows by analyzing logs, correlating events, and generating alerts for potential security threats.

---

# 🚨 Detection Features

## 1. Error Spike Detection
Detects multiple error events from the same IP address within a defined time window.

Example:
- Multiple ERROR events from one IP within 5 minutes

---

## 2. Suspicious Message Detection
Flags high-risk log entries such as:
- Failed login attempts
- Unauthorized access attempts

---

## 3. Password Spraying Detection
Detects multiple IP addresses attempting to access the same user account.

Example:
- Multiple IPs targeting the `admin` account

---

## 4. Success-after-Failure Detection
Detects successful logins occurring shortly after multiple failed login attempts from the same IP address.

This may indicate:
- Credential compromise
- Successful brute-force attack
- Unauthorized account access

---

# 📂 Project Structure

```text
log-analyzer/
│
├── log_analyzer.py
├── sample_logs.txt
└── README.md
```

---

# ▶️ How to Run

```bash
python log_analyzer.py
```

---

# 🛠️ Technologies Used

- Python 3
- datetime module
- Dictionaries
- Sets
- Time-based event correlation

---

# 🛡️ Skills Demonstrated

- Log parsing and analysis
- SOC alerting concepts
- Threat detection engineering
- Behavioral analysis
- Python automation
- Event correlation logic

---

# 🚀 Future Improvements

- Real-time log monitoring
- CLI argument support
- JSON log support
- Severity scoring
- SIEM integration
- Port scan detection

---

# 👨‍💻 Author

Frans De La Rosa

Aspiring SOC Analyst focused on threat detection, log analysis, and security automation.
