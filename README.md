# Log Analyzer (Python SOC Tool)

## 🧠 Overview
This project is a Python-based log analysis tool that simulates core Security Operations Center (SOC) functionality.

It processes structured log files, detects suspicious patterns, and generates alerts for potential security incidents such as brute-force attacks and password spraying.

---

## 🚨 Features

- Log parsing and classification (INFO, WARNING, ERROR)
- Error aggregation per IP address
- Time-based detection of error spikes
- Detection of suspicious log messages
- Password spraying detection (multiple IPs targeting same user)
- Structured security reporting

---

## ⚙️ Detection Capabilities

### 1. Error Spike Detection
Identifies multiple error events from a single IP within a defined time window.

### 2. Suspicious Message Detection
Flags log entries containing indicators such as:
- Failed login attempts
- Unauthorized access

### 3. Password Spraying Detection
Detects when multiple IP addresses attempt to access the same user account.

---

## 📂 Project Structure
log-analyzer/
│
├── log_analyzer.py
├── sample_logs.txt
└── README.md

## 👨‍💻 Author
Francisco De La Rosa
Aspiring SOC Analyst | Cybersecurity Projects

---

## ▶️ How to Run

```bash
python log_analyzer.py
