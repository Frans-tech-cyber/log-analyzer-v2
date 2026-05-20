# Log Analyzer v2 (Python SOC Project)

## 🧠 Overview
This project is a Python-based log analysis tool designed to simulate basic Security Operations Center (SOC) functionality.

It parses log files, classifies events, and detects suspicious activity such as repeated errors and potential brute-force patterns.

---

## 🚨 Features

- Parses structured log files
- Classifies events (INFO, WARNING, ERROR)
- Tracks error frequency per IP address
- Detects time-based attack patterns
- Identifies suspicious log messages
- Generates a structured analysis report

---

## ⚙️ How It Works

1. Reads log file (`sample_logs.txt`)
2. Extracts:
   - Timestamp
   - IP address
   - Log level
   - Message
3. Aggregates:
   - Event counts
   - Errors per IP
   - Error message frequency
4. Detects:
   - Error spikes within a time window
   - Suspicious messages (e.g. failed login, unauthorized access)
5. Outputs a structured report

---

## 📂 Project Structure

log-analyzer-v2/
│
├── log_analyzer.py # Main analysis script
├── sample_logs.txt # Example log file
└── README.md # Documentation

---

## 👨‍💻 Author

Frans De La Rosa
Cybersecurity / SOC Analyst Learning Project

---

## ▶️ How to Run

```bash
python log_analyzer.py
