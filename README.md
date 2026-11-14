LoginGuard

A Python-based SSH Failed Login Detection Tool

LoginGuard is a cybersecurity tool written in Python that analyzes SSH authentication logs to detect suspicious login activity.

Features
- Supports only IPv4 address detection 
- Reads SSH authentication log files.
- Detects failed login attempts.
- Counts failed attempts by IP address.
- Identifies IP addresses exceeding a defined threshold.
- Generates a security report.

Requirements

- Python 3
- SSH authentication log file (e.g. "auth.log")

Usage

Run the tool using:

python detector.py /var/log/auth.log

To set a custom detection threshold:

python detector.py auth.log --threshold NUMBER

Replace "NUMBER" with your desired threshold.

How It Works

1. Reads the authentication log file.
2. Searches for failed SSH login attempts.
3. Extracts the source IP addresses.
4. Counts failed attempts for each IP.
5. Flags suspicious IP addresses.
6. Generates a security report.

Project Structure

LoginGuard/
│
├── detector.py
├── README.md
└── .gitignore

Purpose

This project demonstrates practical cybersecurity concepts, including log analysis, authentication monitoring, and basic brute-force attack detection.

Disclaimer

This tool is intended for educational and defensive security purposes.

---

Author: Abdulaziz803654
