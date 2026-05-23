# Honeypot Attack Monitoring System

A simple cybersecurity honeypot project built with Python to capture, analyze, and visualize malicious login attempts.

This project simulates a fake login system to monitor attacker behavior and generate attack analytics.

---

# Features

- Fake login honeypot
- Logs login attempts
- Tracks attacker IPs
- Visualizes attack data
- Generates analytics graphs
- HTML dashboard support

---

# Project Structure

```text
honeypot/
│
├── honeypot.py              # Main honeypot server
├── analyse_logs.py          # Log analysis script
├── honeypot.log             # Captured login attempts
├── dashboard.html           # Dashboard visualization
├── login.html               # Fake login page
│
├── attacks_per_hour.png
├── top_countries.png
├── top_ips.png
└── top_usernames.png
