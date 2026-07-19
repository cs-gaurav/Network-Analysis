# Real-Time Network Traffic Monitoring and IDS
Lightweight IDS built with Python, Flask, Scapy and SQLite.

## Features
- Real-time packet capture
- Port Scan detection
- Brute Force detection
- HTTP DoS detection
- Severity-based alerts
- Live dashboard

## Stack
Python, Flask, Scapy, SQLite, HTML, CSS, JavaScript

## Run
```bash
python init_db.py
python app.py
python login_portal.py
```

## Demo
- Port Scan: `nmap -sS <target-ip>`
- Brute Force: `python bf_attack.py`
- DoS: `python dos_attack.py`
