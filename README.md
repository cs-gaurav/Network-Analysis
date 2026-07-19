# Network Traffic Monitoring and Attack Detection System

A real-time Intrusion Detection System (IDS) developed using Python, Flask, Scapy, and SQLite. The system monitors network traffic, detects suspicious activities such as Port Scanning and Brute Force attacks, and displays alerts through a live dashboard.

## Features

- Real-time packet capture using Scapy
- Port Scan detection
- Brute Force attack detection
- Live web dashboard
- SQLite database for traffic and alert storage
- Active security incident tracking
- Severity-based alert classification

## Technologies Used

- Python
- Flask
- Scapy
- SQLite
- HTML
- CSS
- JavaScript
- Chart.js

## Detection Logic

### Port Scan Detection

An alert is generated when a source IP attempts connections to multiple unique destination ports within a short period of time.

Severity Levels:

- LOW: 20-99 ports
- MEDIUM: 100-499 ports
- HIGH: 500+ ports

### Brute Force Detection

An alert is generated when multiple failed login attempts are detected from the same IP address.

Severity Levels:

- LOW: 10-19 failed attempts
- MEDIUM: 20-49 failed attempts
- HIGH: 50+ failed attempts

## Database Schema

### traffic_stats

| Field | Description |
|---------|-------------|
| timestamp | Packet timestamp |
| source_ip | Source IP address |
| destination_ip | Destination IP address |
| protocol | TCP/UDP/ICMP |

### alerts

| Field | Description |
|---------|-------------|
| attack_type | Type of attack |
| source_ip | Attacker IP |
| count | Attack count |
| severity | Risk level |
| status | ACTIVE |
| first_detected | First detection time |
| last_detected | Most recent activity |

## Running the Project

```bash
python init_db.py
python app.py
python login_portal.py
python bf_attack.py
nmap -sS 127.0.0.1