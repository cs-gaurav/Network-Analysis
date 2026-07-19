import sys
import queue
from flask import Flask, render_template, jsonify
from threading import Thread
from scapy.all import *
from datetime import datetime
import sqlite3

sys.setrecursionlimit(10000)

app = Flask(__name__)

DB = "security.db"
THRESHOLD_PORTS = 20
IDLE_TIMEOUT_SECONDS = 60 
SCAN_WINDOW_SECONDS = 30 

MEDIUM_PORTS = 100
HIGH_PORTS = 500

port_tracker = {}      
scan_window = {}       
last_packet_time = {}
alerted_severity = {}
pkt_queue = queue.Queue()
IGNORED_PORTS = {5000, 8000}

def compute_port_scan_severity(port_count):
    if port_count >= HIGH_PORTS:
        return "HIGH"
    elif port_count >= MEDIUM_PORTS:
        return "MEDIUM"
    elif port_count >= THRESHOLD_PORTS:
        return "LOW"
    else:
        return None

def get_connection():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def insert_traffic(cursor, timestamp, src_ip, dst_ip, protocol):
    cursor.execute("""
        INSERT INTO traffic_stats
        (timestamp, source_ip, destination_ip, protocol)
        VALUES (?, ?, ?, ?)
    """, (timestamp, src_ip, dst_ip, protocol))

def update_portscan_alert(cursor, src_ip, severity, count):

    cursor.execute("""
        SELECT id
        FROM alerts
        WHERE attack_type=?
        AND source_ip=?
    """, ("Port Scan", src_ip))

    alert = cursor.fetchone()

    if alert:

        cursor.execute("""
            UPDATE alerts
            SET last_seen=?, severity=?, count=?
            WHERE id=?
        """, (
            datetime.now().isoformat(),
            severity,
            count,
            alert[0]
        ))

    else:

        cursor.execute("""
            INSERT INTO alerts
            (
                attack_type,
                source_ip,
                last_seen,
                severity,
                count
            )
            VALUES (?, ?, ?, ?, ?)
        """, (
            "Port Scan",
            src_ip,
            datetime.now().isoformat(),
            severity,
            count
        ))

def process_packet(cursor, packet):
    if IP not in packet:
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    protocol = "OTHER"

    if TCP in packet:
        protocol = "TCP"
    elif UDP in packet:
        protocol = "UDP"
    elif ICMP in packet:
        protocol = "ICMP"

    insert_traffic(
        cursor,
        datetime.now().isoformat(),
        src_ip,
        dst_ip,
        protocol
    )

    if TCP not in packet:
        return

    if str(packet[TCP].flags) != "S":
        return

    now = datetime.now()

    if src_ip in last_packet_time:
        gap = (now - last_packet_time[src_ip]).total_seconds()
        if gap > IDLE_TIMEOUT_SECONDS:
            port_tracker[src_ip] = set()
            scan_window[src_ip] = []
            alerted_severity[src_ip] = None

    last_packet_time[src_ip] = now

    if src_ip not in port_tracker:
        port_tracker[src_ip] = set()
    if src_ip not in scan_window:
        scan_window[src_ip] = []

    dport = packet[TCP].dport
    if dport in IGNORED_PORTS:
        return

    port_tracker[src_ip].add(dport)

    scan_window[src_ip].append((now, dport))
    cutoff = now.timestamp() - SCAN_WINDOW_SECONDS
    scan_window[src_ip] = [
        (ts, p) for (ts, p) in scan_window[src_ip]
        if ts.timestamp() >= cutoff
    ]

    distinct_ports_in_window = {p for (_, p) in scan_window[src_ip]}
    current_severity = compute_port_scan_severity(len(distinct_ports_in_window))

    if current_severity is not None:

        update_portscan_alert(
            cursor,
            src_ip,
            current_severity,
            len(port_tracker[src_ip])
        )

        if current_severity != alerted_severity.get(src_ip):

            print("[PORT SCAN ALERT]")
            print(f"IP: {src_ip}")
            print(f"Ports Scanned: {len(port_tracker[src_ip])}")
            print(f"Severity: {current_severity}")

            alerted_severity[src_ip] = current_severity

    else:
        alerted_severity[src_ip] = None

def packet_callback(packet):
    pkt_queue.put(packet)

def db_worker():
    conn = sqlite3.connect(DB, check_same_thread=False)
    cursor = conn.cursor()

    while True:
        packet = pkt_queue.get()
        try:
            process_packet(cursor, packet)
            conn.commit()
        except Exception as e:
            print("DB worker error:", e)

def start_sniffer():
    while True:
        try:
            sniff(
                iface="lo0",
                filter="tcp",
                prn=packet_callback,
                store=False
            )
        except Exception as e:
            print("Sniffer error:", e)

@app.route("/")
def dashboard():
    return render_template("dash.html")

@app.route("/api/stats")
def stats():

    conn = get_connection()
    cursor = conn.cursor()

    total_packets = cursor.execute(
        "SELECT COUNT(*) FROM traffic_stats"
    ).fetchone()[0]

    source_ips = cursor.execute(
        "SELECT COUNT(DISTINCT source_ip) FROM traffic_stats"
    ).fetchone()[0]

    dest_ips = cursor.execute(
        "SELECT COUNT(DISTINCT destination_ip) FROM traffic_stats"
    ).fetchone()[0]

    tcp_count = cursor.execute(
        "SELECT COUNT(*) FROM traffic_stats WHERE protocol='TCP'"
    ).fetchone()[0]

    udp_count = cursor.execute(
        "SELECT COUNT(*) FROM traffic_stats WHERE protocol='UDP'"
    ).fetchone()[0]

    icmp_count = cursor.execute(
        "SELECT COUNT(*) FROM traffic_stats WHERE protocol='ICMP'"
    ).fetchone()[0]

    other_count = cursor.execute(
        "SELECT COUNT(*) FROM traffic_stats WHERE protocol='OTHER'"
    ).fetchone()[0]

    top_ips = cursor.execute("""
        SELECT source_ip, COUNT(*) AS cnt
        FROM traffic_stats
        GROUP BY source_ip
        ORDER BY cnt DESC
        LIMIT 10
    """).fetchall()

    active_alerts = cursor.execute("""
        SELECT *
        FROM alerts
    """).fetchall()

    conn.close()

    return jsonify({
        "total_packets": total_packets,
        "source_ips": source_ips,
        "dest_ips": dest_ips,
        "tcp_count": tcp_count,
        "udp_count": udp_count,
        "icmp_count": icmp_count,
        "other_count": other_count,
        "top_ips": [dict(row) for row in top_ips],
        "alerts": [dict(row) for row in active_alerts]
    })

if __name__ == "__main__":

    db_worker_thread = Thread(
        target=db_worker,
        daemon=True
    )
    db_worker_thread.start()

    sniffer_thread = Thread(
        target=start_sniffer,
        daemon=True
    )
    sniffer_thread.start()

    app.run(host="0.0.0.0", port=5000)
