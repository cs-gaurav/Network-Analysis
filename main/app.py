from flask import Flask, render_template, jsonify
from threading import Thread
from scapy.all import *
from datetime import datetime
import sqlite3

app = Flask(__name__)

DB = "security.db"
THRESHOLD_PORTS = 20

port_tracker = {}

def get_connection():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def insert_traffic(timestamp, src_ip, dst_ip, protocol):
    conn = sqlite3.connect(DB)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO traffic_stats
        (timestamp, source_ip, destination_ip, protocol)
        VALUES (?, ?, ?, ?)
    """, (timestamp, src_ip, dst_ip, protocol))

    conn.commit()
    conn.close()

def update_portscan_alert(src_ip):

    ports_scanned = len(port_tracker[src_ip])

    if ports_scanned >= 500:
        severity = "HIGH"
    elif ports_scanned >= 100:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    conn = sqlite3.connect(DB)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, count
        FROM alerts
        WHERE attack_type=?
        AND source_ip=?
        AND status='ACTIVE'
    """, ("Port Scan", src_ip))

    alert = cursor.fetchone()

    if alert:

        cursor.execute("""
            UPDATE alerts
            SET count=?,
                severity=?,
                last_seen=?
            WHERE id=?
        """, (
            ports_scanned,
            severity,
            datetime.now(),
            alert[0]
        ))

    else:

        cursor.execute("""
            INSERT INTO alerts
            (
                attack_type,
                source_ip,
                count,
                severity,
                status,
                first_seen,
                last_seen
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            "Port Scan",
            src_ip,
            ports_scanned,
            severity,
            "ACTIVE",
            datetime.now(),
            datetime.now()
        ))

    conn.commit()
    conn.close()

def packet_callback(packet):

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
        datetime.now(),
        src_ip,
        dst_ip,
        protocol
    )

    if TCP not in packet:
        return

    if str(packet[TCP].flags) != "S":
        return

    if src_ip not in port_tracker:
        port_tracker[src_ip] = set()

    port_tracker[src_ip].add(
        packet[TCP].dport
    )

    if len(port_tracker[src_ip]) >= THRESHOLD_PORTS:
        update_portscan_alert(src_ip)

def start_sniffer():
    print("Packet Sniffer Started")

    sniff(
        iface="lo0",
        prn=packet_callback,
        store=False
    )

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
        WHERE status='ACTIVE'
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

    sniffer_thread = Thread(
        target=start_sniffer,
        daemon=True
    )

    sniffer_thread.start()

    app.run(debug=True)