from scapy.all import *
from collections import defaultdict
from datetime import datetime

THRESHOLD_PORTS = 100
TIME_WINDOW_SECONDS = 10

scan_tracker = defaultdict(lambda: {
    "ports": set(),
    "first_seen": None
})

alerted_ips = set()

def packet_callback(packet):

    if IP not in packet or TCP not in packet:
        return

    if str(packet[TCP].flags) != "S":
        return

    src_ip = packet[IP].src
    dst_port = packet[TCP].dport
    current_time = datetime.now()

    if scan_tracker[src_ip]["first_seen"] is None:
        scan_tracker[src_ip]["first_seen"] = current_time

    scan_tracker[src_ip]["ports"].add(dst_port)

    duration = (
        current_time -
        scan_tracker[src_ip]["first_seen"]
    ).total_seconds()

    unique_ports = len(
        scan_tracker[src_ip]["ports"]
    )

    if (
        unique_ports > THRESHOLD_PORTS
        and duration <= TIME_WINDOW_SECONDS
        and src_ip not in alerted_ips
    ):

        alerted_ips.add(src_ip)

        print("\n[PORT SCAN ALERT]")
        print("Source IP:", src_ip)
        print("Unique Ports:", unique_ports)
        print("Duration:", round(duration, 2), "seconds")
        print("Ports Contacted:")
        print(sorted(scan_tracker[src_ip]["ports"]))

print("Real-Time Port Scan Detector Started...")

sniff(
    iface="lo0",
    prn=packet_callback,
    store=False
)