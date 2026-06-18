from scapy.all import *
import csv
from datetime import datetime
import os
print(os.getcwd())

CSV_FILE = "../dataset/portscan_log.csv"

# Create CSV file with headers if it doesn't exist
if os.path.exists(CSV_FILE):
    os.remove(CSV_FILE)
    
if not os.path.exists(CSV_FILE):
    with open(CSV_FILE, "w", newline="") as file:
        writer = csv.writer(file)

        writer.writerow([
            "Timestamp",
            "Source_IP",
            "Destination_IP",
            "Source_Port",
            "Destination_Port",
            "Protocol",
            "Packet_Length",
            "TCP_Flags"
        ])

def packet_callback(packet):

    if IP not in packet:
        return

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    protocol = "OTHER"
    src_port = "-"
    dst_port = "-"
    tcp_flags = "-"

    if TCP in packet:
        protocol = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        tcp_flags = str(packet[TCP].flags)

    elif UDP in packet:
        protocol = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    elif ICMP in packet:
        protocol = "ICMP"

    packet_length = len(packet)

    # Display packet information
    print("-" * 50)
    print("Timestamp:", timestamp)
    print("Source IP:", src_ip)
    print("Destination IP:", dst_ip)
    print("Protocol:", protocol)
    print("Source Port:", src_port)
    print("Destination Port:", dst_port)
    print("Packet Length:", packet_length)
    print("TCP Flags:", tcp_flags)

    # Save to CSV
    with open(CSV_FILE, "a", newline="") as file:
        writer = csv.writer(file)

        writer.writerow([
            timestamp,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            packet_length,
            tcp_flags
        ])

print("Starting packet capture...")
sniff(iface="lo0", prn=packet_callback, store=False)