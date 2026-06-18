import pandas as pd
import csv
import os

THRESHOLD_PORTS = 20
TIME_WINDOW_SECONDS = 60

ALERT_FILE = "../dataset/alerts.csv"

if os.path.exists(ALERT_FILE):
    os.remove(ALERT_FILE)

if not os.path.exists(ALERT_FILE):
    with open(ALERT_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Timestamp",
            "Attack_Type",
            "Source_IP",
            "Severity"
        ])

df = pd.read_csv("../dataset/portscan_log.csv")

df["Timestamp"] = pd.to_datetime(df["Timestamp"])

# Only SYN packets
syn_packets = df[df["TCP_Flags"] == "S"]

for ip in syn_packets["Source_IP"].unique():

    ip_data = syn_packets[syn_packets["Source_IP"] == ip]

    start_time = ip_data["Timestamp"].min()
    end_time = ip_data["Timestamp"].max()

    duration = (end_time - start_time).total_seconds()

    unique_ports = ip_data["Destination_Port"].nunique()

    # Count well-known ports (1-1024)
    well_known_ports = ip_data[
        pd.to_numeric(ip_data["Destination_Port"], errors="coerce")
        .between(1, 1024)
    ]["Destination_Port"].nunique()

    if (
        unique_ports > THRESHOLD_PORTS
        and duration <= TIME_WINDOW_SECONDS
        and well_known_ports > 5
    ):

        ports_contacted = sorted(
            pd.to_numeric(
                ip_data["Destination_Port"],
                errors="coerce"
            ).dropna().unique()
        )

        print("\n[PORT SCAN ALERT]")
        print("Source IP:", ip)
        print("Unique Ports:", unique_ports)
        print("Well Known Ports:", well_known_ports)
        print("Duration:", duration, "seconds")
        print("Ports Contacted:")
        print(ports_contacted)

        with open(ALERT_FILE, "a", newline="") as f:
            writer = csv.writer(f)

            writer.writerow([
                pd.Timestamp.now(),
                "Port Scan",
                ip,
                "HIGH"
            ])