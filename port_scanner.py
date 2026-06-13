#57.144.49.32
import pandas as pd

THRESHOLD_PORTS = 20
TIME_WINDOW_SECONDS = 60

df = pd.read_csv("network_log.csv")

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

        print("\n[PORT SCAN ALERT]")
        print("Source IP:", ip)
        print("Unique Ports:", unique_ports)
        print("Well Known Ports:", well_known_ports)
        print("Duration:", duration, "seconds")