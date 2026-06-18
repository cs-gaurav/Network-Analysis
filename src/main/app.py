from flask import Flask, render_template
import pandas as pd
import os

app = Flask(__name__)

@app.route("/")
def dashboard():

    traffic_file = "../dataset/normal_log.csv"
    alerts_file = "../dataset/alerts.csv"

    total_packets = 0
    source_ips = 0
    dest_ips = 0

    tcp_count = 0
    udp_count = 0
    icmp_count = 0

    top_ips = {}

    total_alerts = 0
    portscan_count = 0
    bruteforce_count = 0

    alerts = []

    # Network Statistics
    if os.path.exists(traffic_file):

        df = pd.read_csv(traffic_file)

        total_packets = len(df)

        source_ips = df["Source_IP"].nunique()

        dest_ips = df["Destination_IP"].nunique()

        top_ips = (
            df["Source_IP"]
            .value_counts()
            .head(10)
            .to_dict()
        )

        tcp_count = len(
            df[df["Protocol"] == "TCP"]
        )

        udp_count = len(
            df[df["Protocol"] == "UDP"]
        )

        icmp_count = len(
            df[df["Protocol"] == "ICMP"]
        )

    # Alert Statistics
    if os.path.exists(alerts_file):

        alerts_df = pd.read_csv(alerts_file)
        total_alerts = len(alerts_df)
        portscan_count = len(
            alerts_df[
                alerts_df["Attack_Type"] == "Port Scan"
            ]
        )

        bruteforce_count = len(
            alerts_df[
                alerts_df["Attack_Type"] == "Brute Force"
            ]
        )

        alerts = alerts_df.tail(10).to_dict(
            orient="records"
        )

    return render_template(
        "dash.html",
        total_packets=total_packets,
        source_ips=source_ips,
        dest_ips=dest_ips,
        tcp_count=tcp_count,
        udp_count=udp_count,
        icmp_count=icmp_count,
        total_alerts=total_alerts,
        portscan_count=portscan_count,
        bruteforce_count=bruteforce_count,
        top_ips=top_ips,
        alerts=alerts
    )

if __name__ == "__main__":
    app.run(debug=True)