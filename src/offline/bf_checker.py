# detects brute force attack by checking total login attempts

import pandas as pd
import csv
import os
from datetime import datetime

THRESHOLD_ATTEMPTS = 10
TIME_WINDOW_SECONDS = 5

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

df = pd.read_csv("../dataset/login_attempts.csv")

df["Timestamp"] = pd.to_datetime(df["Timestamp"])

failed = df[df["Status"] == "FAILED"]

for ip in failed["IP_Address"].unique():

    ip_data = failed[
        failed["IP_Address"] == ip
    ]

    attempts = len(ip_data)

    duration = (
        ip_data["Timestamp"].max()
        - ip_data["Timestamp"].min()
    ).total_seconds()

    print("IP:", ip)
    print("Attempts:", attempts)
    print("Duration:", duration)

    if (
        attempts >= THRESHOLD_ATTEMPTS
        and duration <= TIME_WINDOW_SECONDS
    ):

        print("\n[BRUTE FORCE ALERT]")
        print("IP:", ip)
        print("Failed Attempts:", attempts)
        print(
            "Duration:",
            round(duration, 2),
            "seconds"
        )

        with open(
            ALERT_FILE,
            "a",
            newline=""
        ) as f:

            writer = csv.writer(f)

            writer.writerow([
                datetime.now(),
                "Brute Force",
                ip,
                "MEDIUM"
            ])