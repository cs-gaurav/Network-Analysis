#ports contacte by this ip address
import pandas as pd

df = pd.read_csv("portscan_log.csv")

ip = "57.144.49.32"

ip_data = df[df["Source_IP"] == ip]

print("Packets:", len(ip_data))

print("\nUnique Destination Ports:")
print(sorted(ip_data["Destination_Port"].unique()))