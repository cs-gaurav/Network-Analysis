import pandas as pd

df = pd.read_csv("portscan_log.csv")

print("Total Packets:", len(df))

print("\nUnique Source IPs:")
print(df["Source_IP"].nunique())

print("\nUnique Destination IPs:")
print(df["Destination_IP"].nunique())

print("\nUnique Destination Ports:")
print(df["Destination_Port"].nunique())

print("\nTop 10 Source IPs by Packet Count:")
print(df["Source_IP"].value_counts().head(10))

print("\nTop 10 Destination Ports:")
print(df["Destination_Port"].value_counts().head(10))

print("\nUnique Destination Ports Contacted By Each Source IP:")
result = (
    df.groupby("Source_IP")["Destination_Port"]
    .nunique()
    .sort_values(ascending=False)
)

print(result.head(20))