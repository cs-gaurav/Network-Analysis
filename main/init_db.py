import sqlite3

conn = sqlite3.connect("security.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS traffic_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    source_ip TEXT,
    destination_ip TEXT,
    protocol TEXT
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    attack_type TEXT,
    source_ip TEXT,
    count INTEGER,
    severity TEXT,
    status TEXT,
    first_seen TEXT,
    last_seen TEXT
)
""")

conn.commit()
conn.close()

print("Database created successfully.")