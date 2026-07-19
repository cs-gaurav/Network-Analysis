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
    last_seen TEXT,
    severity TEXT,
    count INTEGER
)
""")

# If security.db already existed from before (without these columns), add
# them now. Safe to re-run: sqlite3 raises OperationalError if a column is
# already there, which we just ignore.
for column_def in ("severity TEXT", "count INTEGER"):
    try:
        cursor.execute(f"ALTER TABLE alerts ADD COLUMN {column_def}")
    except sqlite3.OperationalError:
        pass

conn.commit()
conn.close()

print("Database created successfully.")