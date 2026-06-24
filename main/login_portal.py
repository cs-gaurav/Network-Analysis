from flask import Flask, request, render_template_string
from datetime import datetime
import sqlite3

app = Flask(__name__)

USERNAME = "admin"
PASSWORD = "admin123"

THRESHOLD_ATTEMPTS = 10
TIME_WINDOW_SECONDS = 5

failed_attempts = {}

LOGIN_PAGE = """
<form method="POST">
    Username: <input name="username"><br><br>
    Password: <input name="password" type="password"><br><br>
    <input type="submit" value="Login">
</form>
"""

def update_bruteforce_alert(ip):

    attempts = len(failed_attempts[ip])

    if attempts >= 50:
        severity = "HIGH"
    elif attempts >= 20:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    conn = sqlite3.connect("security.db")
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, count
        FROM alerts
        WHERE attack_type = ?
        AND source_ip = ?
        AND status = 'ACTIVE'
    """, ("Brute Force", ip))

    alert = cursor.fetchone()

    if alert:

        cursor.execute("""
            UPDATE alerts
            SET count = ?,
                severity = ?,
                last_seen = ?
            WHERE id = ?
        """, (
            attempts,
            severity,
            datetime.now(),
            alert[0]
        ))

    else:

        cursor.execute("""
            INSERT INTO alerts (
                attack_type,
                source_ip,
                count,
                severity,
                status,
                first_seen,
                last_seen
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            "Brute Force",
            ip,
            attempts,
            severity,
            "ACTIVE",
            datetime.now(),
            datetime.now()
        ))

    conn.commit()
    conn.close()

@app.route("/", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]
        ip = request.remote_addr

        if username == USERNAME and password == PASSWORD:
            return "Login Successful"

        current_time = datetime.now()

        if ip not in failed_attempts:
            failed_attempts[ip] = []

        failed_attempts[ip].append(current_time)

        failed_attempts[ip] = [
            t for t in failed_attempts[ip]
            if (current_time - t).total_seconds() <= TIME_WINDOW_SECONDS
        ]

        if len(failed_attempts[ip]) >= THRESHOLD_ATTEMPTS:

            print("[BRUTE FORCE ALERT]")
            print(f"IP: {ip}")
            print(f"Attempts: {len(failed_attempts[ip])}")

            update_bruteforce_alert(ip)

        return "Login Failed"

    return render_template_string(LOGIN_PAGE)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)