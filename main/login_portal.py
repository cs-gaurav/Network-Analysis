from flask import Flask, request, render_template_string
from datetime import datetime
import sqlite3
import threading

app = Flask(__name__)

USERNAME = "admin"
PASSWORD = "admin123"

THRESHOLD_ATTEMPTS = 10

MEDIUM_ATTEMPTS = 20
HIGH_ATTEMPTS = 50

INACTIVITY_TIMEOUT_SECONDS = 10

failed_attempts = {}
alerted_severity = {}

DOS_THRESHOLD_REQUESTS = 30
DOS_MEDIUM_REQUESTS = 100
DOS_HIGH_REQUESTS = 300
DOS_WINDOW_SECONDS = 5

INACTIVITY_TIMEOUT_SECONDS_DOS = 5

request_log = {}
dos_session = {}
dos_last_write = {}
DOS_HEARTBEAT_SECONDS = 2

dos_lock = threading.Lock()

def compute_dos_severity(request_count):
    if request_count >= DOS_HIGH_REQUESTS:
        return "HIGH"
    elif request_count >= DOS_MEDIUM_REQUESTS:
        return "MEDIUM"
    elif request_count >= DOS_THRESHOLD_REQUESTS:
        return "LOW"
    else:
        return None

def compute_bruteforce_severity(attempt_count):
    if attempt_count >= HIGH_ATTEMPTS:
        return "HIGH"
    elif attempt_count >= MEDIUM_ATTEMPTS:
        return "MEDIUM"
    elif attempt_count >= THRESHOLD_ATTEMPTS:
        return "LOW"
    else:
        return None

LOGIN_PAGE = """
<form method="POST">
    Username: <input name="username"><br><br>
    Password: <input name="password" type="password"><br><br>
    <input type="submit" value="Login">
</form>
"""

def update_bruteforce_alert(ip, severity, count):

    conn = sqlite3.connect("security.db")
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id
        FROM alerts
        WHERE attack_type = ?
        AND source_ip = ?
    """, ("Brute Force", ip))

    alert = cursor.fetchone()

    if alert:

        cursor.execute("""
            UPDATE alerts
            SET last_seen = ?, severity = ?, count = ?
            WHERE id = ?
        """, (
            datetime.now().isoformat(),
            severity,
            count,
            alert[0]
        ))

    else:

        cursor.execute("""
            INSERT INTO alerts (
                attack_type,
                source_ip,
                last_seen,
                severity,
                count
            )
            VALUES (?, ?, ?, ?, ?)
        """, (
            "Brute Force",
            ip,
            datetime.now().isoformat(),
            severity,
            count
        ))

    conn.commit()
    conn.close()

def update_dos_alert(ip, severity, count):

    conn = sqlite3.connect("security.db")
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id
        FROM alerts
        WHERE attack_type = ?
        AND source_ip = ?
    """, ("DoS", ip))

    alert = cursor.fetchone()

    if alert:

        cursor.execute("""
            UPDATE alerts
            SET last_seen = ?, severity = ?, count = ?
            WHERE id = ?
        """, (
            datetime.now().isoformat(),
            severity,
            count,
            alert[0]
        ))

    else:

        cursor.execute("""
            INSERT INTO alerts (
                attack_type,
                source_ip,
                last_seen,
                severity,
                count
            )
            VALUES (?, ?, ?, ?, ?)
        """, (
            "DoS",
            ip,
            datetime.now().isoformat(),
            severity,
            count
        ))

    conn.commit()
    conn.close()

@app.before_request
def track_dos():

    ip=request.remote_addr
    now=datetime.now()

    with dos_lock:
        request_log.setdefault(ip,[])
        request_log[ip].append(now)

        cutoff=now.timestamp()-DOS_WINDOW_SECONDS
        request_log[ip]=[t for t in request_log[ip] if t.timestamp()>=cutoff]

        live_count = len(request_log[ip])
        raw_severity = compute_dos_severity(live_count)

        session = dos_session.get(ip)

        if session is not None and (
            now - session["last_seen"]
        ).total_seconds() > INACTIVITY_TIMEOUT_SECONDS_DOS:
            session = None
            dos_session.pop(ip, None)
            dos_last_write.pop(ip, None)

        if session is None or (now - session["last_seen"]).total_seconds() > INACTIVITY_TIMEOUT_SECONDS_DOS:
            total_count = 1
            current_severity = raw_severity
        else:
            total_count = session["count"] + 1
            previous = session.get("severity")
            ranks = {None:0, "LOW":1, "MEDIUM":2, "HIGH":3}
            current_severity = previous if ranks[previous] > ranks[raw_severity] else raw_severity

        dos_session[ip] = {
            "count": total_count,
            "last_seen": now,
            "severity": current_severity
        }

        last = dos_last_write.get(ip)
        heartbeat = current_severity is not None and last is not None and (now-last).total_seconds() >= DOS_HEARTBEAT_SECONDS
        changed = current_severity is not None and (session is None or current_severity != session.get("severity"))

        if current_severity is not None and (changed or heartbeat):
            update_dos_alert(ip, current_severity, total_count)
            dos_last_write[ip] = now

        if session is not None and (now-session["last_seen"]).total_seconds() > INACTIVITY_TIMEOUT_SECONDS_DOS:
            dos_last_write.pop(ip, None)

@app.route("/", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]
        ip = request.remote_addr

        if username == USERNAME and password == PASSWORD:
            return "Login Successful"

        current_time = datetime.now()

        record = failed_attempts.get(ip)

        if record is None or (current_time - record["last_seen"]).total_seconds() > INACTIVITY_TIMEOUT_SECONDS:
            attempt_count = 1
        else:
            attempt_count = record["count"] + 1

        failed_attempts[ip] = {"count": attempt_count, "last_seen": current_time}

        current_severity = compute_bruteforce_severity(attempt_count)

        if current_severity is not None:
            update_bruteforce_alert(
                ip,
                current_severity,
                attempt_count
            )
            if current_severity != alerted_severity.get(ip):
                print("[BRUTE FORCE ALERT]")
                print(f"IP: {ip}")
                print(f"Attempts: {attempt_count}")
                print(f"Severity: {current_severity}")
                alerted_severity[ip] = current_severity
        elif current_severity is None:
            alerted_severity[ip] = None
            
        return "Login Failed"

    return render_template_string(LOGIN_PAGE)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, threaded=True)
