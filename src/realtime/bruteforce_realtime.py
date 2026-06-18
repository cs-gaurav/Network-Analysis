from flask import Flask, request, render_template_string
from datetime import datetime
from collections import defaultdict

app = Flask(__name__)

USERNAME = "admin"
PASSWORD = "admin123"

THRESHOLD_ATTEMPTS = 10
TIME_WINDOW_SECONDS = 5

failed_attempts = defaultdict(list)
alerted_ips = set()

LOGIN_PAGE = """
<form method="POST">
    Username: <input name="username"><br><br>
    Password: <input name="password" type="password"><br><br>
    <input type="submit" value="Login">
</form>
"""

@app.route("/", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        ip = request.remote_addr
        current_time = datetime.now()

        # Successful Login
        if username == USERNAME and password == PASSWORD:

            if ip in failed_attempts:
                del failed_attempts[ip]

            return "Login Successful"

        # Failed Login
        failed_attempts[ip].append(current_time)

        # Remove attempts older than TIME_WINDOW_SECONDS
        failed_attempts[ip] = [
            t for t in failed_attempts[ip]
            if (current_time - t).total_seconds()
            <= TIME_WINDOW_SECONDS
        ]

        attempts = len(failed_attempts[ip])

        if (
            attempts >= THRESHOLD_ATTEMPTS
            and ip not in alerted_ips
        ):

            alerted_ips.add(ip)

            print("\n[BRUTE FORCE ALERT]")
            print("Source IP:", ip)
            print("Failed Attempts:", attempts)
            print(
                "Time Window:",
                TIME_WINDOW_SECONDS,
                "seconds"
            )

        return "Login Failed"

    return render_template_string(LOGIN_PAGE)

app.run(debug=True)