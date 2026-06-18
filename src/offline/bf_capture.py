from flask import Flask, request, render_template_string
from datetime import datetime
import csv
import os

app = Flask(__name__)

LOG_FILE = "../dataset/login_attempts.csv"

if os.path.exists(LOG_FILE):
    os.remove(LOG_FILE)
    
if not os.path.exists(LOG_FILE):

    with open(LOG_FILE, "w", newline="") as f:

        writer = csv.writer(f)

        writer.writerow([
            "Timestamp",
            "IP_Address",
            "Username",
            "Status"
        ])

USERNAME = "admin"
PASSWORD = "admin123"

LOGIN_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>Login Portal</title>
</head>
<body>

    <h2>Login Page</h2>

    <form method="POST">

        Username:
        <input name="username">

        <br><br>

        Password:
        <input name="password" type="password">

        <br><br>

        <input type="submit" value="Login">

    </form>

</body>
</html>
"""

@app.route("/", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]

        password = request.form["password"]

        status = "FAILED"

        if (
            username == USERNAME
            and password == PASSWORD
        ):

            status = "SUCCESS"

        with open(
            LOG_FILE,
            "a",
            newline=""
        ) as f:

            writer = csv.writer(f)

            writer.writerow([

                datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S.%f"
                ),

                request.remote_addr,

                username,

                status

            ])

        if status == "SUCCESS":

            return "Login Successful"

        return "Login Failed"

    return render_template_string(
        LOGIN_PAGE
    )

if __name__ == "__main__":

    app.run(debug=True)