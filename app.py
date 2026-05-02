from flask import Flask, render_template, request, redirect
import sqlite3
from datetime import datetime
from ai_model import detect_suspicious_activity

app = Flask(__name__)


# ==============================
# DATABASE CONNECTION FUNCTION
# ==============================

def get_connection():
    return sqlite3.connect("database.db")


# ==============================
# LOGIN PAGE
# ==============================

@app.route("/", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT * FROM users WHERE username=? AND password=?",
            (username, password)
        )

        user = cursor.fetchone()

        time = datetime.now()
        ip_address = request.remote_addr

        if user:

            status = "SUCCESS"

            cursor.execute(
                "INSERT INTO login_attempts (username,time,status) VALUES (?,?,?)",
                (username + " | " + ip_address, time, status)
            )

            conn.commit()
            conn.close()

            return redirect("/dashboard")

        else:

            status = "FAILED"

            cursor.execute(
                "INSERT INTO login_attempts (username,time,status) VALUES (?,?,?)",
                (username + " | " + ip_address, time, status)
            )

            conn.commit()
            conn.close()

            return "Invalid Username or Password"

    return render_template("login.html")


# ==============================
# DASHBOARD PAGE
# ==============================

@app.route("/dashboard")
def dashboard():

    conn = get_connection()
    cursor = conn.cursor()

    # TOTAL ATTEMPTS
    cursor.execute("SELECT COUNT(*) FROM login_attempts")
    total = cursor.fetchone()[0]

    # FAILED ATTEMPTS
    cursor.execute(
        "SELECT COUNT(*) FROM login_attempts WHERE status='FAILED'"
    )
    failed = cursor.fetchone()[0]

    # UNIQUE ATTACKERS
    cursor.execute(
        "SELECT COUNT(DISTINCT username) FROM login_attempts"
    )
    attackers = cursor.fetchone()[0]

    # LOGIN LOG TABLE DATA
    cursor.execute(
        "SELECT username,time,status FROM login_attempts ORDER BY time DESC"
    )
    logs = cursor.fetchall()

    # TIMELINE DATA
    cursor.execute("SELECT time FROM login_attempts")
    timeline_data = cursor.fetchall()

    times = [row[0] for row in timeline_data]

    conn.close()

    # =========================
    # RISK LEVEL CALCULATION
    # =========================

    if failed <= 3:
        risk_level = "LOW"

    elif failed <= 7:
        risk_level = "MEDIUM"

    else:
        risk_level = "HIGH"

    return render_template(
        "dashboard.html",
        total=total,
        failed=failed,
        logs=logs,
        attackers=attackers,
        risk_level=risk_level,
        times=times
    )


# ==============================
# AI DETECTION ROUTE
# ==============================

@app.route("/detect_ai")
def detect_ai():

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT COUNT(*) FROM login_attempts WHERE status='FAILED'"
    )

    failed_attempts = cursor.fetchone()[0]

    conn.close()

    result = detect_suspicious_activity(failed_attempts)

    print(result)

    return redirect("/dashboard")


# ==============================
# RUN SERVER
# ==============================

if __name__ == "__main__":
    app.run(debug=True)