import sqlite3
from sklearn.ensemble import IsolationForest


def detect_suspicious_activity(failed_attempts=None):

    """
    AI-based anomaly detection using Isolation Forest
    """

    # connect database
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    # fetch login status
    cursor.execute("SELECT status FROM login_attempts")
    data = cursor.fetchall()

    conn.close()

    # convert status into numeric
    X = []

    for row in data:

        if row[0] == "FAILED":
            X.append([1])

        else:
            X.append([0])

    # safety check (agar data kam ho)
    if len(X) < 2:
        print("Not enough data for AI detection")
        return "LOW"

    # train AI model
    model = IsolationForest(contamination=0.3)

    model.fit(X)

    # prediction
    prediction = model.predict(X)

    # anomaly detection
    if -1 in prediction:

        print("⚠ Suspicious Activity Detected")

        return "HIGH"

    else:

        print("System Normal")

        return "LOW"