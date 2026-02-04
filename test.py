"""
vulnerable_app.py
WARNING: This file is intentionally insecure.
It demonstrates common security vulnerabilities in Python applications.
"""

import sqlite3
import os
import pickle
from flask import Flask, request

app = Flask(__name__)

# ==============================
# 1. HARD-CODED SECRETS (DATA LEAK)
# ==============================
DB_PASSWORD = "admin123"
SECRET_API_KEY = "sk-live-1234567890"
ADMIN_EMAIL = "admin@company.com"


# ==============================
# 2. INSECURE DATABASE CONNECTION
# ==============================
def get_db():
    # No encryption, no environment variables
    return sqlite3.connect("users.db")


# ==============================
# 3. SQL INJECTION VULNERABILITY
# ==============================
@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    conn = get_db()
    cursor = conn.cursor()

    # ❌ SQL Injection vulnerable query
    query = f"""
        SELECT * FROM users
        WHERE username = '{username}'
        AND password = '{password}'
    """

    print("Executing query:", query)  # ❌ Leaks sensitive info in logs
    cursor.execute(query)

    user = cursor.fetchone()
    conn.close()

    if user:
        return "Login successful"
    else:
        return "Invalid credentials"


# ==============================
# 4. DATA LEAK THROUGH DEBUG MODE
# ==============================
@app.route("/debug")
def debug():
    # ❌ Exposes sensitive internal data
    return {
        "db_password": DB_PASSWORD,
        "api_key": SECRET_API_KEY,
        "admin_email": ADMIN_EMAIL
    }


# ==============================
# 5. COMMAND INJECTION
# ==============================
@app.route("/ping")
def ping():
    host = request.args.get("host")

    # ❌ Command injection vulnerability
    command = f"ping -c 1 {host}"
    os.system(command)

    return "Ping executed"


# ==============================
# 6. UNSAFE DESERIALIZATION
# ==============================
@app.route("/load", methods=["POST"])
def load_data():
    file = request.files["file"]

    # ❌ Arbitrary code execution risk
    data = pickle.load(file)

    return f"Loaded data: {data}"


# ==============================
# 7. INSECURE FILE ACCESS
# ==============================
@app.route("/read")
def read_file():
    filename = request.args.get("file")

    # ❌ Path traversal vulnerability
    with open(filename, "r") as f:
        return f.read()


# ==============================
# 8. NO AUTHORIZATION CHECK
# ==============================
@app.route("/admin/delete_user")
def delete_user():
    user_id = request.args.get("id")

    conn = get_db()
    cursor = conn.cursor()

    # ❌ No auth, anyone can delete users
    cursor.execute(f"DELETE FROM users WHERE id = {user_id}")
    conn.commit()
    conn.close()

    return "User deleted"


# ==============================
# 9. RUNNING APP IN DEBUG MODE
# ==============================
if __name__ == "__main__":
    # ❌ Debug mode exposes stack traces & secrets
    app.run(debug=True)
