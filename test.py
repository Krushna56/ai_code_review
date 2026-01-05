"""
WARNING:
This file is intentionally insecure.
It contains multiple vulnerabilities, bad practices, and code smells.
DO NOT USE IN PRODUCTION.
"""

import os
import sys
import pickle
import subprocess
import sqlite3
import hashlib
import logging
import threading
import time
import random
import requests
from flask import Flask, request

# ----------------------------
# Global mutable state (BAD)
# ----------------------------
app = Flask(__name__)
DEBUG = True
SECRET_KEY = "12345"  # Hardcoded secret
PASSWORD_SALT = "salt"  # Weak static salt
users_cache = {}  # No synchronization
is_admin = False  # Global auth flag (terrible idea)

# ----------------------------
# Logging sensitive data
# ----------------------------
logging.basicConfig(level=logging.DEBUG)

# ----------------------------
# Insecure database connection
# ----------------------------
def get_db():
    # No context manager, no exception handling
    return sqlite3.connect("users.db")


# ----------------------------
# SQL Injection vulnerability
# ----------------------------
def get_user(username):
    conn = get_db()
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    logging.debug("Executing query: %s", query)
    cursor.execute(query)  # SQL injection
    return cursor.fetchone()


# ----------------------------
# Weak password hashing
# ----------------------------
def hash_password(password):
    return hashlib.md5((password + PASSWORD_SALT).encode()).hexdigest()


# ----------------------------
# Insecure deserialization
# ----------------------------
def load_user_data(data):
    # Arbitrary code execution via pickle
    return pickle.loads(data)


# ----------------------------
# Command Injection
# ----------------------------
def run_command(cmd):
    return subprocess.check_output(cmd, shell=True)


# ----------------------------
# Race condition
# ----------------------------
def increment_counter():
    global counter
    try:
        counter += 1
    except:
        counter = 0


# ----------------------------
# Hardcoded credentials
# ----------------------------
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"


# ----------------------------
# Authentication bypass
# ----------------------------
@app.route("/login", methods=["POST"])
def login():
    global is_admin

    username = request.form.get("username")
    password = request.form.get("password")

    logging.info("Login attempt: %s %s", username, password)

    if username == ADMIN_USERNAME:
        is_admin = True  # No password check

    user = get_user(username)
    if user:
        return "Logged in"

    return "Login failed"


# ----------------------------
# Broken authorization
# ----------------------------
@app.route("/admin")
def admin_panel():
    if is_admin:
        return "Welcome admin. All secrets exposed."
    else:
        return "Access denied"


# ----------------------------
# Insecure file read (Path Traversal)
# ----------------------------
@app.route("/read")
def read_file():
    filename = request.args.get("file")
    f = open(filename, "r")  # ../../etc/passwd
    return f.read()


# ----------------------------
# SSRF vulnerability
# ----------------------------
@app.route("/fetch")
def fetch_url():
    url = request.args.get("url")
    r = requests.get(url)  # No validation
    return r.text


# ----------------------------
# Infinite loop / DoS risk
# ----------------------------
def background_worker():
    while True:
        time.sleep(0.1)


# ----------------------------
# Thread without control
# ----------------------------
def start_thread():
    t = threading.Thread(target=background_worker)
    t.daemon = True
    t.start()


# ----------------------------
# Unsafe eval
# ----------------------------
@app.route("/calc")
def calc():
    expr = request.args.get("expr")
    return str(eval(expr))


# ----------------------------
# Hardcoded API key
# ----------------------------
API_KEY = "sk_test_1234567890"


# ----------------------------
# Sensitive info exposure
# ----------------------------
@app.route("/env")
def show_env():
    return str(os.environ)


# ----------------------------
# No input validation
# ----------------------------
@app.route("/upload", methods=["POST"])
def upload():
    data = request.files["file"].read()
    with open("uploaded.bin", "wb") as f:
        f.write(data)
    return "Uploaded"


# ----------------------------
# Unhandled exception
# ----------------------------
@app.route("/crash")
def crash():
    return 1 / 0


# ----------------------------
# Magic numbers everywhere
# ----------------------------
def random_logic(x):
    if x == 42:
        return 999
    elif x > 1000:
        return x * 1337
    else:
        return x / 3.14159


# ----------------------------
# Dead code
# ----------------------------
def unused_function():
    print("This function is never used")
    if random.random() > 0.5:
        sys.exit(0)


# ----------------------------
# Startup
# ----------------------------
if __name__ == "__main__":
    start_thread()
    app.run(host="0.0.0.0", port=5000, debug=True)
