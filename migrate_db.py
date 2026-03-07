"""One-time migration: adds github_access_token column to users table."""
import sqlite3
import os

db = os.path.join(os.path.dirname(__file__), 'backend', 'instance', 'users.db')
if not os.path.exists(db):
    print(f"DB not found at: {db}")
else:
    conn = sqlite3.connect(db)
    existing = {row[1] for row in conn.execute("PRAGMA table_info(users)")}
    print("Existing columns:", sorted(existing))
    if 'github_access_token' not in existing:
        conn.execute("ALTER TABLE users ADD COLUMN github_access_token TEXT")
        conn.commit()
        print("✓ Column 'github_access_token' added successfully")
    else:
        print("✓ Column already exists — nothing to do")
    conn.close()
