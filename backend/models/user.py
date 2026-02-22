"""
User Model for Authentication

Supports both PostgreSQL (production) and SQLite (local dev fallback).
Connection is determined by the DATABASE_URL env var in config.
"""
import sqlite3
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from pathlib import Path
import config


def _is_postgres():
    return getattr(config, 'IS_POSTGRES', False)


class User:
    """User model for authentication"""

    is_authenticated = True

    def __init__(self, id=None, email=None, password_hash=None,
                 github_id=None, github_username=None,
                 linkedin_id=None, linkedin_username=None,
                 created_at=None, last_login=None):
        self.id = id
        self.email = email
        self.password_hash = password_hash
        self.github_id = github_id
        self.github_username = github_username
        self.linkedin_id = linkedin_id
        self.linkedin_username = linkedin_username
        self.created_at = created_at or datetime.utcnow()
        self.last_login = last_login

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'github_id': self.github_id,
            'github_username': self.github_username,
            'linkedin_id': self.linkedin_id,
            'linkedin_username': self.linkedin_username,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None,
        }

    # ─── Connection helpers ────────────────────────────────────────────────────

    @staticmethod
    def get_db_connection():
        """Return a DB connection — psycopg2 for Postgres, sqlite3 for local."""
        if _is_postgres():
            import psycopg2
            import psycopg2.extras
            conn = psycopg2.connect(config.DATABASE_URL)
            conn.autocommit = False
            return conn
        else:
            # SQLite local fallback
            db_path = Path(config.DATABASE_URL.replace('sqlite:///', ''))
            db_path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(str(db_path))
            conn.row_factory = sqlite3.Row
            return conn

    @staticmethod
    def _placeholder():
        """SQL placeholder: %s for Postgres, ? for SQLite."""
        return '%s' if _is_postgres() else '?'

    @staticmethod
    def _cursor(conn):
        """Return a dict-like cursor."""
        if _is_postgres():
            import psycopg2.extras
            return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        return conn.cursor()

    @staticmethod
    def _fetchone(cursor):
        """Fetch one row as a dict regardless of driver."""
        row = cursor.fetchone()
        if row is None:
            return None
        if _is_postgres():
            return dict(row)
        # sqlite3.Row supports dict-style access but convert for safety
        return dict(zip([d[0] for d in cursor.description], row)) if not isinstance(row, sqlite3.Row) else row

    # ─── DB init ───────────────────────────────────────────────────────────────

    @staticmethod
    def init_db():
        """Initialize database tables (runs on app startup)."""
        conn = User.get_db_connection()
        cur = User._cursor(conn)

        if _is_postgres():
            cur.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    email TEXT UNIQUE,
                    password_hash TEXT,
                    github_id TEXT UNIQUE,
                    github_username TEXT,
                    linkedin_id TEXT UNIQUE,
                    linkedin_username TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP
                )
            ''')
            # Add columns if they don't exist (safe migration)
            for col, coltype in [('linkedin_id', 'TEXT'), ('linkedin_username', 'TEXT')]:
                cur.execute('''
                    SELECT column_name FROM information_schema.columns
                    WHERE table_name='users' AND column_name=%s
                ''', (col,))
                if not cur.fetchone():
                    cur.execute(f'ALTER TABLE users ADD COLUMN {col} TEXT')

            cur.execute('CREATE INDEX IF NOT EXISTS idx_email ON users(email)')
            cur.execute('CREATE INDEX IF NOT EXISTS idx_github_id ON users(github_id)')
            cur.execute('CREATE INDEX IF NOT EXISTS idx_linkedin_id ON users(linkedin_id)')
        else:
            # SQLite
            cur.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE,
                    password_hash TEXT,
                    github_id TEXT UNIQUE,
                    github_username TEXT,
                    linkedin_id TEXT UNIQUE,
                    linkedin_username TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP
                )
            ''')
            existing = {row[1] for row in conn.execute("PRAGMA table_info(users)")}
            for col in ['linkedin_id', 'linkedin_username']:
                if col not in existing:
                    conn.execute(f'ALTER TABLE users ADD COLUMN {col} TEXT')
            cur.execute('CREATE INDEX IF NOT EXISTS idx_email ON users(email)')
            cur.execute('CREATE INDEX IF NOT EXISTS idx_github_id ON users(github_id)')
            cur.execute('CREATE INDEX IF NOT EXISTS idx_linkedin_id ON users(linkedin_id)')

        conn.commit()
        cur.close()
        conn.close()

    # ─── Queries ───────────────────────────────────────────────────────────────

    @staticmethod
    def _row_to_user(row):
        if row is None:
            return None
        if isinstance(row, sqlite3.Row):
            row = dict(row)

        def _get(key, default=None):
            return row.get(key, default)

        created = _get('created_at')
        last_login = _get('last_login')
        return User(
            id=_get('id'),
            email=_get('email'),
            password_hash=_get('password_hash'),
            github_id=_get('github_id'),
            github_username=_get('github_username'),
            linkedin_id=_get('linkedin_id'),
            linkedin_username=_get('linkedin_username'),
            created_at=datetime.fromisoformat(str(created)) if isinstance(created, str) and created else created,
            last_login=datetime.fromisoformat(str(last_login)) if isinstance(last_login, str) and last_login else last_login,
        )

    @staticmethod
    def _query_one(sql_pg, sql_sq, params=()):
        """Run a SELECT and return one User or None."""
        conn = User.get_db_connection()
        cur = User._cursor(conn)
        p = User._placeholder()
        sql = sql_pg if _is_postgres() else sql_sq
        cur.execute(sql, params)
        row = User._fetchone(cur)
        cur.close()
        conn.close()
        return User._row_to_user(row)

    @staticmethod
    def get_by_id(user_id):
        return User._query_one(
            'SELECT * FROM users WHERE id = %s',
            'SELECT * FROM users WHERE id = ?',
            (user_id,)
        )

    @staticmethod
    def get_by_email(email):
        return User._query_one(
            'SELECT * FROM users WHERE email = %s',
            'SELECT * FROM users WHERE email = ?',
            (email,)
        )

    @staticmethod
    def get_by_github_id(github_id):
        return User._query_one(
            'SELECT * FROM users WHERE github_id = %s',
            'SELECT * FROM users WHERE github_id = ?',
            (str(github_id),)
        )

    @staticmethod
    def get_by_linkedin_id(linkedin_id):
        return User._query_one(
            'SELECT * FROM users WHERE linkedin_id = %s',
            'SELECT * FROM users WHERE linkedin_id = ?',
            (str(linkedin_id),)
        )

    # ─── Save ──────────────────────────────────────────────────────────────────

    def save(self):
        """Insert or update user in the database."""
        conn = User.get_db_connection()
        cur = User._cursor(conn)

        if self.id:
            if _is_postgres():
                cur.execute('''
                    UPDATE users
                    SET email=%s, password_hash=%s, github_id=%s, github_username=%s,
                        linkedin_id=%s, linkedin_username=%s, last_login=%s
                    WHERE id=%s
                ''', (self.email, self.password_hash, self.github_id, self.github_username,
                      self.linkedin_id, self.linkedin_username, self.last_login, self.id))
            else:
                cur.execute('''
                    UPDATE users
                    SET email=?, password_hash=?, github_id=?, github_username=?,
                        linkedin_id=?, linkedin_username=?, last_login=?
                    WHERE id=?
                ''', (self.email, self.password_hash, self.github_id, self.github_username,
                      self.linkedin_id, self.linkedin_username, self.last_login, self.id))
        else:
            if _is_postgres():
                cur.execute('''
                    INSERT INTO users (email, password_hash, github_id, github_username,
                                       linkedin_id, linkedin_username, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    RETURNING id
                ''', (self.email, self.password_hash, self.github_id, self.github_username,
                      self.linkedin_id, self.linkedin_username, self.created_at))
                row = cur.fetchone()
                self.id = row['id'] if isinstance(row, dict) else row[0]
            else:
                cur.execute('''
                    INSERT INTO users (email, password_hash, github_id, github_username,
                                       linkedin_id, linkedin_username, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (self.email, self.password_hash, self.github_id, self.github_username,
                      self.linkedin_id, self.linkedin_username, self.created_at))
                self.id = cur.lastrowid

        conn.commit()
        cur.close()
        conn.close()
        return self

    def update_last_login(self):
        self.last_login = datetime.utcnow()
        self.save()
