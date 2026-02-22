"""
User Model for Authentication

Handles user authentication with email/password, GitHub OAuth, and LinkedIn OAuth.
"""
import sqlite3
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from pathlib import Path
import config


class User:
    """User model for authentication"""

    # Always True for a real User object; _AnonymousUser in app.py has this as False
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
        """Hash and set password"""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Verify password against hash"""
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'email': self.email,
            'github_id': self.github_id,
            'github_username': self.github_username,
            'linkedin_id': self.linkedin_id,
            'linkedin_username': self.linkedin_username,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None
        }

    @staticmethod
    def get_db_connection():
        """Get database connection"""
        db_path = config.DATABASE_URI
        db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row_to_user(row):
        """Construct a User from a DB row, safely handling missing columns."""
        def _get(key, default=None):
            try:
                return row[key]
            except IndexError:
                return default

        return User(
            id=row['id'],
            email=row['email'],
            password_hash=row['password_hash'],
            github_id=row['github_id'],
            github_username=row['github_username'],
            linkedin_id=_get('linkedin_id'),
            linkedin_username=_get('linkedin_username'),
            created_at=datetime.fromisoformat(row['created_at']) if row['created_at'] else None,
            last_login=datetime.fromisoformat(row['last_login']) if row['last_login'] else None,
        )

    @staticmethod
    def init_db():
        """Initialize database tables"""
        conn = User.get_db_connection()
        cursor = conn.cursor()

        cursor.execute('''
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

        # Migrate: add LinkedIn columns if they don't exist yet
        # NOTE: SQLite does not allow ADD COLUMN with UNIQUE; add plain column then create index.
        existing = {row[1] for row in cursor.execute("PRAGMA table_info(users)")}
        for col in ['linkedin_id', 'linkedin_username']:
            if col not in existing:
                cursor.execute(f'ALTER TABLE users ADD COLUMN {col} TEXT')

        # Indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_email ON users(email)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_github_id ON users(github_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_linkedin_id ON users(linkedin_id)')

        conn.commit()
        conn.close()

    @staticmethod
    def get_by_id(user_id):
        """Get user by ID"""
        conn = User.get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
        row = cursor.fetchone()
        conn.close()
        return User._row_to_user(row) if row else None

    @staticmethod
    def get_by_email(email):
        """Get user by email"""
        conn = User.get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        row = cursor.fetchone()
        conn.close()
        return User._row_to_user(row) if row else None

    @staticmethod
    def get_by_github_id(github_id):
        """Get user by GitHub ID"""
        conn = User.get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE github_id = ?', (str(github_id),))
        row = cursor.fetchone()
        conn.close()
        return User._row_to_user(row) if row else None

    @staticmethod
    def get_by_linkedin_id(linkedin_id):
        """Get user by LinkedIn ID"""
        conn = User.get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE linkedin_id = ?', (str(linkedin_id),))
        row = cursor.fetchone()
        conn.close()
        return User._row_to_user(row) if row else None

    def save(self):
        """Save user to database"""
        conn = User.get_db_connection()
        cursor = conn.cursor()

        if self.id:
            cursor.execute('''
                UPDATE users
                SET email = ?, password_hash = ?, github_id = ?, github_username = ?,
                    linkedin_id = ?, linkedin_username = ?, last_login = ?
                WHERE id = ?
            ''', (self.email, self.password_hash, self.github_id, self.github_username,
                  self.linkedin_id, self.linkedin_username, self.last_login, self.id))
        else:
            cursor.execute('''
                INSERT INTO users (email, password_hash, github_id, github_username,
                                   linkedin_id, linkedin_username, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (self.email, self.password_hash, self.github_id, self.github_username,
                  self.linkedin_id, self.linkedin_username, self.created_at))
            self.id = cursor.lastrowid

        conn.commit()
        conn.close()
        return self

    def update_last_login(self):
        """Update last login timestamp"""
        self.last_login = datetime.utcnow()
        self.save()
