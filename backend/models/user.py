"""
User Model for Authentication

Handles user authentication with email/password and GitHub OAuth
"""
import sqlite3
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from pathlib import Path
import config


class User:
    """User model for authentication"""
    
    def __init__(self, id=None, email=None, password_hash=None, 
                 github_id=None, github_username=None, 
                 created_at=None, last_login=None):
        self.id = id
        self.email = email
        self.password_hash = password_hash
        self.github_id = github_id
        self.github_username = github_username
        self.created_at = created_at or datetime.utcnow()
        self.last_login = last_login
    
    def set_password(self, password):
        """Hash and set password"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Verify password against hash"""
        return check_password_hash(self.password_hash, password)
    
    def get_id(self):
        """Required by Flask-Login"""
        return str(self.id)
    
    @property
    def is_authenticated(self):
        """Required by Flask-Login"""
        return True
    
    @property
    def is_active(self):
        """Required by Flask-Login"""
        return True
    
    @property
    def is_anonymous(self):
        """Required by Flask-Login"""
        return False
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'email': self.email,
            'github_id': self.github_id,
            'github_username': self.github_username,
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
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
        ''')
        
        # Create indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_email ON users(email)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_github_id ON users(github_id)')
        
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
        
        if row:
            return User(
                id=row['id'],
                email=row['email'],
                password_hash=row['password_hash'],
                github_id=row['github_id'],
                github_username=row['github_username'],
                created_at=datetime.fromisoformat(row['created_at']) if row['created_at'] else None,
                last_login=datetime.fromisoformat(row['last_login']) if row['last_login'] else None
            )
        return None
    
    @staticmethod
    def get_by_email(email):
        """Get user by email"""
        conn = User.get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return User(
                id=row['id'],
                email=row['email'],
                password_hash=row['password_hash'],
                github_id=row['github_id'],
                github_username=row['github_username'],
                created_at=datetime.fromisoformat(row['created_at']) if row['created_at'] else None,
                last_login=datetime.fromisoformat(row['last_login']) if row['last_login'] else None
            )
        return None
    
    @staticmethod
    def get_by_github_id(github_id):
        """Get user by GitHub ID"""
        conn = User.get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE github_id = ?', (str(github_id),))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return User(
                id=row['id'],
                email=row['email'],
                password_hash=row['password_hash'],
                github_id=row['github_id'],
                github_username=row['github_username'],
                created_at=datetime.fromisoformat(row['created_at']) if row['created_at'] else None,
                last_login=datetime.fromisoformat(row['last_login']) if row['last_login'] else None
            )
        return None
    
    def save(self):
        """Save user to database"""
        conn = User.get_db_connection()
        cursor = conn.cursor()
        
        if self.id:
            # Update existing user
            cursor.execute('''
                UPDATE users 
                SET email = ?, password_hash = ?, github_id = ?, 
                    github_username = ?, last_login = ?
                WHERE id = ?
            ''', (self.email, self.password_hash, self.github_id, 
                  self.github_username, self.last_login, self.id))
        else:
            # Create new user
            cursor.execute('''
                INSERT INTO users (email, password_hash, github_id, github_username, created_at)
                VALUES (?, ?, ?, ?, ?)
            ''', (self.email, self.password_hash, self.github_id, 
                  self.github_username, self.created_at))
            self.id = cursor.lastrowid
        
        conn.commit()
        conn.close()
        return self
    
    def update_last_login(self):
        """Update last login timestamp"""
        self.last_login = datetime.utcnow()
        self.save()
