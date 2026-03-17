"""
Repository Model - Stores GitHub repo metadata and analysis history
"""

import sqlite3
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
import config
from utils.db_pool import get_pooled_connection, return_connection
import logging

logger = logging.getLogger(__name__)


def _is_postgres():
    return getattr(config, 'IS_POSTGRES', False)


class Repository:
    """Repository model for tracking analyzed repositories"""
    
    def __init__(self, id=None, user_id=None, repo_url=None, owner=None, repo_name=None,
                 repo_full_name=None, description=None, language=None, stars=0,
                 analysis_id=None, github_data=None, commit_status=None, last_commit_sha=None,
                 last_commit_date=None, created_at=None, updated_at=None):
        self.id = id
        self.user_id = user_id
        self.repo_url = repo_url
        self.owner = owner
        self.repo_name = repo_name
        self.repo_full_name = repo_full_name
        self.description = description
        self.language = language
        self.stars = stars
        self.analysis_id = analysis_id  # UID from analysis
        self.github_data = github_data or {}  # Raw GitHub API data
        self.commit_status = commit_status or {}  # Latest commit status
        self.last_commit_sha = last_commit_sha
        self.last_commit_date = last_commit_date
        self.created_at = created_at or datetime.utcnow()
        self.updated_at = updated_at or datetime.utcnow()
    
    @staticmethod
    def create_table():
        """Create repositories table if it doesn't exist"""
        try:
            if _is_postgres():
                from models.user import get_pooled_connection, return_connection
                conn = get_pooled_connection()
                cursor = conn.cursor()
                
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS repositories (
                        id SERIAL PRIMARY KEY,
                        user_id INTEGER NOT NULL,
                        repo_url TEXT UNIQUE NOT NULL,
                        owner TEXT NOT NULL,
                        repo_name TEXT NOT NULL,
                        repo_full_name TEXT,
                        description TEXT,
                        language TEXT,
                        stars INTEGER DEFAULT 0,
                        analysis_id TEXT,
                        github_data JSONB DEFAULT '{}',
                        commit_status JSONB DEFAULT '{}',
                        last_commit_sha TEXT,
                        last_commit_date TIMESTAMP,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                conn.commit()
                return_connection(conn)
            else:
                # SQLite path
                db_path = Path(config.DATABASE_PATH if hasattr(config, 'DATABASE_PATH') 
                              else 'instance/app.db')
                db_path.parent.mkdir(parents=True, exist_ok=True)
                conn = sqlite3.connect(str(db_path))
                cursor = conn.cursor()
                
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS repositories (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        repo_url TEXT UNIQUE NOT NULL,
                        owner TEXT NOT NULL,
                        repo_name TEXT NOT NULL,
                        repo_full_name TEXT,
                        description TEXT,
                        language TEXT,
                        stars INTEGER DEFAULT 0,
                        analysis_id TEXT,
                        github_data TEXT DEFAULT '{}',
                        commit_status TEXT DEFAULT '{}',
                        last_commit_sha TEXT,
                        last_commit_date TIMESTAMP,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                conn.commit()
                conn.close()
            
            logger.info("Repositories table ready")
        except Exception as e:
            logger.error(f"Error creating repositories table: {e}")
    
    def save(self) -> bool:
        """Save repository to database"""
        try:
            if _is_postgres():
                conn = get_pooled_connection()
                cursor = conn.cursor()
                
                if self.id:
                    # Update
                    cursor.execute('''
                        UPDATE repositories
                        SET user_id=%s, repo_url=%s, owner=%s, repo_name=%s,
                            repo_full_name=%s, description=%s, language=%s, stars=%s,
                            analysis_id=%s, github_data=%s, commit_status=%s,
                            last_commit_sha=%s, last_commit_date=%s, updated_at=CURRENT_TIMESTAMP
                        WHERE id=%s
                    ''', (
                        self.user_id, self.repo_url, self.owner, self.repo_name,
                        self.repo_full_name, self.description, self.language, self.stars,
                        self.analysis_id, json.dumps(self.github_data),
                        json.dumps(self.commit_status), self.last_commit_sha,
                        self.last_commit_date, self.id
                    ))
                else:
                    # Insert
                    cursor.execute('''
                        INSERT INTO repositories
                        (user_id, repo_url, owner, repo_name, repo_full_name, description,
                         language, stars, analysis_id, github_data, commit_status,
                         last_commit_sha, last_commit_date)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ''', (
                        self.user_id, self.repo_url, self.owner, self.repo_name,
                        self.repo_full_name, self.description, self.language, self.stars,
                        self.analysis_id, json.dumps(self.github_data),
                        json.dumps(self.commit_status), self.last_commit_sha,
                        self.last_commit_date
                    ))
                    self.id = cursor.lastrowid
                
                conn.commit()
                return_connection(conn)
            else:
                # SQLite
                db_path = Path(config.DATABASE_PATH if hasattr(config, 'DATABASE_PATH')
                              else 'instance/app.db')
                conn = sqlite3.connect(str(db_path))
                cursor = conn.cursor()
                
                if self.id:
                    cursor.execute('''
                        UPDATE repositories
                        SET user_id=?, repo_url=?, owner=?, repo_name=?,
                            repo_full_name=?, description=?, language=?, stars=?,
                            analysis_id=?, github_data=?, commit_status=?,
                            last_commit_sha=?, last_commit_date=?, updated_at=CURRENT_TIMESTAMP
                        WHERE id=?
                    ''', (
                        self.user_id, self.repo_url, self.owner, self.repo_name,
                        self.repo_full_name, self.description, self.language, self.stars,
                        self.analysis_id, json.dumps(self.github_data),
                        json.dumps(self.commit_status), self.last_commit_sha,
                        self.last_commit_date, self.id
                    ))
                else:
                    cursor.execute('''
                        INSERT INTO repositories
                        (user_id, repo_url, owner, repo_name, repo_full_name, description,
                         language, stars, analysis_id, github_data, commit_status,
                         last_commit_sha, last_commit_date)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        self.user_id, self.repo_url, self.owner, self.repo_name,
                        self.repo_full_name, self.description, self.language, self.stars,
                        self.analysis_id, json.dumps(self.github_data),
                        json.dumps(self.commit_status), self.last_commit_sha,
                        self.last_commit_date
                    ))
                    self.id = cursor.lastrowid
                
                conn.commit()
                conn.close()
            
            return True
        except Exception as e:
            logger.error(f"Error saving repository: {e}")
            return False
    
    @staticmethod
    def get_by_url(repo_url: str) -> Optional['Repository']:
        """Get repository by URL"""
        try:
            if _is_postgres():
                conn = get_pooled_connection()
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM repositories WHERE repo_url=%s', (repo_url,))
                row = cursor.fetchone()
                return_connection(conn)
            else:
                db_path = Path(config.DATABASE_PATH if hasattr(config, 'DATABASE_PATH')
                              else 'instance/app.db')
                conn = sqlite3.connect(str(db_path))
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM repositories WHERE repo_url=?', (repo_url,))
                row = cursor.fetchone()
                conn.close()
            
            if row:
                repo_data = dict(row)
                repo_data['github_data'] = json.loads(repo_data['github_data']) if isinstance(repo_data['github_data'], str) else repo_data['github_data']
                repo_data['commit_status'] = json.loads(repo_data['commit_status']) if isinstance(repo_data['commit_status'], str) else repo_data['commit_status']
                return Repository(**repo_data)
            return None
        except Exception as e:
            logger.error(f"Error getting repository: {e}")
            return None
    
    @staticmethod
    def get_by_id(repo_id: int) -> Optional['Repository']:
        """Get repository by ID"""
        try:
            if _is_postgres():
                conn = get_pooled_connection()
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM repositories WHERE id=%s', (repo_id,))
                row = cursor.fetchone()
                return_connection(conn)
            else:
                db_path = Path(config.DATABASE_PATH if hasattr(config, 'DATABASE_PATH')
                              else 'instance/app.db')
                conn = sqlite3.connect(str(db_path))
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM repositories WHERE id=?', (repo_id,))
                row = cursor.fetchone()
                conn.close()
            
            if row:
                repo_data = dict(row)
                repo_data['github_data'] = json.loads(repo_data['github_data']) if isinstance(repo_data['github_data'], str) else repo_data['github_data']
                repo_data['commit_status'] = json.loads(repo_data['commit_status']) if isinstance(repo_data['commit_status'], str) else repo_data['commit_status']
                return Repository(**repo_data)
            return None
        except Exception as e:
            logger.error(f"Error getting repository: {e}")
            return None
    
    @staticmethod
    def get_by_user(user_id: int, limit: int = 50) -> List['Repository']:
        """Get all repositories for a user"""
        try:
            repositories = []
            
            if _is_postgres():
                conn = get_pooled_connection()
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT * FROM repositories 
                    WHERE user_id=%s 
                    ORDER BY updated_at DESC 
                    LIMIT %s
                ''', (user_id, limit))
                rows = cursor.fetchall()
                return_connection(conn)
            else:
                db_path = Path(config.DATABASE_PATH if hasattr(config, 'DATABASE_PATH')
                              else 'instance/app.db')
                conn = sqlite3.connect(str(db_path))
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT * FROM repositories 
                    WHERE user_id=?
                    ORDER BY updated_at DESC 
                    LIMIT ?
                ''', (user_id, limit))
                rows = cursor.fetchall()
                conn.close()
            
            for row in rows:
                repo_data = dict(row)
                repo_data['github_data'] = json.loads(repo_data['github_data']) if isinstance(repo_data['github_data'], str) else repo_data['github_data']
                repo_data['commit_status'] = json.loads(repo_data['commit_status']) if isinstance(repo_data['commit_status'], str) else repo_data['commit_status']
                repositories.append(Repository(**repo_data))
            
            return repositories
        except Exception as e:
            logger.error(f"Error getting user repositories: {e}")
            return []
    
    def delete(self) -> bool:
        """Delete repository from database"""
        try:
            if not self.id:
                return False
            
            if _is_postgres():
                conn = get_pooled_connection()
                cursor = conn.cursor()
                cursor.execute('DELETE FROM repositories WHERE id=%s', (self.id,))
                conn.commit()
                return_connection(conn)
            else:
                db_path = Path(config.DATABASE_PATH if hasattr(config, 'DATABASE_PATH')
                              else 'instance/app.db')
                conn = sqlite3.connect(str(db_path))
                cursor = conn.cursor()
                cursor.execute('DELETE FROM repositories WHERE id=?', (self.id,))
                conn.commit()
                conn.close()
            
            return True
        except Exception as e:
            logger.error(f"Error deleting repository: {e}")
            return False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert repository to dictionary"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'repo_url': self.repo_url,
            'owner': self.owner,
            'repo_name': self.repo_name,
            'repo_full_name': self.repo_full_name,
            'description': self.description,
            'language': self.language,
            'stars': self.stars,
            'analysis_id': self.analysis_id,
            'github_data': self.github_data,
            'commit_status': self.commit_status,
            'last_commit_sha': self.last_commit_sha,
            'last_commit_date': self.last_commit_date,
            'created_at': self.created_at.isoformat() if isinstance(self.created_at, datetime) else self.created_at,
            'updated_at': self.updated_at.isoformat() if isinstance(self.updated_at, datetime) else self.updated_at,
        }
