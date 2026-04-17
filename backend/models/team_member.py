"""
TeamMember Model

Stores team members extracted from git commit history.
Uses same SQLite/PostgreSQL dual-mode pattern as User model.
"""

import sqlite3
import json
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any
import config
from utils.db_pool import get_pooled_connection, return_connection


def _is_postgres():
    return getattr(config, 'IS_POSTGRES', False)


class TeamMember:
    """Represents a team member extracted from git commit history."""

    def __init__(self, id=None, github_username=None, display_name=None,
                 email=None, avatar_url=None, role=None,
                 commit_count=0, pr_security_rating=None,
                 last_commit_at=None, joined_at=None,
                 pr_summary_json=None, commit_history_json=None,
                 analysis_uid=None):
        self.id = id
        self.github_username = github_username
        self.display_name = display_name or github_username
        self.email = email
        self.avatar_url = avatar_url or f"https://avatars.githubusercontent.com/{github_username}?size=80"
        self.role = role or 'Developer'
        self.commit_count = commit_count
        self.pr_security_rating = pr_security_rating  # 0-10 float
        self.last_commit_at = last_commit_at
        self.joined_at = joined_at or datetime.utcnow()
        # Ties this member to a specific analysis session
        self.analysis_uid = analysis_uid
        }

    # ── DB helpers ───────────────────────────────────────────────────────────

    @staticmethod
    def _get_conn():
        if _is_postgres():
            return get_pooled_connection()
        db_path = Path(config.DATABASE_URL.replace('sqlite:///', ''))
        db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _ph():
        return '%s' if _is_postgres() else '?'

    @staticmethod
    def _cursor(conn):
        if _is_postgres():
            import psycopg2.extras
            return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        return conn.cursor()

    @staticmethod
    def _row_to_member(row) -> Optional['TeamMember']:
        if row is None:
            return None
        if isinstance(row, sqlite3.Row):
            row = dict(row)
        if not isinstance(row, dict):
            return None

        def _get(k, d=None):
            return row.get(k, d)

        last_commit = _get('last_commit_at')
        joined_at = _get('joined_at')
        return TeamMember(
            id=_get('id'),
            github_username=_get('github_username'),
            display_name=_get('display_name'),
            email=_get('email'),
            avatar_url=_get('avatar_url'),
            role=_get('role'),
            commit_count=_get('commit_count', 0),
            pr_security_rating=_get('pr_security_rating'),
            last_commit_at=datetime.fromisoformat(str(last_commit)) if last_commit and isinstance(last_commit, str) else last_commit,
            joined_at=datetime.fromisoformat(str(joined_at)) if joined_at and isinstance(joined_at, str) else joined_at,
            pr_summary_json=_get('pr_summary_json'),
            commit_history_json=_get('commit_history_json'),
            analysis_uid=_get('analysis_uid'),
        conn = TeamMember._get_conn()
        cur = TeamMember._cursor(conn)
        if _is_postgres():
            cur.execute('''
                CREATE TABLE IF NOT EXISTS team_members (
                    id SERIAL PRIMARY KEY,
                    github_username TEXT NOT NULL,
                    display_name TEXT,
                    email TEXT,
                    avatar_url TEXT,
                    role TEXT DEFAULT 'Developer',
                    commit_count INTEGER DEFAULT 0,
                    pr_security_rating REAL,
                    last_commit_at TIMESTAMP,
                    joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    pr_summary_json TEXT,
                    commit_history_json TEXT,
                    analysis_uid TEXT,
                    UNIQUE (github_username, analysis_uid)
                )
            ''')
            cur.execute('CREATE INDEX IF NOT EXISTS idx_tm_username ON team_members(github_username)')
            cur.execute('CREATE INDEX IF NOT EXISTS idx_tm_uid ON team_members(analysis_uid)')
            # Runtime migration: add column if missing
            try:
                cur.execute("ALTER TABLE team_members ADD COLUMN analysis_uid TEXT")
            except Exception:
                pass
        else:
            cur.execute('''
                CREATE TABLE IF NOT EXISTS team_members (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    github_username TEXT NOT NULL,
                    display_name TEXT,
                    email TEXT,
                    avatar_url TEXT,
                    role TEXT DEFAULT 'Developer',
                    commit_count INTEGER DEFAULT 0,
                    pr_security_rating REAL,
                    last_commit_at TIMESTAMP,
                    joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    pr_summary_json TEXT,
                    commit_history_json TEXT,
                    analysis_uid TEXT,
                    UNIQUE (github_username, analysis_uid)
                )
            ''')
            # Runtime migration: add column to existing tables
            try:
                cur.execute("ALTER TABLE team_members ADD COLUMN analysis_uid TEXT")
            except Exception:
                pass  # Column already exists
        conn.commit()
        cur.close()
        conn.close()

    # ── CRUD ─────────────────────────────────────────────────────────────────

    @staticmethod
    def get_all(analysis_uid: Optional[str] = None) -> List['TeamMember']:
        """Return members, optionally filtered by analysis_uid."""
        conn = TeamMember._get_conn()
        cur = TeamMember._cursor(conn)
        ph = TeamMember._ph()
        if analysis_uid:
            cur.execute(
                f'SELECT * FROM team_members WHERE analysis_uid = {ph} ORDER BY commit_count DESC',
                (analysis_uid,)
            )
        else:
            cur.execute('SELECT * FROM team_members ORDER BY commit_count DESC')
        rows = cur.fetchall()
        cur.close()
        conn.close()
        members = []
        for row in rows:
            r = dict(row) if not isinstance(row, dict) else row
            m = TeamMember._row_to_member(r)
            if m:
                members.append(m)
        return members

    @staticmethod
    def get_by_username(username: str) -> Optional['TeamMember']:
        conn = TeamMember._get_conn()
        cur = TeamMember._cursor(conn)
        ph = TeamMember._ph()
        cur.execute(f'SELECT * FROM team_members WHERE github_username = {ph}', (username,))
        row = cur.fetchone()
        cur.close()
        conn.close()
        return TeamMember._row_to_member(dict(row) if row and not isinstance(row, dict) else row)

    @staticmethod
    def get_by_id(member_id: int) -> Optional['TeamMember']:
        conn = TeamMember._get_conn()
        cur = TeamMember._cursor(conn)
        ph = TeamMember._ph()
        cur.execute(f'SELECT * FROM team_members WHERE id = {ph}', (member_id,))
        row = cur.fetchone()
        cur.close()
        conn.close()
        return TeamMember._row_to_member(dict(row) if row and not isinstance(row, dict) else row)

    def save(self) -> 'TeamMember':
        """Insert or update team member."""
        conn = TeamMember._get_conn()
        cur = TeamMember._cursor(conn)
        ph = self._ph()

        pr_json = json.dumps(self.pr_summary) if self._pr_summary_json is None else self._pr_summary_json
        ch_json = json.dumps(self.commit_history) if self._commit_history_json is None else self._commit_history_json

        if self.id:
            if _is_postgres():
                cur.execute(f'''
                    UPDATE team_members
                    SET display_name={ph}, email={ph}, avatar_url={ph}, role={ph},
                        commit_count={ph}, pr_security_rating={ph}, last_commit_at={ph},
                        pr_summary_json={ph}, commit_history_json={ph}
                    WHERE id={ph}
                ''', (self.display_name, self.email, self.avatar_url, self.role,
                      self.commit_count, self.pr_security_rating, self.last_commit_at,
                      pr_json, ch_json, self.id))
            else:
                cur.execute('''
                    UPDATE team_members
                    SET display_name=?, email=?, avatar_url=?, role=?,
                        commit_count=?, pr_security_rating=?, last_commit_at=?,
                        pr_summary_json=?, commit_history_json=?
                    WHERE id=?
                ''', (self.display_name, self.email, self.avatar_url, self.role,
                      self.commit_count, self.pr_security_rating, self.last_commit_at,
                      pr_json, ch_json, self.id))
        else:
            if _is_postgres():
                cur.execute(f'''
                    INSERT INTO team_members
                        (github_username, display_name, email, avatar_url, role,
                         commit_count, pr_security_rating, last_commit_at, joined_at,
                         pr_summary_json, commit_history_json, analysis_uid)
                    VALUES ({ph},{ph},{ph},{ph},{ph},{ph},{ph},{ph},{ph},{ph},{ph},{ph})
                    ON CONFLICT (github_username, analysis_uid) DO UPDATE SET
                        display_name=EXCLUDED.display_name,
                        commit_count=EXCLUDED.commit_count,
                        pr_security_rating=EXCLUDED.pr_security_rating,
                        last_commit_at=EXCLUDED.last_commit_at,
                        pr_summary_json=EXCLUDED.pr_summary_json,
                        commit_history_json=EXCLUDED.commit_history_json
                    RETURNING id
                ''', (self.github_username, self.display_name, self.email,
                      self.avatar_url, self.role, self.commit_count,
                      self.pr_security_rating, self.last_commit_at, self.joined_at,
                      pr_json, ch_json, self.analysis_uid))
                row = cur.fetchone()
                self.id = (row['id'] if isinstance(row, dict) else row[0]) if row else self.id
            else:
                cur.execute('''
                    INSERT OR REPLACE INTO team_members
                        (github_username, display_name, email, avatar_url, role,
                         commit_count, pr_security_rating, last_commit_at, joined_at,
                         pr_summary_json, commit_history_json, analysis_uid)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                ''', (self.github_username, self.display_name, self.email,
                      self.avatar_url, self.role, self.commit_count,
                      self.pr_security_rating, self.last_commit_at, self.joined_at,
                      pr_json, ch_json, self.analysis_uid))
                self.id = cur.lastrowid

        conn.commit()
        cur.close()
        conn.close()
        return self

    @staticmethod
    def delete(member_id: int) -> bool:
        conn = TeamMember._get_conn()
        cur = TeamMember._cursor(conn)
        ph = TeamMember._ph()
        cur.execute(f'DELETE FROM team_members WHERE id = {ph}', (member_id,))
        affected = cur.rowcount
        conn.commit()
        cur.close()
        conn.close()
        return affected > 0
