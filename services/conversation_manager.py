"""
Conversation Manager

Manages chat sessions and conversation history with persistent storage.
"""

import sqlite3
import json
import uuid
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from pathlib import Path
import config

logger = logging.getLogger(__name__)


class ConversationManager:
    """Manage chat sessions and conversation history"""

    def __init__(self, db_path: Optional[str] = None):
        """
        Initialize conversation manager

        Args:
            db_path: Path to SQLite database (default: vector_db/conversations.db)
        """
        if db_path is None:
            db_path = config.VECTOR_DB_DIR / 'conversations.db'

        self.db_path = str(db_path)
        self._initialize_database()
        logger.info(f"Initialized ConversationManager with database: {
                    self.db_path}")

    def _initialize_database(self):
        """Create database schema if it doesn't exist"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Sessions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_active TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                metadata TEXT
            )
        ''')

        # Messages table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                message_id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                role TEXT NOT NULL,
                content TEXT NOT NULL,
                code_context TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                tokens_used INTEGER DEFAULT 0,
                metadata TEXT,
                FOREIGN KEY (session_id) REFERENCES sessions(session_id)
            )
        ''')

        # Create indexes for faster queries
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_session_user 
            ON sessions(user_id)
        ''')

        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_message_session 
            ON messages(session_id, timestamp)
        ''')

        conn.commit()
        conn.close()
        logger.info("Database schema initialized")

    def create_session(self, user_id: str, metadata: Optional[Dict[str, Any]] = None) -> str:
        """
        Create a new chat session

        Args:
            user_id: User identifier
            metadata: Optional session metadata

        Returns:
            session_id: Unique session identifier
        """
        session_id = str(uuid.uuid4())

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            INSERT INTO sessions (session_id, user_id, metadata)
            VALUES (?, ?, ?)
        ''', (session_id, user_id, json.dumps(metadata) if metadata else None))

        conn.commit()
        conn.close()

        logger.info(f"Created session {session_id} for user {user_id}")
        return session_id

    def add_message(
        self,
        session_id: str,
        role: str,
        content: str,
        code_context: Optional[str] = None,
        tokens_used: int = 0,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Add a message to a session

        Args:
            session_id: Session identifier
            role: 'user' or 'assistant'
            content: Message content
            code_context: Optional code snippet for context
            tokens_used: Number of tokens used by this message
            metadata: Optional message metadata

        Returns:
            message_id: Unique message identifier
        """
        message_id = str(uuid.uuid4())

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            INSERT INTO messages 
            (message_id, session_id, role, content, code_context, tokens_used, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            message_id,
            session_id,
            role,
            content,
            code_context,
            tokens_used,
            json.dumps(metadata) if metadata else None
        ))

        # Update session last_active timestamp
        cursor.execute('''
            UPDATE sessions 
            SET last_active = CURRENT_TIMESTAMP 
            WHERE session_id = ?
        ''', (session_id,))

        conn.commit()
        conn.close()

        logger.debug(f"Added {role} message to session {session_id}")
        return message_id

    def get_conversation_history(
        self,
        session_id: str,
        limit: Optional[int] = None,
        include_code_context: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Get conversation history for a session

        Args:
            session_id: Session identifier
            limit: Maximum number of messages to return (most recent first)
            include_code_context: Whether to include code context in results

        Returns:
            List of messages in chronological order
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        query = '''
            SELECT message_id, role, content, code_context, timestamp, tokens_used, metadata
            FROM messages
            WHERE session_id = ?
            ORDER BY timestamp DESC
        '''

        if limit:
            query += f' LIMIT {limit}'

        cursor.execute(query, (session_id,))
        rows = cursor.fetchall()
        conn.close()

        # Reverse to get chronological order
        messages = []
        for row in reversed(rows):
            message = {
                'message_id': row['message_id'],
                'role': row['role'],
                'content': row['content'],
                'timestamp': row['timestamp'],
                'tokens_used': row['tokens_used']
            }

            if include_code_context and row['code_context']:
                message['code_context'] = row['code_context']

            if row['metadata']:
                message['metadata'] = json.loads(row['metadata'])

            messages.append(message)

        return messages

    def get_session_info(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        Get session information

        Args:
            session_id: Session identifier

        Returns:
            Session info or None if not found
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute('''
            SELECT session_id, user_id, created_at, last_active, metadata
            FROM sessions
            WHERE session_id = ?
        ''', (session_id,))

        row = cursor.fetchone()
        conn.close()

        if not row:
            return None

        info = {
            'session_id': row['session_id'],
            'user_id': row['user_id'],
            'created_at': row['created_at'],
            'last_active': row['last_active']
        }

        if row['metadata']:
            info['metadata'] = json.loads(row['metadata'])

        return info

    def get_user_sessions(self, user_id: str, active_only: bool = False) -> List[Dict[str, Any]]:
        """
        Get all sessions for a user

        Args:
            user_id: User identifier
            active_only: Only return sessions active in last 24 hours

        Returns:
            List of session info
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        query = '''
            SELECT session_id, user_id, created_at, last_active, metadata
            FROM sessions
            WHERE user_id = ?
        '''

        if active_only:
            cutoff = datetime.now() - timedelta(hours=24)
            query += f" AND last_active > '{cutoff.isoformat()}'"

        query += ' ORDER BY last_active DESC'

        cursor.execute(query, (user_id,))
        rows = cursor.fetchall()
        conn.close()

        sessions = []
        for row in rows:
            session = {
                'session_id': row['session_id'],
                'user_id': row['user_id'],
                'created_at': row['created_at'],
                'last_active': row['last_active']
            }

            if row['metadata']:
                session['metadata'] = json.loads(row['metadata'])

            sessions.append(session)

        return sessions

    def delete_session(self, session_id: str) -> bool:
        """
        Delete a session and all its messages

        Args:
            session_id: Session identifier

        Returns:
            True if deleted, False if session not found
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Delete messages first (foreign key constraint)
        cursor.execute(
            'DELETE FROM messages WHERE session_id = ?', (session_id,))

        # Delete session
        cursor.execute(
            'DELETE FROM sessions WHERE session_id = ?', (session_id,))

        deleted = cursor.rowcount > 0
        conn.commit()
        conn.close()

        if deleted:
            logger.info(f"Deleted session {session_id}")

        return deleted

    def get_total_tokens(self, session_id: str) -> int:
        """
        Get total tokens used in a session

        Args:
            session_id: Session identifier

        Returns:
            Total tokens used
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            SELECT COALESCE(SUM(tokens_used), 0) as total
            FROM messages
            WHERE session_id = ?
        ''', (session_id,))

        total = cursor.fetchone()[0]
        conn.close()

        return total

    def cleanup_old_sessions(self, days: int = 30) -> int:
        """
        Delete sessions older than specified days

        Args:
            days: Number of days to keep

        Returns:
            Number of sessions deleted
        """
        cutoff = datetime.now() - timedelta(days=days)

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Get sessions to delete
        cursor.execute('''
            SELECT session_id FROM sessions
            WHERE last_active < ?
        ''', (cutoff.isoformat(),))

        session_ids = [row[0] for row in cursor.fetchall()]

        # Delete messages and sessions
        for session_id in session_ids:
            cursor.execute(
                'DELETE FROM messages WHERE session_id = ?', (session_id,))
            cursor.execute(
                'DELETE FROM sessions WHERE session_id = ?', (session_id,))

        conn.commit()
        conn.close()

        logger.info(f"Cleaned up {len(session_ids)} old sessions")
        return len(session_ids)
