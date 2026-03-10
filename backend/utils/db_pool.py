"""
Database connection pooling utilities for PostgreSQL.

Provides efficient database connection management with connection pooling
to prevent connection exhaustion and improve concurrency.
"""

import logging
from typing import Optional
import config

logger = logging.getLogger(__name__)

# Connection pool instance (lazy-initialized)
_connection_pool: Optional[object] = None


def get_connection_pool():
    """
    Get or create the PostgreSQL connection pool.
    
    Uses psycopg2-pool (if available) for efficient connection management.
    Falls back to direct connections if pool is not available.
    
    Returns:
        ConnectionPool or None (pool unavailable, use direct connections)
    """
    global _connection_pool
    
    if not config.IS_POSTGRES:
        return None  # Connection pooling not needed for SQLite
    
    if _connection_pool is not None:
        return _connection_pool
    
    try:
        from psycopg2 import pool
        
        pool_config = config.SQLALCHEMY_ENGINE_OPTIONS
        
        # Create connection pool
        _connection_pool = pool.SimpleConnectionPool(
            minconn=pool_config.get('pool_size', 5),
            maxconn=pool_config.get('max_overflow', 10) + pool_config.get('pool_size', 5),
            dsn=config.DATABASE_URL
        )
        
        logger.info(
            f"PostgreSQL connection pool initialized: "
            f"min={pool_config.get('pool_size', 5)}, "
            f"max={pool_config.get('max_overflow', 10) + pool_config.get('pool_size', 5)}"
        )
        return _connection_pool
        
    except ImportError:
        logger.warning(
            "psycopg2-pool not available. Using direct connections without pooling. "
            "Install psycopg2[binary] to enable connection pooling."
        )
        return None
    except Exception as e:
        logger.error(f"Failed to initialize connection pool: {e}")
        return None


def get_pooled_connection():
    """
    Get a connection from the pool or create a direct connection if pool unavailable.
    
    Returns:
        Database connection object
    """
    pool = get_connection_pool()
    
    if pool is not None:
        try:
            conn = pool.getconn()
            conn.autocommit = False
            return conn
        except Exception as e:
            logger.warning(f"Failed to get connection from pool: {e}. Using direct connection.")
    
    # Fallback to direct connection
    import psycopg2
    conn = psycopg2.connect(config.DATABASE_URL)
    conn.autocommit = False
    return conn


def return_connection(conn):
    """
    Return a connection to the pool or close it if pool unavailable.
    
    Args:
        conn: Database connection to return
    """
    if conn is None:
        return
    
    pool = get_connection_pool()
    
    if pool is not None:
        try:
            pool.putconn(conn)
            return
        except Exception as e:
            logger.warning(f"Failed to return connection to pool: {e}")
    
    # Close direct connection
    try:
        conn.close()
    except Exception as e:
        logger.warning(f"Failed to close connection: {e}")


def close_connection_pool():
    """Close all connections in the pool (call on app shutdown)."""
    global _connection_pool
    
    if _connection_pool is not None:
        try:
            _connection_pool.closeall()
            logger.info("Connection pool closed successfully")
            _connection_pool = None
        except Exception as e:
            logger.error(f"Error closing connection pool: {e}")
