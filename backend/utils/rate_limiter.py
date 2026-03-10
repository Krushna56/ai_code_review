"""
Rate limiting utilities for API endpoints.

Provides in-memory and Redis-based rate limiting with configurable limits
per endpoint and IP address or user ID.
"""

import logging
import time
from functools import wraps
from typing import Dict, Callable, Optional, Tuple
from collections import defaultdict
from threading import Lock
from datetime import datetime, timedelta
from flask import request, jsonify

logger = logging.getLogger(__name__)


class RateLimiter:
    """In-memory rate limiter for API endpoints"""

    def __init__(self):
        """Initialize rate limiter with thread-safe tracking"""
        self.requests: Dict[str, list] = defaultdict(list)
        self.lock = Lock()

    def _get_client_id(self) -> str:
        """Get unique client identifier (IP by default, can be user ID)"""
        if hasattr(request, 'user') and request.user:
            return f"user_{request.user.id}"
        return request.remote_addr or "unknown"

    def is_allowed(self, client_id: str, limit: int, window_seconds: int) -> Tuple[bool, int, int]:
        """
        Check if request is allowed under rate limit.

        Args:
            client_id: Unique identifier for the client
            limit: Maximum requests allowed
            window_seconds: Time window in seconds

        Returns:
            Tuple of (allowed: bool, current_count: int, reset_seconds: int)
        """
        now = time.time()
        cutoff = now - window_seconds

        with self.lock:
            # Clean old requests
            self.requests[client_id] = [
                req_time for req_time in self.requests[client_id]
                if req_time > cutoff
            ]

            # Check limit
            current_count = len(self.requests[client_id])
            if current_count < limit:
                self.requests[client_id].append(now)
                reset_in = window_seconds - (now - self.requests[client_id][0])
                return True, current_count + 1, int(reset_in) + 1

            # Calculate reset time
            oldest_request = self.requests[client_id][0]
            reset_in = int(window_seconds - (now - oldest_request)) + 1

            return False, current_count, reset_in

    def cleanup_expired(self, max_age_seconds: int = 3600):
        """Remove expired entries to prevent memory bloat"""
        now = time.time()
        cutoff = now - max_age_seconds

        with self.lock:
            # Remove clients with no recent requests
            expired_clients = [
                client_id for client_id, requests in self.requests.items()
                if not requests or all(req_time < cutoff for req_time in requests)
            ]
            for client_id in expired_clients:
                del self.requests[client_id]

            logger.debug(f"Rate limiter cleanup: removed {len(expired_clients)} expired clients")


# Global rate limiter instance
_rate_limiter = RateLimiter()


def rate_limit(
    limit: int = 60,
    window_seconds: int = 60,
    key_func: Optional[Callable] = None
):
    """
    Rate limiting decorator for Flask routes.

    Args:
        limit: Maximum requests allowed
        window_seconds: Time window in seconds
        key_func: Optional function to get custom rate limit key

    Example:
        @app.route('/api/analyze', methods=['POST'])
        @rate_limit(limit=5, window_seconds=60)
        def api_analyze():
            return jsonify({'message': 'Analysis started'})
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Get client identifier
            if key_func:
                client_id = key_func()
            else:
                client_id = request.remote_addr or "unknown"

            # Check rate limit
            allowed, current, reset_in = _rate_limiter.is_allowed(
                client_id, limit, window_seconds
            )

            # Add rate limit headers
            response = func(*args, **kwargs)
            if hasattr(response, 'headers'):
                response.headers['X-RateLimit-Limit'] = str(limit)
                response.headers['X-RateLimit-Remaining'] = str(max(0, limit - current))
                response.headers['X-RateLimit-Reset'] = str(int(time.time()) + reset_in)

            if not allowed:
                # Rate limit exceeded
                logger.warning(f"Rate limit exceeded for {client_id}: {current}/{limit} requests")
                response = jsonify({
                    'error': 'Rate limit exceeded',
                    'limit': limit,
                    'window_seconds': window_seconds,
                    'reset_in_seconds': reset_in
                })
                response.status_code = 429
                response.headers['X-RateLimit-Limit'] = str(limit)
                response.headers['X-RateLimit-Remaining'] = '0'
                response.headers['X-RateLimit-Reset'] = str(int(time.time()) + reset_in)
                response.headers['Retry-After'] = str(reset_in)

            return response

        return wrapper
    return decorator


def cleanup_rate_limiter():
    """Cleanup rate limiter on app shutdown"""
    _rate_limiter.cleanup_expired()
    logger.info("Rate limiter cleaned up")


# Predefined rate limit configurations for common endpoints
RATE_LIMITS = {
    'analysis': {
        'limit': 5,
        'window_seconds': 60,
        'description': 'Max 5 code analyses per minute per IP'
    },
    'chat': {
        'limit': 30,
        'window_seconds': 60,
        'description': 'Max 30 chat messages per minute per IP'
    },
    'query': {
        'limit': 20,
        'window_seconds': 60,
        'description': 'Max 20 queries per minute per IP'
    },
    'auth': {
        'limit': 10,
        'window_seconds': 60,
        'description': 'Max 10 auth attempts per minute per IP'
    },
    'upload': {
        'limit': 10,
        'window_seconds': 300,
        'description': 'Max 10 file uploads per 5 minutes per IP'
    },
    'download': {
        'limit': 100,
        'window_seconds': 3600,
        'description': 'Max 100 downloads per hour per IP'
    },
    'api_general': {
        'limit': 1000,
        'window_seconds': 3600,
        'description': 'Max 1000 API requests per hour per IP'
    }
}
