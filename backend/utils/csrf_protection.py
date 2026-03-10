"""
CSRF Protection utilities for Flask application.

Provides CSRF token generation, validation, and middleware for protecting
against Cross-Site Request Forgery attacks.
"""

import logging
import secrets
import hmac
import hashlib
from functools import wraps
from typing import Optional
from flask import request, session, g, jsonify
import config

logger = logging.getLogger(__name__)

CSRF_TOKEN_LENGTH = 32
CSRF_TOKEN_HEADER = 'X-CSRF-Token'
CSRF_SESSION_KEY = '_csrf_token'


def generate_csrf_token() -> str:
    """Generate a new CSRF token"""
    return secrets.token_urlsafe(CSRF_TOKEN_LENGTH)


def get_csrf_token() -> str:
    """
    Get or create a CSRF token for the current session.
    
    Returns:
        CSRF token as string
    """
    if CSRF_SESSION_KEY not in session:
        session[CSRF_SESSION_KEY] = generate_csrf_token()
    return session[CSRF_SESSION_KEY]


def validate_csrf_token(token: Optional[str]) -> bool:
    """
    Validate a CSRF token against the session token.
    
    Args:
        token: Token to validate
        
    Returns:
        True if valid, False otherwise
    """
    if not token:
        logger.warning("CSRF validation: No token provided")
        return False
    
    session_token = session.get(CSRF_SESSION_KEY)
    if not session_token:
        logger.warning("CSRF validation: No token in session")
        return False
    
    # Use constant-time comparison to prevent timing attacks
    if not hmac.compare_digest(token, session_token):
        logger.warning("CSRF validation: Token mismatch")
        return False
    
    return True


def get_csrf_token_from_request() -> Optional[str]:
    """
    Extract CSRF token from request.
    
    Checks in order:
    1. X-CSRF-Token header
    2. _csrf_token form field
    3. _csrf_token query parameter
    
    Returns:
        Token if found, None otherwise
    """
    # Check header first (preferred for JSON/AJAX)
    token = request.headers.get(CSRF_TOKEN_HEADER)
    if token:
        return token
    
    # Check form data
    if request.method in ('POST', 'PUT', 'DELETE', 'PATCH'):
        token = request.form.get('_csrf_token')
        if token:
            return token
    
    # Check query parameters
    token = request.args.get('_csrf_token')
    if token:
        return token
    
    return None


def csrf_protect(func):
    """
    Decorator to protect a view function with CSRF validation.
    
    Skips validation for:
    - GET, HEAD, OPTIONS requests
    - Requests with valid API tokens
    
    Example:
        @app.route('/api/submit', methods=['POST', 'PUT'])
        @csrf_protect
        def submit_form():
            return jsonify({'status': 'success'})
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        # Skip CSRF validation for safe methods
        if request.method in ('GET', 'HEAD', 'OPTIONS'):
            return func(*args, **kwargs)
        
        # Skip CSRF validation for API requests with JWT tokens
        if request.headers.get('Authorization', '').startswith('Bearer '):
            return func(*args, **kwargs)
        
        # Validate CSRF token for other methods
        token = get_csrf_token_from_request()
        if not validate_csrf_token(token):
            logger.warning(
                f"CSRF validation failed for {request.method} {request.path} "
                f"from {request.remote_addr}"
            )
            response = jsonify({'error': 'CSRF validation failed'})
            response.status_code = 403
            return response
        
        return func(*args, **kwargs)
    
    return wrapper


class CSRFMiddleware:
    """Middleware to inject CSRF token into template context"""
    
    def __init__(self, app):
        """Initialize middleware"""
        self.app = app
        
        # Register before_request handler
        app.before_request(self._before_request)
        
        # Register context processor for templates
        app.context_processor(self._inject_csrf_token)
        
        logger.info("CSRF middleware initialized")
    
    @staticmethod
    def _before_request():
        """Before request handler to set up CSRF token"""
        # Generate token for session if not present
        token = get_csrf_token()
        g.csrf_token = token
    
    @staticmethod
    def _inject_csrf_token():
        """Inject CSRF token into template context"""
        return dict(csrf_token=g.get('csrf_token', ''))


def enable_csrf_protection(app):
    """
    Enable CSRF protection for the Flask application.
    
    Args:
        app: Flask application instance
    """
    # Initialize middleware
    CSRFMiddleware(app)
    
    # Add CSRF token to all responses as header
    @app.after_request
    def add_csrf_token_header(response):
        """Add CSRF token to response headers"""
        if 'text/html' in response.content_type:
            token = g.get('csrf_token', get_csrf_token())
            response.headers['X-CSRF-Token'] = token
        return response
    
    logger.info("CSRF protection enabled for application")
