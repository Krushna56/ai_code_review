"""
JWT Utilities

Provides token generation, verification, and a jwt_required decorator
to replace Flask-Login for stateless API authentication.
"""
import jwt
import logging
from datetime import datetime, timezone, timedelta
from functools import wraps
from flask import request, jsonify, g
import config

logger = logging.getLogger(__name__)

# --- In-memory refresh token blacklist (invalidated on logout) ---
_blacklisted_tokens: set = set()


class JWTManager:
    """Handles JWT token generation and verification."""

    @staticmethod
    def _utcnow() -> datetime:
        return datetime.now(timezone.utc)

    @staticmethod
    def generate_tokens(user_id: int, email: str) -> dict:
        """
        Generate an access token (short-lived) and a refresh token (long-lived).

        Returns:
            dict with keys: access_token, refresh_token, expires_in (seconds)
        """
        now = JWTManager._utcnow()

        access_payload = {
            "sub": str(user_id),
            "email": email,
            "type": "access",
            "iat": now,
            "exp": now + timedelta(seconds=config.JWT_ACCESS_TOKEN_EXPIRES),
        }

        refresh_payload = {
            "sub": str(user_id),
            "email": email,
            "type": "refresh",
            "iat": now,
            "exp": now + timedelta(seconds=config.JWT_REFRESH_TOKEN_EXPIRES),
        }

        access_token = jwt.encode(
            access_payload, config.JWT_SECRET_KEY, algorithm="HS256"
        )
        refresh_token = jwt.encode(
            refresh_payload, config.JWT_SECRET_KEY, algorithm="HS256"
        )

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "expires_in": config.JWT_ACCESS_TOKEN_EXPIRES,
            "token_type": "Bearer",
        }

    @staticmethod
    def verify_token(token: str) -> dict:
        """
        Decode and validate a JWT token.

        Raises:
            jwt.ExpiredSignatureError  — token has expired
            jwt.InvalidTokenError      — token is invalid / tampered
        """
        return jwt.decode(token, config.JWT_SECRET_KEY, algorithms=["HS256"])

    @staticmethod
    def blacklist_token(token: str) -> None:
        """Add a token to the blacklist (used at logout)."""
        _blacklisted_tokens.add(token)

    @staticmethod
    def is_blacklisted(token: str) -> bool:
        return token in _blacklisted_tokens


def jwt_required(f):
    """
    Route decorator that enforces JWT authentication.

    Reads (in order):
      1. Authorization: Bearer <token>  header
      2. session['jwt_access_token']    (fallback for web-page JS calls)
    Sets:  flask.g.current_user = { 'id': ..., 'email': ... }

    Returns 401 JSON on failure.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        from flask import session as flask_session

        # 1. Try Authorization header first (API / mobile clients)
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1].strip()
        else:
            # 2. Fall back to session cookie (web-app JS calls)
            token = flask_session.get("jwt_access_token", "")

        if not token:
            return jsonify({"error": "Authorization header missing or invalid"}), 401

        if JWTManager.is_blacklisted(token):
            return jsonify({"error": "Token has been revoked"}), 401

        try:
            payload = JWTManager.verify_token(token)
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired"}), 401
        except jwt.InvalidTokenError as exc:
            logger.warning(f"Invalid JWT: {exc}")
            return jsonify({"error": "Invalid token"}), 401

        if payload.get("type") != "access":
            return jsonify({"error": "Refresh tokens cannot be used for API access"}), 401

        g.current_user = {
            "id": int(payload["sub"]),
            "email": payload.get("email"),
        }
        return f(*args, **kwargs)

    return decorated

