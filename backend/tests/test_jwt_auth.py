"""
Tests for JWT Authentication
"""
import pytest
import json
import jwt as _jwt
from datetime import datetime, timezone, timedelta
import os
import sys

# Add backend directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-jwt-tests')
os.environ.setdefault('JWT_SECRET_KEY', 'test-secret-key-for-jwt-tests')
os.environ.setdefault('OPENAI_API_KEY', 'test-key')


@pytest.fixture(scope='session')
def app():
    """Create test Flask app."""
    import config
    config.DATABASE_URI = config.BASE_DIR / 'instance' / 'test_users.db'

    from app import app as flask_app
    flask_app.config['TESTING'] = True
    flask_app.config['SECRET_KEY'] = 'test-secret-key-for-jwt-tests'

    from models.user import User
    User.init_db()

    yield flask_app

    # Cleanup test database
    db_path = str(config.DATABASE_URI)
    if os.path.exists(db_path):
        os.remove(db_path)


@pytest.fixture(scope='session')
def client(app):
    return app.test_client()


@pytest.fixture(scope='session')
def registered_user(client):
    """Register a test user once per session and return credentials + tokens."""
    import uuid
    unique_email = f"jwttest_{uuid.uuid4().hex[:8]}@example.com"
    resp = client.post('/auth/register', json={
        'email': unique_email,
        'password': 'securepass123'
    })
    assert resp.status_code == 201, f"Registration failed: {resp.get_json()}"
    return resp.get_json()


# ---------------------------------------------------------------------------
# JWTManager unit tests
# ---------------------------------------------------------------------------

class TestJWTManager:
    def test_generate_tokens_structure(self):
        """Token response has the right keys."""
        from auth.jwt_utils import JWTManager
        tokens = JWTManager.generate_tokens(1, 'test@example.com')
        assert 'access_token' in tokens
        assert 'refresh_token' in tokens
        assert 'expires_in' in tokens
        assert tokens['token_type'] == 'Bearer'

    def test_verify_access_token(self):
        """Access token decodes correctly."""
        from auth.jwt_utils import JWTManager
        tokens = JWTManager.generate_tokens(42, 'a@b.com')
        payload = JWTManager.verify_token(tokens['access_token'])
        assert payload['sub'] == '42'
        assert payload['email'] == 'a@b.com'
        assert payload['type'] == 'access'

    def test_verify_refresh_token(self):
        """Refresh token has type=refresh."""
        from auth.jwt_utils import JWTManager
        tokens = JWTManager.generate_tokens(1, 'a@b.com')
        payload = JWTManager.verify_token(tokens['refresh_token'])
        assert payload['type'] == 'refresh'

    def test_expired_token_raises(self):
        """Expired token raises ExpiredSignatureError."""
        import config
        expired_token = _jwt.encode(
            {
                'sub': '1', 'email': 'a@b.com', 'type': 'access',
                'iat': datetime.now(timezone.utc) - timedelta(seconds=3600),
                'exp': datetime.now(timezone.utc) - timedelta(seconds=1),
            },
            config.JWT_SECRET_KEY, algorithm='HS256'
        )
        from auth.jwt_utils import JWTManager
        with pytest.raises(_jwt.ExpiredSignatureError):
            JWTManager.verify_token(expired_token)

    def test_blacklist(self):
        """Blacklisted tokens are detected."""
        from auth.jwt_utils import JWTManager
        tokens = JWTManager.generate_tokens(1, 'a@b.com')
        tok = tokens['access_token']
        assert not JWTManager.is_blacklisted(tok)
        JWTManager.blacklist_token(tok)
        assert JWTManager.is_blacklisted(tok)


# ---------------------------------------------------------------------------
# Auth endpoints
# ---------------------------------------------------------------------------

class TestRegister:
    def test_register_success(self, client):
        resp = client.post('/auth/register', json={
            'email': 'newuser@example.com',
            'password': 'password123'
        })
        assert resp.status_code == 201
        data = resp.get_json()
        assert 'access_token' in data
        assert 'refresh_token' in data
        assert data['user']['email'] == 'newuser@example.com'

    def test_register_duplicate_email(self, client):
        client.post('/auth/register', json={
            'email': 'dup@example.com', 'password': 'pass12345'
        })
        resp = client.post('/auth/register', json={
            'email': 'dup@example.com', 'password': 'pass12345'
        })
        assert resp.status_code == 409

    def test_register_missing_fields(self, client):
        resp = client.post('/auth/register', json={'email': 'x@x.com'})
        assert resp.status_code == 400

    def test_register_short_password(self, client):
        resp = client.post('/auth/register', json={
            'email': 'short@example.com', 'password': '1234'
        })
        assert resp.status_code == 400


class TestLogin:
    def test_login_success(self, client, registered_user):
        # Use the email from the dynamically-registered user
        email = registered_user['user']['email']
        resp = client.post('/auth/login', json={
            'email': email,
            'password': 'securepass123'
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'access_token' in data
        assert 'refresh_token' in data

    def test_login_wrong_password(self, client, registered_user):
        email = registered_user['user']['email']
        resp = client.post('/auth/login', json={
            'email': email,
            'password': 'wrongpassword'
        })
        assert resp.status_code == 401

    def test_login_unknown_user(self, client):
        resp = client.post('/auth/login', json={
            'email': 'nobody@example.com', 'password': 'anything'
        })
        assert resp.status_code == 401


class TestRefresh:
    def test_refresh_success(self, client, registered_user):
        refresh_token = registered_user['refresh_token']
        resp = client.post('/auth/refresh', json={'refresh_token': refresh_token})
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'access_token' in data

    def test_refresh_with_access_token_rejected(self, client, registered_user):
        """Using an access token as a refresh token should fail."""
        access_token = registered_user['access_token']
        resp = client.post('/auth/refresh', json={'refresh_token': access_token})
        assert resp.status_code == 400

    def test_refresh_missing_token(self, client):
        resp = client.post('/auth/refresh', json={})
        assert resp.status_code == 400


class TestLogout:
    def test_logout(self, client, registered_user):
        resp = client.post('/auth/logout', json={
            'refresh_token': registered_user['refresh_token']
        }, headers={'Authorization': f"Bearer {registered_user['access_token']}"})
        assert resp.status_code == 200


class TestMe:
    def test_me_with_valid_token(self, client, registered_user):
        # Re-login to get a fresh token (avoids reusing a blacklisted token from TestLogout)
        email = registered_user['user']['email']
        login_resp = client.post('/auth/login', json={
            'email': email, 'password': 'securepass123'
        })
        fresh_token = login_resp.get_json()['access_token']
        resp = client.get('/auth/me', headers={'Authorization': f'Bearer {fresh_token}'})
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'user' in data

    def test_me_without_token(self, client):
        resp = client.get('/auth/me')
        assert resp.status_code == 401

    def test_me_with_bad_token(self, client):
        resp = client.get('/auth/me', headers={'Authorization': 'Bearer invalidtoken'})
        assert resp.status_code == 401

    def test_me_with_expired_token(self, client):
        import config
        expired = _jwt.encode(
            {
                'sub': '999', 'email': 'x@x.com', 'type': 'access',
                'iat': datetime.now(timezone.utc) - timedelta(hours=2),
                'exp': datetime.now(timezone.utc) - timedelta(hours=1),
            },
            config.JWT_SECRET_KEY, algorithm='HS256'
        )
        resp = client.get('/auth/me', headers={'Authorization': f'Bearer {expired}'})
        assert resp.status_code == 401


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
