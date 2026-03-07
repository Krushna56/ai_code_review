"""
Authentication Routes — JWT-based

Each endpoint name appears exactly ONCE in this file.
GET  /auth/login           → render login page
POST /auth/login           → JSON: authenticate, return tokens
GET  /auth/register-page   → render register page
POST /auth/register        → JSON: create account, return tokens
GET|POST /auth/logout      → GET: clear session + redirect; POST: blacklist tokens (API)
POST /auth/set-session     → store JWT in Flask session (called from JS after login)
POST /auth/refresh         → exchange refresh token for new access token
GET  /auth/me              → return current user info (JWT required)
GET  /auth/github          → start GitHub OAuth flow
GET  /auth/github/callback → handle GitHub OAuth callback, set session, redirect home
"""
from flask import Blueprint, jsonify, request, redirect, session, render_template, url_for
from models.user import User
from auth.jwt_utils import JWTManager, jwt_required
import requests
import secrets
import config
import logging
import time
import hmac
import hashlib

logger = logging.getLogger(__name__)

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

# ---------------------------------------------------------------------------
# HMAC-signed stateless OAuth state tokens
# Format: "<nonce>.<timestamp>.<hmac_signature>"
# No shared storage needed — works across Flask reloader processes.
# ---------------------------------------------------------------------------
_OAUTH_STATE_TTL = 600  # 10 minutes

def _create_oauth_state() -> str:
    """Generate a signed state token: nonce.timestamp.signature"""
    nonce = secrets.token_urlsafe(16)
    timestamp = str(int(time.time()))
    payload = f"{nonce}.{timestamp}"
    signature = hmac.new(
        config.SECRET_KEY.encode('utf-8'),
        payload.encode('utf-8'),
        hashlib.sha256,
    ).hexdigest()
    return f"{payload}.{signature}"

def _verify_oauth_state(state: str) -> bool:
    """Return True if the state is valid, signed by us, and not expired."""
    if not state:
        return False
    try:
        parts = state.rsplit('.', 1)  # split off the signature
        if len(parts) != 2:
            return False
        payload, received_sig = parts
        expected_sig = hmac.new(
            config.SECRET_KEY.encode('utf-8'),
            payload.encode('utf-8'),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(received_sig, expected_sig):
            return False
        # Check expiry
        _, timestamp_str = payload.rsplit('.', 1)
        if time.time() - int(timestamp_str) > _OAUTH_STATE_TTL:
            logger.warning("OAuth state token expired")
            return False
        return True
    except Exception as e:
        logger.warning(f"OAuth state verification error: {e}")
        return False


# ---------------------------------------------------------------------------
# Login — GET renders page, POST authenticates (JSON)
# ---------------------------------------------------------------------------
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """
    GET:  Render the login page.
    POST: Authenticate with email + password, return JSON tokens.
    """
    if request.method == 'GET':
        return render_template('auth/login.html')

    data = request.get_json(silent=True) or {}
    email = (data.get('email') or '').strip().lower()
    password = data.get('password', '')

    if not email or not password:
        return jsonify({'error': 'email and password are required'}), 400

    user = User.get_by_email(email)
    if user is None or not user.check_password(password):
        return jsonify({'error': 'Invalid email or password'}), 401

    user.update_last_login()
    logger.info(f"User logged in: {email}")
    tokens = JWTManager.generate_tokens(user.id, user.email)
    return jsonify({**tokens, 'user': user.to_dict()}), 200


# ---------------------------------------------------------------------------
# Register page (GET) — render template
# ---------------------------------------------------------------------------
@auth_bp.route('/register-page', methods=['GET'])
def register_page():
    """Render the register page."""
    return render_template('auth/register.html')


# ---------------------------------------------------------------------------
# Register — POST: create account, return tokens
# ---------------------------------------------------------------------------
@auth_bp.route('/register', methods=['POST'])
def register():
    """
    POST: Register a new user.
    Body: { "email": "...", "password": "..." }
    """
    data = request.get_json(silent=True) or {}
    email = (data.get('email') or '').strip().lower()
    password = data.get('password', '')

    if not email or not password:
        return jsonify({'error': 'email and password are required'}), 400
    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400
    if User.get_by_email(email):
        return jsonify({'error': 'Email already registered'}), 409

    try:
        user = User(email=email)
        user.set_password(password)
        user.save()
        logger.info(f"New user registered: {email}")
        tokens = JWTManager.generate_tokens(user.id, user.email)
        return jsonify({**tokens, 'user': user.to_dict()}), 201
    except Exception as e:
        logger.error(f"Registration error: {e}")
        return jsonify({'error': 'Registration failed'}), 500


# ---------------------------------------------------------------------------
# Logout — GET: clear session + redirect; POST: blacklist tokens (API clients)
# ---------------------------------------------------------------------------
@auth_bp.route('/logout', methods=['GET', 'POST'])
def logout():
    """
    GET:  Clear the JWT from the Flask session and redirect to home.
    POST: Blacklist the provided refresh/access tokens (JSON API).
    """
    if request.method == 'GET':
        refresh_token = session.pop('jwt_refresh_token', None)
        session.pop('jwt_access_token', None)
        if refresh_token:
            JWTManager.blacklist_token(refresh_token)
        return redirect(url_for('index'))

    # POST — JSON API: blacklist tokens
    data = request.get_json(silent=True) or {}
    refresh_token = data.get('refresh_token', '').strip()
    if refresh_token:
        JWTManager.blacklist_token(refresh_token)
    auth_header = request.headers.get('Authorization', '')
    if auth_header.startswith('Bearer '):
        JWTManager.blacklist_token(auth_header.split(' ', 1)[1].strip())
    return jsonify({'message': 'Logged out successfully'}), 200


# ---------------------------------------------------------------------------
# Set-session — store JWT in Flask session (called by JS after login/register)
# ---------------------------------------------------------------------------
@auth_bp.route('/set-session', methods=['POST'])
def set_session():
    """
    Store tokens in the Flask session so the context_processor
    can inject current_user into Jinja2 templates.
    Body: { "access_token": "...", "refresh_token": "..." }
    """
    data = request.get_json(silent=True) or {}
    access_token = data.get('access_token', '').strip()
    refresh_token = data.get('refresh_token', '').strip()

    if not access_token:
        return jsonify({'error': 'access_token required'}), 400

    try:
        payload = JWTManager.verify_token(access_token)
        if payload.get('type') != 'access':
            return jsonify({'error': 'Not an access token'}), 400
    except Exception:
        return jsonify({'error': 'Invalid access token'}), 401

    session['jwt_access_token'] = access_token
    if refresh_token:
        session['jwt_refresh_token'] = refresh_token
    return jsonify({'ok': True}), 200


# ---------------------------------------------------------------------------
# Refresh access token
# ---------------------------------------------------------------------------
@auth_bp.route('/refresh', methods=['POST'])
def refresh():
    """
    Exchange a valid refresh token for a new access token.
    Body: { "refresh_token": "..." }
    """
    import jwt as _jwt

    data = request.get_json(silent=True) or {}
    refresh_token = data.get('refresh_token', '').strip()

    if not refresh_token:
        return jsonify({'error': 'refresh_token is required'}), 400
    if JWTManager.is_blacklisted(refresh_token):
        return jsonify({'error': 'Token has been revoked'}), 401

    try:
        payload = JWTManager.verify_token(refresh_token)
    except _jwt.ExpiredSignatureError:
        return jsonify({'error': 'Refresh token has expired. Please log in again.'}), 401
    except _jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid refresh token'}), 401

    if payload.get('type') != 'refresh':
        return jsonify({'error': 'Provided token is not a refresh token'}), 400

    user = User.get_by_id(int(payload['sub']))
    if not user:
        return jsonify({'error': 'User not found'}), 404

    tokens = JWTManager.generate_tokens(user.id, user.email)
    return jsonify({
        'access_token': tokens['access_token'],
        'expires_in': tokens['expires_in'],
        'token_type': 'Bearer',
    }), 200


# ---------------------------------------------------------------------------
# Current user info (JWT-protected)
# ---------------------------------------------------------------------------
@auth_bp.route('/me', methods=['GET'])
@jwt_required
def me():
    """Return the currently authenticated user's profile."""
    from flask import g
    user = User.get_by_id(g.current_user['id'])
    if not user:
        return jsonify({'error': 'User not found'}), 404
    return jsonify({'user': user.to_dict()}), 200


# ---------------------------------------------------------------------------
# GitHub OAuth — redirect to GitHub
# ---------------------------------------------------------------------------
@auth_bp.route('/github')
def github_login():
    """Initiate GitHub OAuth flow."""
    if not config.GITHUB_CLIENT_ID:
        return jsonify({'error': 'GitHub OAuth is not configured'}), 501

    state = _create_oauth_state()
    base_url = config.OAUTH_REDIRECT_BASE_URL or request.host_url.rstrip('/')
    github_auth_url = (
        f"{config.GITHUB_AUTHORIZATION_URL}"
        f"?client_id={config.GITHUB_CLIENT_ID}"
        f"&redirect_uri={base_url}/auth/github/callback"
        f"&scope=user:email"
        f"&state={state}"
    )
    logger.info(f"GitHub OAuth initiated, state stored server-side")
    return redirect(github_auth_url)


# ---------------------------------------------------------------------------
# GitHub OAuth — callback (issues JWT, stores in session, redirects home)
# ---------------------------------------------------------------------------
@auth_bp.route('/github/callback')
def github_callback():
    """Handle GitHub OAuth callback — issue JWT and redirect home."""
    logger.info("GitHub callback received")

    state = request.args.get('state')
    if not _verify_oauth_state(state):
        logger.warning(f"GitHub callback: invalid or expired state token")
        return jsonify({'error': 'Invalid state token — please try logging in again'}), 400

    code = request.args.get('code')
    if not code:
        return jsonify({'error': 'GitHub authorization failed — no code'}), 400

    try:
        token_resp = requests.post(
            config.GITHUB_TOKEN_URL,
            data={
                'client_id': config.GITHUB_CLIENT_ID,
                'client_secret': config.GITHUB_CLIENT_SECRET,
                'code': code,
                'redirect_uri': f"{config.OAUTH_REDIRECT_BASE_URL or request.host_url.rstrip('/')}/auth/github/callback",
            },
            headers={'Accept': 'application/json'},
            timeout=10,
        )
        token_resp.raise_for_status()
        gh_access_token = token_resp.json().get('access_token')

        if not gh_access_token:
            return jsonify({'error': 'Failed to obtain access token from GitHub'}), 502

        user_resp = requests.get(
            config.GITHUB_API_URL,
            headers={'Authorization': f'token {gh_access_token}', 'Accept': 'application/json'},
            timeout=10,
        )
        user_resp.raise_for_status()
        gh_user = user_resp.json()

        github_id = str(gh_user['id'])
        github_username = gh_user['login']
        github_email = gh_user.get('email')

        if not github_email:
            emails_resp = requests.get(
                f"{config.GITHUB_API_URL}/emails",
                headers={'Authorization': f'token {gh_access_token}', 'Accept': 'application/json'},
                timeout=10,
            )
            if emails_resp.ok:
                primary = next((e['email'] for e in emails_resp.json() if e.get('primary')), None)
                if primary:
                    github_email = primary

        user = User.get_by_github_id(github_id)
        if not user:
            if github_email:
                user = User.get_by_email(github_email)
                if user:
                    user.github_id = github_id
                    user.github_username = github_username
                    user.save()
                else:
                    user = User(email=github_email, github_id=github_id, github_username=github_username)
                    user.save()
            else:
                user = User(github_id=github_id, github_username=github_username)
                user.save()

        user.update_last_login()
        logger.info(f"GitHub user authenticated: {github_username}")

        # Persist the GitHub access token so email-login users can still call the GitHub API
        user.github_access_token = gh_access_token
        user.save()

        tokens = JWTManager.generate_tokens(user.id, user.email or github_username)
        session['jwt_access_token'] = tokens['access_token']
        session['jwt_refresh_token'] = tokens['refresh_token']
        # Store GitHub access token so the repo-picker can call the GitHub API
        session['github_access_token'] = gh_access_token
        session.permanent = True
        session.modified = True
        logger.info(f"GitHub user session set for: {github_username}")
        return redirect(url_for('index'))

    except requests.RequestException as e:
        logger.error(f"GitHub OAuth error: {e}")
        return jsonify({'error': 'Failed to authenticate with GitHub'}), 502
    except Exception as e:
        logger.error(f"Unexpected GitHub OAuth error: {e}")
        return jsonify({'error': 'Unexpected error during GitHub authentication'}), 500


# ---------------------------------------------------------------------------
# LinkedIn OAuth — redirect to LinkedIn
# ---------------------------------------------------------------------------
@auth_bp.route('/linkedin')
def linkedin_login():
    """Initiate LinkedIn OAuth flow."""
    if not config.LINKEDIN_CLIENT_ID:
        return jsonify({'error': 'LinkedIn OAuth is not configured'}), 501

    state = _create_oauth_state()
    base_url = config.OAUTH_REDIRECT_BASE_URL or request.host_url.rstrip('/')
    linkedin_auth_url = (
        f"{config.LINKEDIN_AUTHORIZATION_URL}"
        f"?response_type=code"
        f"&client_id={config.LINKEDIN_CLIENT_ID}"
        f"&redirect_uri={base_url}/auth/linkedin/callback"
        f"&scope=openid%20profile%20email"
        f"&state={state}"
    )
    return redirect(linkedin_auth_url)


# ---------------------------------------------------------------------------
# LinkedIn OAuth — callback (issues JWT, stores in session, redirects home)
# ---------------------------------------------------------------------------
@auth_bp.route('/linkedin/callback')
def linkedin_callback():
    """Handle LinkedIn OAuth callback — issue JWT and redirect home."""
    logger.info("LinkedIn callback received")

    state = request.args.get('state')
    if not _verify_oauth_state(state):
        logger.warning(f"LinkedIn callback: invalid or expired state token")
        return jsonify({'error': 'Invalid state token — please try logging in again'}), 400

    code = request.args.get('code')
    if not code:
        return jsonify({'error': 'LinkedIn authorization failed — no code'}), 400

    try:
        # Exchange code for access token
        token_resp = requests.post(
            config.LINKEDIN_TOKEN_URL,
            data={
                'grant_type': 'authorization_code',
                'code': code,
                'redirect_uri': f"{config.OAUTH_REDIRECT_BASE_URL or request.host_url.rstrip('/')}/auth/linkedin/callback",
                'client_id': config.LINKEDIN_CLIENT_ID,
                'client_secret': config.LINKEDIN_CLIENT_SECRET,
            },
            headers={'Accept': 'application/json'},
            timeout=10,
        )
        token_resp.raise_for_status()
        li_access_token = token_resp.json().get('access_token')

        if not li_access_token:
            return jsonify({'error': 'Failed to obtain access token from LinkedIn'}), 502

        # Get LinkedIn user profile via OpenID Connect userinfo
        user_resp = requests.get(
            config.LINKEDIN_API_URL,
            headers={'Authorization': f'Bearer {li_access_token}', 'Accept': 'application/json'},
            timeout=10,
        )
        user_resp.raise_for_status()
        li_user = user_resp.json()

        linkedin_id = str(li_user.get('sub', ''))
        linkedin_username = li_user.get('name', '')
        linkedin_email = li_user.get('email')

        if not linkedin_id:
            return jsonify({'error': 'Could not retrieve LinkedIn user ID'}), 502

        # Find or create user
        user = User.get_by_linkedin_id(linkedin_id)
        if not user:
            if linkedin_email:
                user = User.get_by_email(linkedin_email)
                if user:
                    user.linkedin_id = linkedin_id
                    user.linkedin_username = linkedin_username
                    user.save()
                else:
                    user = User(
                        email=linkedin_email,
                        linkedin_id=linkedin_id,
                        linkedin_username=linkedin_username,
                    )
                    user.save()
            else:
                user = User(linkedin_id=linkedin_id, linkedin_username=linkedin_username)
                user.save()

        user.update_last_login()
        logger.info(f"LinkedIn user authenticated: {linkedin_username}")

        tokens = JWTManager.generate_tokens(user.id, user.email or linkedin_username)
        session['jwt_access_token'] = tokens['access_token']
        session['jwt_refresh_token'] = tokens['refresh_token']
        logger.info(f"LinkedIn user session set for: {linkedin_username}")
        return redirect(url_for('index'))

    except requests.RequestException as e:
        logger.error(f"LinkedIn OAuth error: {e}")
        return jsonify({'error': 'Failed to authenticate with LinkedIn'}), 502
    except Exception as e:
        logger.error(f"Unexpected LinkedIn OAuth error: {e}")
        return jsonify({'error': 'Unexpected error during LinkedIn authentication'}), 500


# ---------------------------------------------------------------------------
# GitHub Repos — return the authenticated user's repo list
# ---------------------------------------------------------------------------
@auth_bp.route('/github/repos')
def github_repos():
    """Return the logged-in GitHub user's repositories as JSON (for the repo picker)."""
    from flask import g
    from auth.jwt_utils import JWTManager
    import jwt as _jwt

    # 1. Try session token first (fastest path — set right after OAuth callback)
    gh_token = session.get('github_access_token')

    # 2. Fall back to the token stored in DB (for users who log in via email/password)
    if not gh_token:
        jwt_token = session.get('jwt_access_token')
        if jwt_token:
            try:
                payload = JWTManager.verify_token(jwt_token)
                user = User.get_by_id(int(payload['sub']))
                if user:
                    gh_token = user.github_access_token
                    if gh_token:
                        # Restore to session for subsequent requests
                        session['github_access_token'] = gh_token
                        session.modified = True
            except _jwt.InvalidTokenError:
                pass

    if not gh_token:
        return jsonify({'error': 'GitHub not connected — please login with GitHub first'}), 401

    repos = []
    page = 1
    while True:
        try:
            resp = requests.get(
                'https://api.github.com/user/repos',
                headers={
                    'Authorization': f'token {gh_token}',
                    'Accept': 'application/json',
                },
                params={'per_page': 100, 'page': page, 'sort': 'updated', 'affiliation': 'owner,collaborator'},
                timeout=10,
            )
            if not resp.ok:
                break
            batch = resp.json()
            if not batch:
                break
            for r in batch:
                repos.append({
                    'name': r['name'],
                    'full_name': r['full_name'],
                    'description': r.get('description') or '',
                    'language': r.get('language') or 'Unknown',
                    'stars': r.get('stargazers_count', 0),
                    'forks': r.get('forks_count', 0),
                    'private': r.get('private', False),
                    'clone_url': r['clone_url'],
                    'html_url': r['html_url'],
                    'updated_at': r.get('updated_at', ''),
                })
            if len(batch) < 100:
                break
            page += 1
        except requests.RequestException as e:
            logger.error(f"Error fetching GitHub repos: {e}")
            break

    logger.info(f"Fetched {len(repos)} GitHub repos")
    return jsonify({'repos': repos, 'total': len(repos)}), 200


