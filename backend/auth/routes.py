"""
Authentication Routes

Handles user registration, login, logout, and GitHub OAuth
"""
from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, current_user
from urllib.parse import urlparse  # Changed from werkzeug.urls.url_parse for Werkzeug 3.0+
import requests
import secrets
import config
from auth.forms import RegistrationForm, LoginForm
from models.user import User
import logging

logger = logging.getLogger(__name__)

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """User registration with email and password"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = RegistrationForm()
    
    if form.validate_on_submit():
        try:
            # Create new user
            user = User(email=form.email.data)
            user.set_password(form.password.data)
            user.save()
            
            # Log user in
            login_user(user)
            flash('Registration successful! Welcome to AI Code Review Platform.', 'success')
            logger.info(f"New user registered: {user.email}")
            
            return redirect(url_for('index'))
        except Exception as e:
            logger.error(f"Registration error: {e}")
            flash('An error occurred during registration. Please try again.', 'error')
    
    return render_template('auth/register.html', form=form)


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """User login with email and password"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = LoginForm()
    
    if form.validate_on_submit():
        user = User.get_by_email(form.email.data)
        
        if user is None or not user.check_password(form.password.data):
            flash('Invalid email or password', 'error')
            return redirect(url_for('auth.login'))
        
        login_user(user, remember=form.remember.data)
        user.update_last_login()
        logger.info(f"User logged in: {user.email}")
        
        # Redirect to next page or index
        next_page = request.args.get('next')
        if not next_page or urlparse(next_page).netloc != '':
            next_page = url_for('index')
        
        flash(f'Welcome back, {user.email}!', 'success')
        return redirect(next_page)
    
    return render_template('auth/login.html', form=form)


@auth_bp.route('/logout')
def logout():
    """Logout current user"""
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))


@auth_bp.route('/github')
def github_login():
    """Initiate GitHub OAuth flow"""
    if not config.GITHUB_CLIENT_ID:
        flash('GitHub OAuth is not configured. Please contact the administrator.', 'error')
        return redirect(url_for('auth.login'))
    
    # Generate state token for CSRF protection
    state = secrets.token_urlsafe(32)
    session['oauth_state'] = state
    
    # Build GitHub authorization URL
    github_auth_url = (
        f"{config.GITHUB_AUTHORIZATION_URL}"
        f"?client_id={config.GITHUB_CLIENT_ID}"
        f"&redirect_uri={request.host_url}auth/github/callback"
        f"&scope=user:email"
        f"&state={state}"
    )
    
    return redirect(github_auth_url)


@auth_bp.route('/github/callback')
def github_callback():
    """Handle GitHub OAuth callback"""
    # Verify state token
    state = request.args.get('state')
    if not state or state != session.get('oauth_state'):
        flash('Invalid state token. Authentication failed.', 'error')
        return redirect(url_for('auth.login'))
    
    # Clear state from session
    session.pop('oauth_state', None)
    
    # Get authorization code
    code = request.args.get('code')
    if not code:
        flash('GitHub authorization failed.', 'error')
        return redirect(url_for('auth.login'))
    
    try:
        # Exchange code for access token
        token_response = requests.post(
            config.GITHUB_TOKEN_URL,
            data={
                'client_id': config.GITHUB_CLIENT_ID,
                'client_secret': config.GITHUB_CLIENT_SECRET,
                'code': code,
                'redirect_uri': f"{request.host_url}auth/github/callback"
            },
            headers={'Accept': 'application/json'}
        )
        token_response.raise_for_status()
        access_token = token_response.json().get('access_token')
        
        if not access_token:
            flash('Failed to obtain access token from GitHub.', 'error')
            return redirect(url_for('auth.login'))
        
        # Get user info from GitHub
        user_response = requests.get(
            config.GITHUB_API_URL,
            headers={
                'Authorization': f'token {access_token}',
                'Accept': 'application/json'
            }
        )
        user_response.raise_for_status()
        github_user = user_response.json()
        
        github_id = str(github_user['id'])
        github_username = github_user['login']
        github_email = github_user.get('email')
        
        # Get primary email if not public
        if not github_email:
            emails_response = requests.get(
                f"{config.GITHUB_API_URL}/emails",
                headers={
                    'Authorization': f'token {access_token}',
                    'Accept': 'application/json'
                }
            )
            if emails_response.status_code == 200:
                emails = emails_response.json()
                primary_email = next((e['email'] for e in emails if e['primary']), None)
                if primary_email:
                    github_email = primary_email
        
        # Check if user exists by GitHub ID
        user = User.get_by_github_id(github_id)
        
        if user:
            # User exists, log them in
            login_user(user)
            user.update_last_login()
            flash(f'Welcome back, {user.github_username or user.email}!', 'success')
            logger.info(f"GitHub user logged in: {github_username}")
        else:
            # Check if email already exists
            if github_email:
                existing_user = User.get_by_email(github_email)
                if existing_user:
                    # Link GitHub account to existing user
                    existing_user.github_id = github_id
                    existing_user.github_username = github_username
                    existing_user.save()
                    login_user(existing_user)
                    existing_user.update_last_login()
                    flash(f'GitHub account linked successfully! Welcome back, {existing_user.email}!', 'success')
                    logger.info(f"GitHub account linked to existing user: {github_email}")
                else:
                    # Create new user with GitHub
                    user = User(
                        email=github_email,
                        github_id=github_id,
                        github_username=github_username
                    )
                    user.save()
                    login_user(user)
                    flash(f'Welcome to AI Code Review Platform, {github_username}!', 'success')
                    logger.info(f"New user created via GitHub: {github_username}")
            else:
                # No email from GitHub, create user with GitHub ID only
                user = User(
                    github_id=github_id,
                    github_username=github_username
                )
                user.save()
                login_user(user)
                flash(f'Welcome to AI Code Review Platform, {github_username}!', 'success')
                logger.info(f"New user created via GitHub (no email): {github_username}")
        
        return redirect(url_for('index'))
        
    except requests.RequestException as e:
        logger.error(f"GitHub OAuth error: {e}")
        flash('Failed to authenticate with GitHub. Please try again.', 'error')
        return redirect(url_for('auth.login'))
    except Exception as e:
        logger.error(f"Unexpected error during GitHub OAuth: {e}")
        flash('An unexpected error occurred. Please try again.', 'error')
        return redirect(url_for('auth.login'))
