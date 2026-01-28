# Authentication Setup Guide

## Overview

This platform now includes user authentication with both email/password registration and GitHub OAuth support.

## Setup Steps

### 1. Install Dependencies

```bash
pip install Flask-Login Flask-WTF WTForms email-validator bcrypt requests-oauthlib
```

Or install all dependencies:

```bash
pip install -r requirements.txt
```

### 2. Configure Environment Variables

Copy `.env.example` to `.env` and configure:

```bash
# Authentication Secret (REQUIRED)
# Generate a strong secret key for production
SECRET_KEY=your-secret-key-here-change-in-production

# GitHub OAuth (OPTIONAL)
GITHUB_CLIENT_ID=your-github-oauth-client-id
GITHUB_CLIENT_SECRET=your-github-oauth-client-secret
```

**To generate a secure SECRET_KEY:**

```python
import secrets
print(secrets.token_hex(32))
```

### 3. Set Up GitHub OAuth (Optional)

If you want to enable GitHub login:

1. Go to https://github.com/settings/developers
2. Click "New OAuth App"
3. Fill in the form:
   - **Application name**: AI Code Review Platform
   - **Homepage URL**: `http://localhost:5000`
   - **Authorization callback URL**: `http://localhost:5000/auth/github/callback`
4. Click "Register application"
5. Copy the **Client ID** and **Client Secret** to your `.env` file

### 4. Run the Application

The database will be initialized automatically on first run:

```bash
python app.py
```

The authentication database (`instance/users.db`) will be created automatically.

## Usage

### Registration

- Navigate to `http://localhost:5000/auth/register`
- Fill in email and password
- Click "Register"

### Login

- Navigate to `http://localhost:5000/auth/login`
- Enter email and password
- Or click "Continue with GitHub"

### Protected Routes

The following routes now require authentication:

- `/` - Main upload page
- `/dashboard` - Security dashboard
- `/chat` - AI chat interface
- `/api/*` - All API endpoints

## Features

✅ **Email/Password Authentication**

- Secure password hashing with bcrypt
- Email validation
- "Remember Me" functionality

✅ **GitHub OAuth**

- One-click GitHub login
- Automatic account linking
- GitHub username display

✅ **Session Management**

- Flask-Login integration
- Persistent sessions
- Secure logout

## Security Notes

1. **Change SECRET_KEY in Production**: The default secret key is for development only
2. **HTTPS Required**: Use HTTPS in production for secure authentication
3. **GitHub OAuth**: Callback URL must match your deployment domain
4. **Password Requirements**: Minimum 8 characters enforced

## Database Schema

The `users` table includes:

- `id` - Primary key
- `email` - Unique email address
- `password_hash` - Bcrypt hashed password
- `github_id` - GitHub user ID (for OAuth)
- `github_username` - GitHub username
- `created_at` - Registration timestamp
- `last_login` - Last login timestamp

## Troubleshooting

**Issue**: "No module named 'flask_login'"

- **Solution**: Run `pip install Flask-Login`

**Issue**: GitHub OAuth not working

- **Solution**: Check that `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET` are set correctly
- **Solution**: Verify callback URL matches GitHub app configuration

**Issue**: Database errors

- **Solution**: Delete `instance/users.db` and restart the application

**Issue**: Redirected to login on every page

- **Solution**: Check that SECRET_KEY is set in `.env`

## API Changes

All API endpoints now require authentication. Include session cookie or use API authentication headers.

## Next Steps

- Consider adding password reset functionality
- Implement email verification
- Add user profile management
- Track analysis history per user
