# Real-Time GitHub Integration - Implementation Guide

## Overview

This document outlines the real-time GitHub integration feature added to the AI Code Review Platform. The system now provides live GitHub repository data, commit status tracking, and contributor insights directly in the dashboard.

## Architecture

### Components Implemented

#### 1. **GitHub Service Client** (`backend/services/github_service.py`)
- **GitHubAPIClient Class**: Main interface for GitHub API interactions
  - Authenticates with optional user access tokens
  - Provides 10+ methods for real-time data fetching
  - Handles API rate limiting
  - Includes comprehensive error handling and logging

**Key Methods:**
```python
- parse_github_url(url) → (owner, repo)
- get_repo_info(owner, repo) → Repository metadata
- get_latest_commits(owner, repo, branch, limit) → Commit history
- get_commit_status(owner, repo, sha) → CI/CD status
- get_check_runs(owner, repo, ref) → GitHub Actions details
- get_pull_requests(owner, repo, state, limit) → PR information
- get_release_info(owner, repo) → Latest release data
- get_branches(owner, repo, limit) → Branch tracking
- get_contributors(owner, repo, limit) → Contributor statistics
- get_repo_stats(owner, repo) → Comprehensive statistics
```

#### 2. **Repository Model** (`backend/models/repository.py`)
- **Database Schema**: Tracks analyzed repositories with GitHub metadata
- **Fields**:
  - `id`: Primary key
  - `user_id`: Link to user account
  - `repo_url`: Full GitHub repository URL
  - `owner`, `repo_name`, `repo_full_name`: Parsed GitHub identifiers
  - `description`, `language`, `stars`: Repository metadata
  - `analysis_id`: Link to code analysis
  - `github_data`: Complete GitHub API response (JSON)
  - `commit_status`: Latest commit CI/CD status
  - `last_commit_sha`, `last_commit_date`: Tracking data
  - `created_at`, `updated_at`: Timestamps

- **Methods**:
  - `save()` → Persist to database
  - `get_by_url(url)` → Retrieve by URL
  - `get_by_id(id)` → Retrieve by primary key
  - `get_by_user(user_id, limit)` → User's tracked repos
  - `delete()` → Remove repository
  - `to_dict()` → Serialize for API responses
  - `create_table()` → Initialize database schema

#### 3. **Flask API Endpoints** (`backend/app.py`)

##### Real-Time Data Endpoints

**1. Repository Information**
```
GET /api/github/repo-info/<owner>/<repo>
```
- Returns: Repository metadata (stars, forks, language, URLs, etc.)
- Authentication: JWT required
- Caching: Updates in database on each call
- Rate Limited: Applied per endpoint

**2. Commit History**
```
GET /api/github/commits/<owner>/<repo>?branch=main&limit=20
```
- Returns: Latest commits with authors, messages, timestamps
- Parameters:
  - `branch`: Target branch (default: `main`)
  - `limit`: Number of commits (1-100, default: 20)
- Features:
  - Author avatar URLs
  - Commit SHA for traceability
  - ISO timestamp formatting

**3. Commit CI/CD Status**
```
GET /api/github/commit-status/<owner>/<repo>/<sha>
```
- Returns:
  - Commit status (success/failure/pending/error)
  - GitHub Actions check runs with details
  - Build logs if available
- Updates: Stores latest status in database

**4. Comprehensive Repository Statistics**
```
GET /api/github/stats/<owner>/<repo>
```
- Returns: Aggregated data
  - Repository metadata
  - Latest 10 commits
  - Current CI/CD status
  - Pull requests (open/closed)
  - Top 10 contributors
  - Release information
  - Branch information

**5. User's Tracked Repositories**
```
GET /api/github/user-repos?limit=50
```
- Returns: All repositories being tracked by current user
- Pagination: Supports `limit` parameter
- Response Format:
  ```json
  {
    "repositories": [...],
    "count": 12
  }
  ```

**6. Track New Repository**
```
POST /api/github/track-repo
Content-Type: application/json

{
  "repo_url": "https://github.com/owner/repo"
}
```
- Creates new tracking entry
- Fetches initial metadata from GitHub
- Returns: Repository object with full data
- Status Codes:
  - 201: Successfully created
  - 200: Already being tracked
  - 404: Repository not found
  - 400: Invalid URL format

### Authentication & Authorization

**GitHub API Authentication:**
- **Public Repos**: Works without authentication (60 req/hr limit)
- **Authenticated Requests**: Uses user's personal access token (5000 req/hr limit)
- **Token Storage**: Stored in User model's `github_access_token` field
- **OAuth Flow**: Integrated with existing settings in `settings.py`

**JWT Requirements:**
- All endpoints require valid JWT token in Authorization header
- Tokens validated by `@jwt_required` decorator
- User context available via `g.user_id`

### Database Integration

**Initialization:**
```python
# Automatically called on app startup
Repository.create_table()
```

**Supported Backends:**
- **PostgreSQL**: Full JSONB support for github_data field
- **SQLite**: JSON text storage with automatic serialization

**Connection Pooling:**
- Uses existing `db_pool.py` utilities
- Connection reuse for performance
- Thread-safe connections (PostgreSQL)
- SQLite fallback for development

## Usage Examples

### 1. Get Real-Time Repository Stats

```python
import requests

headers = {"Authorization": f"Bearer {jwt_token}"}
response = requests.get(
    "http://localhost:5000/api/github/stats/microsoft/vscode",
    headers=headers
)
stats = response.json()

print(f"Stars: {stats['stars']}")
print(f"Language: {stats['language']}")
print(f"Latest Commit: {stats['latest_commit']['message']}")
print(f"Build Status: {stats['commit_status']['state']}")
```

### 2. Track User's Repository

```python
payload = {
    "repo_url": "https://github.com/user/my-project"
}
response = requests.post(
    "http://localhost:5000/api/github/track-repo",
    json=payload,
    headers=headers
)
repository = response.json()['repository']
print(f"Tracking {repository['repo_full_name']}")
```

### 3. Get Commit Status for Deployment Verification

```python
response = requests.get(
    f"http://localhost:5000/api/github/commit-status/org/repo/{commit_sha}",
    headers=headers
)
status = response.json()
if status['status']['state'] == 'success':
    print("Safe to deploy!")
else:
    print(f"Build failed: {status['check_runs']}")
```

### 4. Monitor Contributors

```python
response = requests.get(
    "http://localhost:5000/api/github/stats/myorg/myrepo",
    headers=headers
)
stats = response.json()
for contributor in stats['contributors'][:5]:
    print(f"{contributor['login']}: {contributor['contributions']} commits")
```

## Dashboard Integration

### Frontend Components

**Recommended Dashboard Widgets:**

1. **Repository Overview Card**
   - Repository name and URL
   - Star/fork counts
   - Primary language
   - Last updated timestamp

2. **Commit Status Indicator**
   - Latest commit SHA (truncated)
   - CI/CD status with color coding
   - Check runs detail list
   - Last check run timestamp

3. **Recent Commits Feed**
   - Author avatar + name
   - Commit message (truncated)
   - Timestamp
   - Link to GitHub commit page

4. **Contributors Leaderboard**
   - Top 10 contributors with avatars
   - Contribution count
   - Percentage of total contributions

5. **Repository Health Metrics**
   - Open PR count
   - Latest release tag
   - Branch protection status
   - Last deployment date

### Real-Time Updates (Future Enhancement)

**WebSocket Implementation Ready:**
- Architecture supports WebSocket endpoints
- Can add `/api/github/subscribe/<owner>/<repo>` for live updates
- Recommended polling interval: 30-60 seconds
- Event types supported:
  - Commit events (push)
  - PR events (created/merged)
  - Release events (published)
  - Check run events (completed)

## Performance Considerations

### Rate Limiting
- **GitHub API**: 60/hr (unauthenticated), 5000/hr (authenticated)
- **Application**: Apply per-endpoint rate limiting (8 requests/min default)
- **Caching**: Store results in database, expire every 5 minutes

### Optimization Strategies

1. **Batch Requests**
   - Use `get_repo_stats()` for comprehensive data
   - Reduces multiple API calls to single request

2. **Selective Fields**
   - Parse GitHub responses to extract only needed fields
   - Reduces storage and transmission size

3. **Background Polling**
   - Implement background task to periodically fetch updates
   - Use `utils/background_tasks.py` infrastructure
   - Schedule: Every 5-15 minutes based on user subscriptions

4. **Database Caching**
   - Repository metadata cached in `repositories` table
   - Avoids redundant GitHub API calls for same repo
   - Automatic updates on user requests

## Security

### Access Control
- All endpoints protected with JWT authentication
- User can only track repositories within their account
- GitHub access tokens isolated per user

### Data Privacy
- Sensitive tokens stored encrypted in User model
- GitHub data (public information) stored in database
- Audit logging for all API calls

### Rate Limit Protection
- Per-endpoint rate limiting prevents abuse
- CSRF tokens on all state-changing operations
- Request correlation IDs for tracing

## Error Handling

### Common Error Scenarios

**Repository Not Found (404):**
```python
response.status_code == 404  # Use valid owner/repo format
```

**API Rate Limit Exceeded (403):**
```python
# Automatically handled with authentication
# Authenticated requests have 5000/hr limit
```

**Network Timeout:**
```python
# Logged and returned as error response
# User can retry with exponential backoff
```

**Invalid GitHub URL:**
```python
# Validated by parse_github_url()
# Returns 400 for malformed URLs
```

## Deployment

### Environment Configuration

Required settings in `settings.py`:
```python
GITHUB_CLIENT_ID = os.getenv('GITHUB_CLIENT_ID')
GITHUB_CLIENT_SECRET = os.getenv('GITHUB_CLIENT_SECRET')
GITHUB_AUTH_URL = 'https://github.com/login/oauth/authorize'
GITHUB_TOKEN_URL = 'https://github.com/login/oauth/access_token'
GITHUB_API_URL = 'https://api.github.com/user'
```

### Database Initialization

Automatic on app startup:
```python
# In app.py (line ~140)
Repository.create_table()
logger.info("Initialized repository tracking table")
```

### Testing

Run endpoints test:
```bash
pytest backend/tests/test_github_endpoints.py -v
```

## Future Enhancements

### Phase 2: Real-Time Streaming
- [ ] WebSocket support for live updates
- [ ] GitHub webhook integration
- [ ] Event subscription system
- [ ] Dashboard push notifications

### Phase 3: Advanced Analytics
- [ ] Contributor productivity metrics
- [ ] Release cycle analysis
- [ ] Merge time analytics
- [ ] Code quality trends

### Phase 4: CI/CD Integration
- [ ] Deployment status tracking
- [ ] Build artifact management
- [ ] Test coverage monitoring
- [ ] Performance regression detection

## Troubleshooting

**Q: Can't fetch repository data**
A: Check GitHub API quota, ensure valid repo URL, verify token if private repo

**Q: Rate limit errors**
A: Wait 1 hour or use authenticated token with higher limits (5000/hr)

**Q: No recent commits showing**
A: Repository might be private, ensure GitHub access token is provided

**Q: Database errors**
A: Run `Repository.create_table()` manually, check database connectivity

## Support

For issues or questions:
1. Check application logs in `backend/app.log`
2. Review GitHub API documentation: https://docs.github.com/rest
3. Check user's GitHub access token permissions
4. Verify API rate limit status at https://api.github.com/rate_limit
