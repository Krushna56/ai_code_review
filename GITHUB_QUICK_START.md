# Real-Time GitHub Integration - Quick Start Guide

## 🚀 What's New?

Your AI Code Review Platform now has **real-time GitHub integration**! The dashboard can display live repository data including commits, CI/CD status, contributors, and more.

---

## 📋 Quick Reference

### Base URL
```
http://localhost:5000
```

### Authentication
All endpoints require a valid JWT token:
```
Authorization: Bearer <your-jwt-token>
```

---

## 📊 API Endpoints

### 1️⃣ Get Repository Information
```bash
curl -X GET "http://localhost:5000/api/github/repo-info/microsoft/vscode" \
  -H "Authorization: Bearer TOKEN"
```

**Response:**
```json
{
  "url": "https://github.com/microsoft/vscode",
  "name": "vscode",
  "description": "Visual Studio Code",
  "stars": 150000,
  "forks": 25000,
  "language": "TypeScript",
  "created_at": "2015-04-29T...",
  "updated_at": "2026-03-10T..."
}
```

### 2️⃣ Get Latest Commits
```bash
curl -X GET "http://localhost:5000/api/github/commits/microsoft/vscode?branch=main&limit=10" \
  -H "Authorization: Bearer TOKEN"
```

**Response:**
```json
{
  "commits": [
    {
      "sha": "abc123...",
      "message": "Fix bug in editor",
      "author": {
        "name": "Developer",
        "email": "dev@example.com",
        "avatar_url": "https://..."
      },
      "created_at": "2026-03-10T14:30:00Z",
      "url": "https://github.com/.../commit/abc123"
    }
  ],
  "count": 10
}
```

### 3️⃣ Get Commit Status (CI/CD)
```bash
curl -X GET "http://localhost:5000/api/github/commit-status/microsoft/vscode/abc123def456" \
  -H "Authorization: Bearer TOKEN"
```

**Response:**
```json
{
  "status": {
    "state": "success",
    "description": "All checks passed",
    "url": "https://github.com/..."
  },
  "check_runs": [
    {
      "name": "Unit Tests",
      "status": "completed",
      "conclusion": "success"
    },
    {
      "name": "Build",
      "status": "completed",
      "conclusion": "success"
    }
  ]
}
```

### 4️⃣ Get Repository Statistics
```bash
curl -X GET "http://localhost:5000/api/github/stats/microsoft/vscode" \
  -H "Authorization: Bearer TOKEN"
```

**Response:** (Comprehensive data combining all above)
```json
{
  "url": "https://github.com/microsoft/vscode",
  "stars": 150000,
  "latest_commit": {...},
  "commit_status": {...},
  "pull_requests": {
    "open": 250,
    "closed": 5000,
    "merged": 4800
  },
  "contributors": [...],
  "latest_release": {...},
  "branches": [...]
}
```

### 5️⃣ Get Your Tracked Repositories
```bash
curl -X GET "http://localhost:5000/api/github/user-repos?limit=50" \
  -H "Authorization: Bearer TOKEN"
```

**Response:**
```json
{
  "repositories": [
    {
      "id": 1,
      "repo_url": "https://github.com/microsoft/vscode",
      "owner": "microsoft",
      "repo_name": "vscode",
      "stars": 150000,
      "language": "TypeScript",
      "created_at": "2026-03-10T..."
    }
  ],
  "count": 1
}
```

### 6️⃣ Track a New Repository
```bash
curl -X POST "http://localhost:5000/api/github/track-repo" \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "https://github.com/microsoft/vscode"}'
```

**Response:**
```json
{
  "message": "Repository added to tracking",
  "repository": {
    "id": 1,
    "repo_url": "https://github.com/microsoft/vscode",
    "owner": "microsoft",
    "repo_name": "vscode",
    "description": "Visual Studio Code",
    "language": "TypeScript",
    "stars": 150000,
    "github_data": {...}
  }
}
```

---

## 💡 Usage Examples

### Python Example
```python
import requests
import json

# Set your JWT token
TOKEN = "your-jwt-token-here"
headers = {"Authorization": f"Bearer {TOKEN}"}

# Get repository info
response = requests.get(
    "http://localhost:5000/api/github/repo-info/python/cpython",
    headers=headers
)
repo = response.json()

print(f"Repository: {repo['name']}")
print(f"Stars: {repo['stars']}")
print(f"Language: {repo['language']}")

# Get latest commits
response = requests.get(
    "http://localhost:5000/api/github/commits/python/cpython?limit=5",
    headers=headers
)
commits = response.json()

for commit in commits['commits']:
    print(f"\n{commit['message']}")
    print(f"  Author: {commit['author']['name']}")
    print(f"  Date: {commit['created_at']}")

# Track a repository
response = requests.post(
    "http://localhost:5000/api/github/track-repo",
    headers=headers,
    json={"repo_url": "https://github.com/python/cpython"}
)
print(f"\n{response.json()['message']}")
```

### JavaScript Example
```javascript
// Set your JWT token
const TOKEN = "your-jwt-token-here";
const headers = {
  "Authorization": `Bearer ${TOKEN}`,
  "Content-Type": "application/json"
};

// Get repository stats
async function getRepoStats() {
  const response = await fetch(
    "http://localhost:5000/api/github/stats/nodejs/node",
    { headers }
  );
  const stats = await response.json();
  
  console.log(`Repository: ${stats.name}`);
  console.log(`Stars: ${stats.stars}`);
  console.log(`Latest Commit: ${stats.latest_commit.message}`);
  console.log(`Build Status: ${stats.commit_status.state}`);
}

// Track a repository
async function trackRepo(repoUrl) {
  const response = await fetch(
    "http://localhost:5000/api/github/track-repo",
    {
      method: "POST",
      headers,
      body: JSON.stringify({ repo_url: repoUrl })
    }
  );
  const data = await response.json();
  console.log(data.message);
  return data.repository;
}

getRepoStats();
trackRepo("https://github.com/nodejs/node");
```

---

## 🔐 Authentication Setup

### Get Your GitHub Access Token (Optional)
For higher rate limits (5000/hr instead of 60/hr):

1. Go to: https://github.com/settings/tokens
2. Click "Generate new token"
3. Select scopes: `public_repo`, `repo`
4. Copy the token
5. Store in your User profile in the database

### Use in API Calls
The system automatically uses the token stored in your profile. No additional headers needed!

---

## ⚙️ Configuration

### Enable GitHub OAuth
Set these environment variables:
```bash
GITHUB_CLIENT_ID=your-client-id
GITHUB_CLIENT_SECRET=your-client-secret
```

### Personal Access Token
Add to your user profile in database:
```sql
UPDATE users SET github_access_token = 'ghp_xxxxx' WHERE id = 1;
```

---

## 📊 Dashboard Integration

### Display Latest Commit
```html
<div class="github-card">
  <h3>Latest Commit</h3>
  <p id="commit-message">Loading...</p>
  <p id="commit-author">By: <span></span></p>
  <p id="commit-date">Date: <span></span></p>
</div>

<script>
fetch('/api/github/commits/owner/repo?limit=1')
  .then(r => r.json())
  .then(data => {
    const commit = data.commits[0];
    document.getElementById('commit-message').textContent = commit.message;
    document.getElementById('commit-author').querySelector('span').textContent = commit.author.name;
    document.getElementById('commit-date').querySelector('span').textContent = commit.created_at;
  });
</script>
```

### Display CI/CD Status
```html
<div class="github-status" id="status">
  <span class="loader">Checking...</span>
</div>

<script>
fetch('/api/github/commit-status/owner/repo/sha')
  .then(r => r.json())
  .then(data => {
    const status = data.status.state;
    const icon = status === 'success' ? '✅' : status === 'failure' ? '❌' : '⏳';
    document.getElementById('status').innerHTML = `${icon} Build: ${status}`;
  });
</script>
```

---

## 🔍 Debug Mode

### Enable Detailed Logging
```python
# In backend/app.py
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Check API Response
```bash
# With verbose output
curl -v -X GET "http://localhost:5000/api/github/repo-info/owner/repo" \
  -H "Authorization: Bearer TOKEN"

# Pretty print JSON
curl -s "http://localhost:5000/api/github/repo-info/owner/repo" \
  -H "Authorization: Bearer TOKEN" | python -m json.tool
```

### Monitor Database
```sql
-- Check tracked repositories
SELECT repo_url, owner, repo_name, stars, updated_at FROM repositories;

-- Check GitHub data
SELECT repo_url, github_data FROM repositories LIMIT 1;
```

---

## ⚠️ Common Issues

### "401 Unauthorized"
- JWT token is missing or expired
- Solution: Get a new JWT token and include in Authorization header

### "403 Rate Limit Exceeded"
- GitHub API rate limit reached (60/hr without auth)
- Solution: Use GitHub personal access token for higher limits (5000/hr)

### "404 Repository Not Found"
- Repository doesn't exist or URL is incorrect
- Solution: Verify the repository exists and use correct owner/repo format

### "500 Internal Error"
- Check application logs: `backend/app.log`
- Verify database connectivity
- Ensure Repository table exists

---

## 📈 Performance Tips

### Optimize API Calls
- Use `get_repo_stats()` for comprehensive data (reduces calls)
- Cache results in frontend for 5 minutes
- Batch requests when possible

### Rate Limit Management
- Set up personal access token for 5000/hr limit
- Implement caching layer in frontend
- Poll GitHub every 5-15 minutes, not continuously

### Database Performance
- Repository data cached on first fetch
- Subsequent calls hit database (faster)
- Automatic cleanup of old data

---

## 🎯 Next Steps

1. **Get JWT Token**: Contact admin for authentication token
2. **Add GitHub Access Token**: Provide your personal access token (optional)
3. **Track Repositories**: Use `/api/github/track-repo` endpoint
4. **Integrate Dashboard**: Add widgets using `/api/github/*` endpoints
5. **Enable Auto-Refresh**: Set up polling interval (30-60 seconds)

---

## 📚 Further Reading

- [Full Integration Guide](backend/GITHUB_INTEGRATION.md)
- [GitHub API Documentation](https://docs.github.com/rest)
- [Implementation Summary](GITHUB_IMPLEMENTATION_COMPLETE.md)
- [Verification Report](VERIFICATION_REPORT.md)

---

## 🆘 Support

**For issues:**
1. Check `backend/app.log` for error details
2. Review GitHub API status: https://status.github.com
3. Check your API rate limit: https://api.github.com/rate_limit
4. Verify JWT token is valid and not expired

**All endpoints are secured with JWT authentication.**
**No endpoint requires GitHub OAuth credentials in the request.**
