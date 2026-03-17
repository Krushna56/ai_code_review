"""
GitHub API Integration Service

Provides real-time GitHub repository monitoring, commit status tracking,
and webhook integration for live updates.
"""

import requests
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
import re
from functools import lru_cache

logger = logging.getLogger(__name__)


class GitHubAPIClient:
    """GitHub API client for fetching repository and commit data"""
    
    def __init__(self, access_token: Optional[str] = None):
        """
        Initialize GitHub API client
        
        Args:
            access_token: User's GitHub access token (optional - limited API calls without it)
        """
        self.access_token = access_token
        self.base_url = "https://api.github.com"
        self.headers = self._get_headers()
    
    def _get_headers(self) -> Dict[str, str]:
        """Get request headers with authentication if available"""
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "AICodeReview"
        }
        if self.access_token:
            headers["Authorization"] = f"token {self.access_token}"
        return headers
    
    @staticmethod
    def parse_github_url(url: str) -> Optional[Dict[str, str]]:
        """
        Parse GitHub repository URL
        
        Args:
            url: GitHub URL (https://github.com/owner/repo or git@github.com:owner/repo)
            
        Returns:
            Dict with 'owner' and 'repo' keys, or None if invalid
        """
        # Match https://github.com/owner/repo
        https_match = re.match(r'https://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$', url)
        if https_match:
            return {'owner': https_match.group(1), 'repo': https_match.group(2)}
        
        # Match git@github.com:owner/repo.git
        ssh_match = re.match(r'git@github\.com:([^/]+)/([^/]+?)(?:\.git)?$', url)
        if ssh_match:
            return {'owner': ssh_match.group(1), 'repo': ssh_match.group(2)}
        
        return None
    
    def get_repo_info(self, owner: str, repo: str) -> Optional[Dict[str, Any]]:
        """
        Get repository information
        
        Args:
            owner: Repository owner
            repo: Repository name
            
        Returns:
            Repository metadata or None if not found
        """
        try:
            url = f"{self.base_url}/repos/{owner}/{repo}"
            response = requests.get(url, headers=self.headers, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            return {
                'name': data.get('name'),
                'full_name': data.get('full_name'),
                'description': data.get('description'),
                'url': data.get('html_url'),
                'stars': data.get('stargazers_count', 0),
                'forks': data.get('forks_count', 0),
                'watchers': data.get('watchers_count', 0),
                'language': data.get('language'),
                'created_at': data.get('created_at'),
                'updated_at': data.get('updated_at'),
                'default_branch': data.get('default_branch'),
                'is_private': data.get('private'),
            }
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching repo info for {owner}/{repo}: {e}")
            return None
    
    def get_latest_commits(self, owner: str, repo: str, branch: str = 'main', 
                          limit: int = 10) -> Optional[List[Dict[str, Any]]]:
        """
        Get latest commits from a repository
        
        Args:
            owner: Repository owner
            repo: Repository name
            branch: Branch name (default: main)
            limit: Number of commits to fetch (max 100, default 10)
            
        Returns:
            List of commits or None if error
        """
        try:
            url = f"{self.base_url}/repos/{owner}/{repo}/commits"
            params = {
                'sha': branch,
                'per_page': min(limit, 100),
                'page': 1
            }
            response = requests.get(url, headers=self.headers, params=params, timeout=10)
            response.raise_for_status()
            
            commits = []
            for commit in response.json():
                commits.append({
                    'sha': commit['sha'],
                    'message': commit['commit']['message'],
                    'author': commit['commit']['author']['name'],
                    'author_email': commit['commit']['author']['email'],
                    'author_avatar': commit['author']['avatar_url'] if commit['author'] else None,
                    'date': commit['commit']['author']['date'],
                    'url': commit['html_url'],
                    'author_github': commit['author']['login'] if commit['author'] else None,
                })
            
            return commits
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching commits for {owner}/{repo}: {e}")
            return None
    
    def get_commit_status(self, owner: str, repo: str, sha: str) -> Optional[Dict[str, Any]]:
        """
        Get commit status (check runs, CI/CD)
        
        Args:
            owner: Repository owner
            repo: Repository name
            sha: Commit SHA
            
        Returns:
            Commit status info or None if error
        """
        try:
            url = f"{self.base_url}/repos/{owner}/{repo}/commits/{sha}/status"
            response = requests.get(url, headers=self.headers, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            return {
                'state': data.get('state'),  # success, failure, pending, error
                'total_count': data.get('total_count', 0),
                'statuses': [
                    {
                        'state': status.get('state'),
                        'context': status.get('context'),
                        'description': status.get('description'),
                        'url': status.get('target_url'),
                        'created_at': status.get('created_at'),
                    }
                    for status in data.get('statuses', [])
                ]
            }
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching commit status for {owner}/{repo}/{sha}: {e}")
            return None
    
    def get_check_runs(self, owner: str, repo: str, ref: str) -> Optional[List[Dict[str, Any]]]:
        """
        Get check runs for a commit (GitHub Actions)
        
        Args:
            owner: Repository owner
            repo: Repository name
            ref: Commit SHA or branch name
            
        Returns:
            List of check runs or None if error
        """
        try:
            url = f"{self.base_url}/repos/{owner}/{repo}/commits/{ref}/check-runs"
            headers = self.headers.copy()
            headers["Accept"] = "application/vnd.github.v3+json"
            
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            check_runs = []
            
            for run in data.get('check_runs', []):
                check_runs.append({
                    'id': run['id'],
                    'name': run['name'],
                    'status': run['status'],  # queued, in_progress, completed
                    'conclusion': run['conclusion'],  # success, failure, neutral, cancelled, timed_out, action_required
                    'started_at': run['started_at'],
                    'completed_at': run['completed_at'],
                    'url': run['html_url'],
                    'app_name': run['app']['name'] if run.get('app') else None,
                })
            
            return check_runs
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching check runs for {owner}/{repo}/{ref}: {e}")
            return None
    
    def get_pull_requests(self, owner: str, repo: str, state: str = 'open',
                         limit: int = 10) -> Optional[List[Dict[str, Any]]]:
        """
        Get pull requests
        
        Args:
            owner: Repository owner
            repo: Repository name
            state: 'open', 'closed', or 'all' (default: open)
            limit: Number of PRs to fetch (max 100, default 10)
            
        Returns:
            List of pull requests or None if error
        """
        try:
            url = f"{self.base_url}/repos/{owner}/{repo}/pulls"
            params = {
                'state': state,
                'per_page': min(limit, 100),
                'sort': 'updated',
                'direction': 'desc',
            }
            response = requests.get(url, headers=self.headers, params=params, timeout=10)
            response.raise_for_status()
            
            prs = []
            for pr in response.json():
                prs.append({
                    'id': pr['id'],
                    'number': pr['number'],
                    'title': pr['title'],
                    'state': pr['state'],
                    'author': pr['user']['login'],
                    'author_avatar': pr['user']['avatar_url'],
                    'created_at': pr['created_at'],
                    'updated_at': pr['updated_at'],
                    'url': pr['html_url'],
                    'additions': pr['additions'],
                    'deletions': pr['deletions'],
                    'changed_files': pr['changed_files'],
                })
            
            return prs
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching PRs for {owner}/{repo}: {e}")
            return None
    
    def get_release_info(self, owner: str, repo: str) -> Optional[Dict[str, Any]]:
        """
        Get latest release information
        
        Args:
            owner: Repository owner
            repo: Repository name
            
        Returns:
            Release info or None if error/no releases
        """
        try:
            url = f"{self.base_url}/repos/{owner}/{repo}/releases/latest"
            response = requests.get(url, headers=self.headers, timeout=10)
            
            if response.status_code == 404:
                return None  # No releases
            
            response.raise_for_status()
            
            data = response.json()
            return {
                'tag': data['tag_name'],
                'name': data['name'],
                'body': data['body'],
                'author': data['author']['login'],
                'created_at': data['created_at'],
                'published_at': data['published_at'],
                'prerelease': data['prerelease'],
                'draft': data['draft'],
                'url': data['html_url'],
            }
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching release info for {owner}/{repo}: {e}")
            return None
    
    def get_branches(self, owner: str, repo: str, limit: int = 20) -> Optional[List[Dict[str, str]]]:
        """
        Get repository branches
        
        Args:
            owner: Repository owner
            repo: Repository name
            limit: Number of branches to fetch (default 20)
            
        Returns:
            List of branches or None if error
        """
        try:
            url = f"{self.base_url}/repos/{owner}/{repo}/branches"
            params = {'per_page': min(limit, 100)}
            response = requests.get(url, headers=self.headers, params=params, timeout=10)
            response.raise_for_status()
            
            branches = []
            for branch in response.json():
                branches.append({
                    'name': branch['name'],
                    'commit_sha': branch['commit']['sha'],
                    'commit_url': branch['commit']['url'],
                    'protected': branch['protected'],
                })
            
            return branches
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching branches for {owner}/{repo}: {e}")
            return None
    
    def get_contributors(self, owner: str, repo: str, limit: int = 10) -> Optional[List[Dict[str, Any]]]:
        """
        Get top contributors
        
        Args:
            owner: Repository owner
            repo: Repository name
            limit: Number of contributors (default 10)
            
        Returns:
            List of contributors or None if error
        """
        try:
            url = f"{self.base_url}/repos/{owner}/{repo}/contributors"
            params = {'per_page': min(limit, 100)}
            response = requests.get(url, headers=self.headers, params=params, timeout=10)
            response.raise_for_status()
            
            contributors = []
            for contributor in response.json():
                contributors.append({
                    'login': contributor['login'],
                    'avatar_url': contributor['avatar_url'],
                    'contributions': contributor['contributions'],
                    'profile_url': contributor['html_url'],
                })
            
            return contributors
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching contributors for {owner}/{repo}: {e}")
            return None
    
    def get_repo_stats(self, owner: str, repo: str) -> Optional[Dict[str, Any]]:
        """
        Get comprehensive repository statistics
        
        Args:
            owner: Repository owner
            repo: Repository name
            
        Returns:
            Repository statistics or None if error
        """
        try:
            # Fetch all data in parallel would be better, but let's do it sequentially for now
            repo_info = self.get_repo_info(owner, repo)
            if not repo_info:
                return None
            
            latest_commits = self.get_latest_commits(owner, repo, limit=5)
            latest_release = self.get_release_info(owner, repo)
            contributors = self.get_contributors(owner, repo, limit=5)
            branches = self.get_branches(owner, repo, limit=10)
            prs = self.get_pull_requests(owner, repo, state='open', limit=5)
            
            # Get commit status for latest commit if available
            commit_status = None
            if latest_commits and len(latest_commits) > 0:
                latest_sha = latest_commits[0]['sha']
                commit_status = self.get_commit_status(owner, repo, latest_sha)
                # Also get check runs
                check_runs = self.get_check_runs(owner, repo, latest_sha)
                if check_runs:
                    commit_status['check_runs'] = check_runs
            
            return {
                'repo_info': repo_info,
                'latest_commits': latest_commits,
                'commit_status': commit_status,
                'latest_release': latest_release,
                'contributors': contributors,
                'branches': branches,
                'pull_requests': prs,
                'fetched_at': datetime.utcnow().isoformat(),
            }
        except Exception as e:
            logger.error(f"Error getting repo stats for {owner}/{repo}: {e}")
            return None


def create_github_client(access_token: Optional[str] = None) -> GitHubAPIClient:
    """Factory function to create GitHub API client"""
    return GitHubAPIClient(access_token)
