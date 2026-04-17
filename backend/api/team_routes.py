"""
Team Management API Routes

Endpoints:
  GET  /api/team/members           — list all team members
  GET  /api/team/member/<id>       — full member profile
  POST /api/team/extract/<uid>     — auto-extract members from git commits in analyzed codebase
  POST /api/team/members           — manually add a member
  PUT  /api/team/members/<id>      — update member (role, etc.)
  DELETE /api/team/members/<id>    — remove member
  GET  /api/team/current-uid       — get current analysis UID from session

PR Security Rating algorithm:
  - Fetches PRs for the codebase repo from GitHub API
  - Filters PRs authored by this member
  - Checks if PR diffs contain known vulnerability patterns
  - Computes a score 1-10 (10 = perfectly secure PRs)
"""

import json
import logging
import os
import re
import subprocess
from datetime import datetime
from typing import Dict, List, Optional

from flask import Blueprint, jsonify, request, session, current_app

from auth.jwt_utils import jwt_required
from models.team_member import TeamMember
from services.github_service import GitHubAPIClient

logger = logging.getLogger(__name__)

team_bp = Blueprint('team', __name__)


def _resolve_upload_path(uid: str) -> str:
    """Resolve the absolute path to an uploaded project given its UID."""
    # Try app config first
    try:
        upload_folder = current_app.config.get('UPLOAD_FOLDER', 'uploads')
    except RuntimeError:
        upload_folder = 'uploads'
    # Build candidate paths — relative to CWD (backend/) and one level up
    candidates = [
        os.path.abspath(os.path.join(upload_folder, uid)),
        os.path.abspath(os.path.join('..', upload_folder, uid)),
        os.path.abspath(os.path.join(upload_folder.lstrip('/'), uid)),
    ]
    for path in candidates:
        if os.path.isdir(path):
            return path
    # Return the first candidate even if it doesn't exist (for error reporting)
    return candidates[0]

# ── Vulnerability patterns for PR security rating ──────────────────────────
VULN_PATTERNS = [
    (r'eval\s*\(', 20),           # eval() usage
    (r'exec\s*\(', 20),           # exec() usage
    (r'os\.system\s*\(', 15),     # shell injection risk
    (r'subprocess.*shell\s*=\s*True', 20),  # shell=True
    (r'pickle\.loads\s*\(', 20),  # insecure deserialization
    (r'\.format\s*\(.*request', 15), # template injection
    (r'password\s*=\s*["\'][^"\']+["\']', 25),  # hardcoded password
    (r'secret\s*=\s*["\'][^"\']+["\']', 20),    # hardcoded secret
    (r'api_key\s*=\s*["\'][^"\']+["\']', 20),   # hardcoded API key
    (r'SELECT.*\+.*request', 25), # SQL injection via concatenation
    (r'innerHTML\s*=', 10),       # XSS risk
    (r'document\.write\s*\(', 15), # XSS
]


def _compute_pr_security_rating(pr_diffs: List[str]) -> float:
    """
    Compute a 1-10 PR security rating based on vulnerability patterns in diff content.
    10 = no issues found, lower = more issues.
    """
    if not pr_diffs:
        return 7.5  # neutral when no PRs

    total_penalty = 0
    pr_count = len(pr_diffs)

    for diff in pr_diffs:
        pr_penalty = 0
        # Only check added lines (lines starting with +)
        added_lines = '\n'.join(
            line[1:]  # strip the leading +
            for line in diff.splitlines()
            if line.startswith('+') and not line.startswith('+++')
        )
        for pattern, weight in VULN_PATTERNS:
            matches = len(re.findall(pattern, added_lines, re.IGNORECASE))
            pr_penalty += matches * weight
        total_penalty += min(pr_penalty, 100)  # cap per PR at 100

    avg_penalty = total_penalty / pr_count
    rating = max(1.0, 10.0 - (avg_penalty / 10))
    return round(rating, 1)


def _extract_repo_info_from_path(project_path: str) -> Optional[Dict]:
    """Try to read .git/config to get remote origin URL."""
    try:
        git_config = os.path.join(project_path, '.git', 'config')
        if os.path.exists(git_config):
            with open(git_config, 'r') as f:
                content = f.read()
            match = re.search(r'url\s*=\s*(https://github\.com/([^/\s]+)/([^/\s\.]+))', content)
            if match:
                return {'url': match.group(1), 'owner': match.group(2), 'repo': match.group(3)}
        # Try git remote
        result = subprocess.run(
            ['git', 'remote', 'get-url', 'origin'],
            cwd=project_path, capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            url = result.stdout.strip()
            m = re.search(r'github\.com[:/]([^/]+)/([^/\s\.]+)', url)
            if m:
                return {'url': url, 'owner': m.group(1), 'repo': m.group(2).rstrip('.git')}
    except Exception as e:
        logger.debug(f"[team_routes] Could not extract repo info: {e}")
    return None


def _extract_git_commits(project_path: str) -> List[Dict]:
    """Extract commit history from the git repo in project_path."""
    commits = []

    # Check if .git directory exists
    git_dir = os.path.join(project_path, '.git')
    if not os.path.isdir(git_dir):
        logger.info(f"[team_routes] No .git directory at {project_path} — skipping git log")
        return []

    try:
        result = subprocess.run(
            ['git', 'log', '--pretty=format:%H|%an|%ae|%ai|%s', '--max-count=500'],
            cwd=project_path, capture_output=True, text=True, timeout=30,
            encoding='utf-8', errors='replace'
        )
        if result.returncode == 0 and result.stdout.strip():
            for line in result.stdout.strip().splitlines():
                parts = line.split('|', 4)
                if len(parts) >= 5:
                    commits.append({
                        'sha': parts[0][:8],
                        'author': parts[1].strip(),
                        'email': parts[2].strip(),
                        'date': parts[3].strip(),
                        'message': parts[4].strip(),
                    })
        else:
            stderr_msg = (result.stderr or '').strip()[:200]
            logger.warning(f"[team_routes] git log returned code {result.returncode}: {stderr_msg}")
    except FileNotFoundError:
        logger.warning("[team_routes] git not found in PATH")
    except subprocess.TimeoutExpired:
        logger.warning("[team_routes] git log timed out")
    except Exception as e:
        logger.warning(f"[team_routes] git log failed: {e}")
    return commits


def _github_username_from_email(email: str) -> Optional[str]:
    """
    Heuristic: try to derive a GitHub username from commit email.
    GitHub commit emails often follow: username@users.noreply.github.com
    """
    if not email:
        return None
    m = re.match(r'^(\d+\+)?([^@]+)@users\.noreply\.github\.com$', email)
    if m:
        return m.group(2)
    return None


def _fetch_github_contributors(owner: str, repo: str, gh_client) -> List[Dict]:
    """
    Fetch GitHub contributors via the GitHub API.
    Returns a list of contributor dicts with github_username, avatar_url, contributions.
    """
    contributors = []
    try:
        import requests as req
        token = gh_client.access_token if gh_client else None
        headers = {'Accept': 'application/vnd.github.v3+json'}
        if token:
            headers['Authorization'] = f'token {token}'
        url = f'https://api.github.com/repos/{owner}/{repo}/contributors?per_page=100&anon=1'
        resp = req.get(url, headers=headers, timeout=15)
        if resp.status_code == 200:
            for c in resp.json():
                if c.get('type') == 'Anonymous':
                    contributors.append({
                        'github_username': c.get('name', 'anonymous').replace(' ', '-')[:39],
                        'display_name': c.get('name', 'Anonymous'),
                        'email': c.get('email', ''),
                        'avatar_url': c.get('avatar_url', ''),
                        'contributions': c.get('contributions', 0),
                    })
                else:
                    contributors.append({
                        'github_username': c.get('login', 'unknown'),
                        'display_name': c.get('login', 'Unknown'),
                        'email': '',
                        'avatar_url': c.get('avatar_url', ''),
                        'contributions': c.get('contributions', 0),
                    })
        else:
            logger.warning(f"[team_routes] GitHub contributors API returned {resp.status_code} for {owner}/{repo}")
    except Exception as e:
        logger.warning(f"[team_routes] Failed to fetch GitHub contributors: {e}")
    return contributors


def _load_repo_url_from_metadata(uid: str) -> Optional[str]:
    """Try to read the repo_url from the analysis history JSON if stored."""
    try:
        import json as _json
        history_file = 'analysis_history.json'
        if os.path.exists(history_file):
            with open(history_file, 'r') as f:
                history = _json.load(f)
            for entry in history:
                if entry.get('uid') == uid and entry.get('repo_url'):
                    return entry['repo_url']
    except Exception:
        pass
    return None


# ────────────────────────────────────────────────────────────────────────────
# Routes
# ────────────────────────────────────────────────────────────────────────────

@team_bp.route('/api/team/members', methods=['GET'])
@jwt_required
def list_team_members():
    """List all team members scoped to the current analysis session."""
    try:
        uid = session.get('current_uid')
        if not uid:
            # No analysis has been run yet in this session
            return jsonify({
                'members': [],
                'total': 0,
                'no_analysis': True,
            }), 200
        members = TeamMember.get_all(analysis_uid=uid)
        return jsonify({
            'members': [m.to_dict() for m in members],
            'total': len(members),
            'no_analysis': False,
        }), 200
    except Exception as e:
        logger.error(f"[team] list_team_members error: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@team_bp.route('/api/team/member/<int:member_id>', methods=['GET'])
@jwt_required
def get_member_profile(member_id):
    """Get full profile for a team member."""
    try:
        member = TeamMember.get_by_id(member_id)
        if not member:
            return jsonify({'error': 'Member not found'}), 404
        return jsonify(member.to_dict()), 200
    except Exception as e:
        logger.error(f"[team] get_member_profile error: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@team_bp.route('/api/team/current-uid', methods=['GET'])
@jwt_required
def get_current_uid():
    """Return the current analysis UID stored in the user session."""
    uid = session.get('current_uid')
    return jsonify({'uid': uid}), 200


@team_bp.route('/api/team/extract/<uid>', methods=['POST'])
@jwt_required
def extract_team_from_commits(uid):
    """
    Auto-extract team members from git commit history in the analyzed codebase.
    Also fetches GitHub avatar and PR security rating if GitHub token is available.
    """
    try:
        project_path = _resolve_upload_path(uid)
        if not os.path.exists(project_path):
            return jsonify({'error': f'Project not found for UID {uid}. Upload and analyze first.'}), 404

        # Extract commits from git history
        commits = _extract_git_commits(project_path)
        if not commits:
            return jsonify({'message': 'No git history found in codebase', 'members': []}), 200

        # Group commits by author email
        author_map: Dict[str, Dict] = {}
        for commit in commits:
            email = commit['email']
            if email not in author_map:
                author_map[email] = {
                    'display_name': commit['author'],
                    'email': email,
                    'commits': [],
                    'first_commit': commit['date'],
                    'last_commit': commit['date'],
                }
            author_map[email]['commits'].append(commit)
            if commit['date'] > author_map[email]['last_commit']:
                author_map[email]['last_commit'] = commit['date']

        # Get GitHub token from current user session
        github_token = session.get('github_access_token') or os.getenv('GITHUB_TOKEN', '')
        gh_client = GitHubAPIClient(access_token=github_token) if github_token else None

        # Try to get repo info for PR rating
        repo_info = _extract_repo_info_from_path(project_path)

        # ─ Fallback: GitHub contributors API ─────────────────────────────────
        if not commits:
            logger.info(f"[team_routes] No git commits for {uid} — trying GitHub contributors API")

            # Try to resolve repo info from metadata (cloned repos store repo_url)
            if not repo_info:
                stored_url = _load_repo_url_from_metadata(uid)
                if stored_url:
                    m = re.search(r'github\.com[:/]([^/]+)/([^/\s\.]+)', stored_url)
                    if m:
                        repo_info = {'owner': m.group(1), 'repo': m.group(2).rstrip('.git'), 'url': stored_url}

            if repo_info and gh_client:
                contributors = _fetch_github_contributors(repo_info['owner'], repo_info['repo'], gh_client)
                if contributors:
                    saved_members = []
                    for c in contributors:
                        member = TeamMember(
                            github_username=c['github_username'],
                            display_name=c['display_name'],
                            email=c['email'],
                            avatar_url=c['avatar_url'] or f"https://avatars.githubusercontent.com/{c['github_username']}?size=80",
                            role='Developer',
                            commit_count=c['contributions'],
                            pr_security_rating=None,
                            analysis_uid=uid,
                        )
                        member._pr_summary_json = '[]'
                        member._commit_history_json = '[]'
                        member.save()
                        saved_members.append(member.to_dict())
                    return jsonify({
                        'message': f'Extracted {len(saved_members)} contributors from GitHub API',
                        'members': saved_members,
                        'total': len(saved_members),
                        'source': 'github_contributors',
                    }), 200
            elif repo_info:
                return jsonify({
                    'message': 'No git history found and no GitHub token — connect GitHub to fetch contributors',
                    'hint': 'Connect your GitHub account in the profile menu to enable contributor extraction',
                    'members': [], 'total': 0,
                }), 200
            else:
                return jsonify({
                    'message': 'No git history found in this codebase. For uploaded ZIP files without .git history, provide a GitHub repo URL instead.',
                    'hint': 'Use the Remote Repository option on the home page to analyze a GitHub repo and get team data.',
                    'members': [], 'total': 0,
                }), 200
        # Process git commit authors (reached only if commits exist)
        saved_members = []
        for email, author_data in author_map.items():
            # Try to derive GitHub username
            gh_username = _github_username_from_email(email)
            if not gh_username:
                # Use display name as slug
                gh_username = re.sub(r'[^a-zA-Z0-9\-]', '-', author_data['display_name'].lower())[:39]

            # Fetch GitHub avatar
            avatar_url = f"https://avatars.githubusercontent.com/{gh_username}?size=80"

            # Fetch PR security rating if we have GitHub client and repo info
            pr_security_rating = None
            pr_summary = []
            if gh_client and repo_info:
                try:
                    prs = gh_client.get_pull_requests(
                        repo_info['owner'], repo_info['repo'],
                        state='all', limit=50
                    ) or []
                    # Filter PRs by this author
                    author_prs = [pr for pr in prs if pr.get('author', '').lower() == gh_username.lower()]
                    if author_prs:
                        # Fetch diff for each PR to compute rating
                        diffs = []
                        for pr in author_prs[:10]:
                            try:
                                diff_url = f"https://api.github.com/repos/{repo_info['owner']}/{repo_info['repo']}/pulls/{pr['number']}"
                                import requests as req
                                resp = req.get(diff_url,
                                    headers={**gh_client.headers, 'Accept': 'application/vnd.github.v3.diff'},
                                    timeout=10)
                                if resp.status_code == 200:
                                    diffs.append(resp.text[:5000])
                            except Exception:
                                pass
                        if diffs:
                            pr_security_rating = _compute_pr_security_rating(diffs)
                        pr_summary = [{
                            'number': pr['number'],
                            'title': pr['title'],
                            'state': pr['state'],
                            'url': pr['url'],
                            'created_at': pr['created_at'],
                        } for pr in author_prs[:20]]
                except Exception as e:
                    logger.warning(f"[team] PR fetch failed for {gh_username}: {e}")

            commit_history_data = [{
                'sha': c['sha'],
                'message': c['message'][:80],
                'date': c['date'],
            } for c in author_data['commits'][:30]]

            # Parse last_commit as datetime
            try:
                last_commit_dt = datetime.fromisoformat(author_data['last_commit'].replace('Z', '+00:00'))
            except Exception:
                last_commit_dt = None

            member = TeamMember(
                github_username=gh_username,
                display_name=author_data['display_name'],
                email=email,
                avatar_url=avatar_url,
                role='Developer',
                commit_count=len(author_data['commits']),
                pr_security_rating=pr_security_rating,
                last_commit_at=last_commit_dt,
                analysis_uid=uid,
            )
            member._pr_summary_json = json.dumps(pr_summary)
            member._commit_history_json = json.dumps(commit_history_data)
            member.save()
            saved_members.append(member.to_dict())

        return jsonify({
            'message': f'Extracted {len(saved_members)} team members from commit history',
            'members': saved_members,
            'total': len(saved_members),
        }), 200

    except Exception as e:
        logger.error(f"[team] extract_team error: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@team_bp.route('/api/team/members', methods=['POST'])
@jwt_required
def add_team_member():
    """Manually add a team member by GitHub username."""
    try:
        data = request.json or {}
        gh_username = (data.get('github_username') or '').strip()
        if not gh_username:
            return jsonify({'error': 'github_username is required'}), 400

        # Check if already exists
        existing = TeamMember.get_by_username(gh_username)
        if existing:
            return jsonify({'message': 'Member already exists', 'member': existing.to_dict()}), 200

        member = TeamMember(
            github_username=gh_username,
            display_name=data.get('display_name', gh_username),
            email=data.get('email', ''),
            role=data.get('role', 'Developer'),
            avatar_url=f"https://avatars.githubusercontent.com/{gh_username}?size=80",
            analysis_uid=session.get('current_uid'),
        )
        member.save()
        return jsonify({'message': 'Member added', 'member': member.to_dict()}), 201

    except Exception as e:
        logger.error(f"[team] add_team_member error: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@team_bp.route('/api/team/members/<int:member_id>', methods=['PUT'])
@jwt_required
def update_team_member(member_id):
    """Update a team member's role or display name."""
    try:
        member = TeamMember.get_by_id(member_id)
        if not member:
            return jsonify({'error': 'Member not found'}), 404
        data = request.json or {}
        if 'display_name' in data:
            member.display_name = data['display_name']
        if 'role' in data:
            member.role = data['role']
        member.save()
        return jsonify({'message': 'Updated', 'member': member.to_dict()}), 200
    except Exception as e:
        logger.error(f"[team] update error: {e}")
        return jsonify({'error': str(e)}), 500


@team_bp.route('/api/team/members/<int:member_id>', methods=['DELETE'])
@jwt_required
def delete_team_member(member_id):
    """Remove a team member."""
    try:
        deleted = TeamMember.delete(member_id)
        if not deleted:
            return jsonify({'error': 'Member not found'}), 404
        return jsonify({'message': 'Member removed'}), 200
    except Exception as e:
        logger.error(f"[team] delete error: {e}")
        return jsonify({'error': str(e)}), 500
