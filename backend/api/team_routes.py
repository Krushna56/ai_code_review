"""
Team Management API Routes

Endpoints:
  GET  /api/team/members           — list all team members
  GET  /api/team/member/<id>       — full member profile
  POST /api/team/extract/<uid>     — auto-extract members from git commits in analyzed codebase
  POST /api/team/members           — manually add a member
  PUT  /api/team/members/<id>      — update member (role, etc.)
  DELETE /api/team/members/<id>    — remove member

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

from flask import Blueprint, jsonify, request, session

from auth.jwt_utils import jwt_required
from models.team_member import TeamMember
from services.github_service import GitHubAPIClient

logger = logging.getLogger(__name__)

team_bp = Blueprint('team', __name__)

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
    try:
        result = subprocess.run(
            ['git', 'log', '--pretty=format:%H|%an|%ae|%ai|%s', '--max-count=200'],
            cwd=project_path, capture_output=True, text=True, timeout=15
        )
        if result.returncode == 0:
            for line in result.stdout.strip().splitlines():
                parts = line.split('|', 4)
                if len(parts) >= 5:
                    commits.append({
                        'sha': parts[0][:8],
                        'author': parts[1],
                        'email': parts[2],
                        'date': parts[3],
                        'message': parts[4],
                    })
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


# ────────────────────────────────────────────────────────────────────────────
# Routes
# ────────────────────────────────────────────────────────────────────────────

@team_bp.route('/api/team/members', methods=['GET'])
@jwt_required
def list_team_members():
    """List all team members with their stats."""
    try:
        members = TeamMember.get_all()
        return jsonify({
            'members': [m.to_dict() for m in members],
            'total': len(members),
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


@team_bp.route('/api/team/extract/<uid>', methods=['POST'])
@jwt_required
def extract_team_from_commits(uid):
    """
    Auto-extract team members from git commit history in the analyzed codebase.
    Also fetches GitHub avatar and PR security rating if GitHub token is available.
    """
    try:
        project_path = os.path.join('uploads', uid)
        if not os.path.exists(project_path):
            return jsonify({'error': 'Project not found. Upload and analyze first.'}), 404

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
