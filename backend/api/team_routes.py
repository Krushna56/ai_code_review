"""
Team Management API Routes

Endpoints:
  GET  /api/team/members           — list all team members (scoped to session uid)
  GET  /api/team/member/<id>       — full member profile
  POST /api/team/extract/<uid>     — auto-extract members from git commits in analyzed codebase
  POST /api/team/members           — manually add a member
  PUT  /api/team/members/<id>      — update member (role, etc.)
  DELETE /api/team/members/<id>    — remove member
  GET  /api/team/current-uid       — get current analysis UID from session
"""

import os
import re
import json
import logging
import subprocess
from datetime import datetime
from typing import Dict, List, Optional

from flask import Blueprint, request, jsonify, session, current_app, g

from auth.jwt_utils import jwt_required
from models.team_member import TeamMember
from services.github_service import GitHubAPIClient

logger = logging.getLogger(__name__)

team_bp = Blueprint('team', __name__)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _resolve_upload_path(uid: str) -> str:
    """Resolve the absolute path to an uploaded project given its UID."""
    try:
        upload_folder = current_app.config.get('UPLOAD_FOLDER', 'uploads')
    except RuntimeError:
        upload_folder = 'uploads'
    candidates = [
        os.path.abspath(os.path.join(upload_folder, uid)),
        os.path.abspath(os.path.join('..', upload_folder, uid)),
        os.path.abspath(os.path.join(upload_folder.lstrip('/'), uid)),
    ]
    for path in candidates:
        if os.path.isdir(path):
            return path
    return candidates[0]


def _extract_git_commits(project_path: str) -> List[Dict]:
    """Run git log on the project path and return a list of commit dicts."""
    commits = []
    try:
        result = subprocess.run(
            ['git', 'log', '--pretty=format:%H|%an|%ae|%aI|%s', '--no-merges', '-n', '500'],
            cwd=project_path,
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
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
            logger.warning(
                f"[team_routes] GitHub contributors API returned {resp.status_code} for {owner}/{repo}"
            )
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


def _extract_repo_info_from_path(project_path: str) -> Optional[Dict]:
    """Try to detect GitHub owner/repo from the .git remote URL."""
    try:
        result = subprocess.run(
            ['git', 'remote', 'get-url', 'origin'],
            cwd=project_path, capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            url = result.stdout.strip()
            m = re.search(r'github\.com[:/]([^/]+)/([^/\s\.]+)', url)
            if m:
                return {
                    'owner': m.group(1),
                    'repo': m.group(2).rstrip('.git'),
                    'url': url,
                }
    except Exception:
        pass
    return None


def _compute_pr_security_rating(diffs: List[str]) -> float:
    """Simple heuristic security rating 1-10 based on diff content."""
    score = 8.0
    bad_patterns = [
        r'eval\(', r'exec\(', r'subprocess\.call', r'os\.system',
        r'password\s*=\s*["\']', r'secret\s*=\s*["\']', r'sql\s*\+\s*',
        r'innerHTML\s*=', r'document\.write\(',
    ]
    for diff in diffs:
        for pat in bad_patterns:
            if re.search(pat, diff, re.IGNORECASE):
                score -= 0.5
    return max(1.0, min(10.0, round(score, 1)))


# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────

@team_bp.route('/api/team/members', methods=['GET'])
@jwt_required
def list_team_members():
    """List team members scoped to the current analysis session."""
    try:
        uid = session.get('current_uid')

        # No active analysis session — return sentinel so frontend shows "no analysis" state
        if not uid:
            return jsonify({
                'no_analysis': True,
                'members': [],
                'total': 0,
                'message': 'No active analysis session. Run an analysis first.',
            }), 200

        members = TeamMember.get_all(analysis_uid=uid)
        return jsonify({
            'members': [m.to_dict() for m in members],
            'total': len(members),
            'analysis_uid': uid,
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
def extract_team(uid):
    """Auto-extract team members from git commit history for the given analysis UID."""
    try:
        # Store uid in session so subsequent GET /api/team/members is scoped
        session['current_uid'] = uid
        session.modified = True

        project_path = _resolve_upload_path(uid)
        if not os.path.isdir(project_path):
            return jsonify({'error': f'Analysis project not found for UID: {uid}'}), 404

        # Extract commits from git history
        commits = _extract_git_commits(project_path)

        # Get GitHub token from current user session
        github_token = session.get('github_access_token') or os.getenv('GITHUB_TOKEN', '')
        gh_client = GitHubAPIClient(access_token=github_token) if github_token else None

        # Try to get repo info for PR rating
        repo_info = _extract_repo_info_from_path(project_path)

        # ── Fallback: GitHub contributors API ────────────────────────────────
        if not commits:
            logger.info(f"[team_routes] No git commits for {uid} — trying GitHub contributors API")

            if not repo_info:
                stored_url = _load_repo_url_from_metadata(uid)
                if stored_url:
                    m = re.search(r'github\.com[:/]([^/]+)/([^/\s\.]+)', stored_url)
                    if m:
                        repo_info = {
                            'owner': m.group(1),
                            'repo': m.group(2).rstrip('.git'),
                            'url': stored_url,
                        }

            if repo_info and gh_client:
                contributors = _fetch_github_contributors(
                    repo_info['owner'], repo_info['repo'], gh_client
                )
                if contributors:
                    saved_members = []
                    for c in contributors:
                        member = TeamMember(
                            github_username=c['github_username'],
                            display_name=c['display_name'],
                            email=c['email'],
                            avatar_url=c['avatar_url'] or (
                                f"https://avatars.githubusercontent.com/{c['github_username']}?size=80"
                            ),
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
                    'message': (
                        'No git history found in this codebase. '
                        'For uploaded ZIP files without .git history, provide a GitHub repo URL instead.'
                    ),
                    'hint': 'Use the Remote Repository option on the home page to analyze a GitHub repo and get team data.',
                    'members': [], 'total': 0,
                }), 200

        # ── Process git commit authors ────────────────────────────────────────
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

        saved_members = []
        for email, author_data in author_map.items():
            gh_username = _github_username_from_email(email)
            if not gh_username:
                gh_username = re.sub(r'[^a-zA-Z0-9\-]', '-', author_data['display_name'].lower())[:39]

            avatar_url = f"https://avatars.githubusercontent.com/{gh_username}?size=80"

            pr_security_rating = None
            pr_summary = []
            if gh_client and repo_info:
                try:
                    prs = gh_client.get_pull_requests(
                        repo_info['owner'], repo_info['repo'],
                        state='all', limit=50
                    ) or []
                    author_prs = [pr for pr in prs if pr.get('author', '').lower() == gh_username.lower()]
                    if author_prs:
                        diffs = []
                        for pr in author_prs[:10]:
                            try:
                                diff_url = (
                                    f"https://api.github.com/repos/{repo_info['owner']}"
                                    f"/{repo_info['repo']}/pulls/{pr['number']}"
                                )
                                import requests as req
                                resp = req.get(
                                    diff_url,
                                    headers={**gh_client.headers, 'Accept': 'application/vnd.github.v3.diff'},
                                    timeout=10,
                                )
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

            try:
                last_commit_dt = datetime.fromisoformat(
                    author_data['last_commit'].replace('Z', '+00:00')
                )
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
