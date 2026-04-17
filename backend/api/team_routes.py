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
<<<<<<< HEAD
            analysis_uid=session.get('current_uid'),
=======
>>>>>>> 50b420b4620be03ea149dc44fc325e539a565625
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
