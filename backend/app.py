from flask import Flask, render_template, request, redirect, send_from_directory, jsonify, send_file, url_for, session, g
import os
import shutil
import zipfile
import uuid
import logging
import subprocess
import json
import threading
import time
from datetime import datetime, timedelta
from collections import defaultdict
from pathlib import Path
import config
import google.genai as genai
from analyzer import analyze_codebase
from services.report_service import get_report_service
from services.feedback_service import get_feedback_service
from services.github_service import GitHubAPIClient, create_github_client
from models.user import User
from models.repository import Repository
from auth import auth_bp
from auth.jwt_utils import jwt_required
from utils.file_filter import should_ignore_file, should_ignore_directory
from utils.rate_limiter import rate_limit, RATE_LIMITS
from utils.csrf_protection import enable_csrf_protection
from utils.structured_logging import setup_flask_logging, setup_logging, generate_correlation_id


# Import API v2 routes
from api.v2_routes import api_v2
from api.file_issues import file_issues_bp
from api.bounty_routes import bounty_bp
from api.team_routes import team_bp

# Configure structured logging
setup_logging(
    log_file=config.LOG_FILE,
    json_format=config.FLASK_ENV == 'production',
    level=config.LOG_LEVEL
)
logger = logging.getLogger(__name__)


def cleanup_old_temp_files():
    """Clean up temporary files older than the retention period"""
    try:
        retention_hours = config.TEMP_FILE_RETENTION_HOURS
        cutoff_time = datetime.now() - timedelta(hours=retention_hours)
        
        logger.info(f"Starting cleanup of temp files older than {retention_hours} hours...")
        
        cleaned_files = 0
        cleaned_size = 0
        
        # Clean up upload folder
        for folder in [config.UPLOAD_FOLDER, config.PROCESSED_FOLDER]:
            if not os.path.exists(folder):
                continue
                
            for item in os.listdir(folder):
                item_path = os.path.join(folder, item)
                try:
                    # Get modification time
                    mod_time = datetime.fromtimestamp(os.path.getmtime(item_path))
                    
                    if mod_time < cutoff_time:
                        # Calculate size before deletion
                        if os.path.isdir(item_path):
                            size = sum(f.stat().st_size for f in Path(item_path).rglob('*') if f.is_file())
                            shutil.rmtree(item_path)
                        else:
                            size = os.path.getsize(item_path)
                            os.remove(item_path)
                        
                        cleaned_files += 1
                        cleaned_size += size
                        logger.info(f"Deleted old temp item: {item}")
                        
                except Exception as e:
                    logger.warning(f"Error cleaning up {item_path}: {e}")
        
        if cleaned_files > 0:
            cleaned_size_mb = cleaned_size / (1024 * 1024)
            logger.info(f"Cleanup complete: Removed {cleaned_files} items, freed {cleaned_size_mb:.2f} MB")
        else:
            logger.info("Cleanup complete: No old files to remove")
            
    except Exception as e:
        logger.error(f"Error during temp file cleanup: {e}", exc_info=True)

# Override Flask's Request class to set Werkzeug multipart limits
from flask import Request as FlaskRequest

class LargeUploadRequest(FlaskRequest):
    """Custom request class with increased multipart limits"""
    max_content_length = config.MAX_CONTENT_LENGTH
    max_form_memory_size = config.MAX_FORM_MEMORY_SIZE
    max_form_parts = 100000  # Increased from default 1000

app = Flask(__name__, 
            static_folder='../frontend/static',
            template_folder='../frontend/templates')
app.request_class = LargeUploadRequest  # Use custom request class
app.config['UPLOAD_FOLDER'] = str(config.UPLOAD_FOLDER)
app.config['PROCESSED_FOLDER'] = str(config.PROCESSED_FOLDER)
app.config['MAX_CONTENT_LENGTH'] = config.MAX_CONTENT_LENGTH
app.config['MAX_FORM_MEMORY_SIZE'] = config.MAX_FORM_MEMORY_SIZE  # Werkzeug multipart limit
app.config['MAX_FORM_PARTS'] = 100000  # Werkzeug 3.x: max parts in multipart upload
app.config['SECRET_KEY'] = config.SECRET_KEY

@app.route("/")
def index():
    """Root route: redirect to login if not authenticated, else to the main dashboard."""
    from auth.jwt_utils import JWTManager
    import jwt as _jwt
    token = session.get('jwt_access_token')
    if token:
        try:
            payload = JWTManager.verify_token(token)
            if not JWTManager.is_blacklisted(token):
                return redirect(url_for('index_page'))
        except Exception:
            pass
    return redirect(url_for('auth.login'))


@app.route("/dashboard", methods=['GET', 'POST'])
def index_page():
    """Main dashboard — requires authentication.
    POST requests (old form submissions without an action attr) are redirected
    to the correct upload endpoint so users get a clear error instead of a 405.
    """
    from auth.jwt_utils import JWTManager
    token = session.get('jwt_access_token')
    if not token:
        return redirect(url_for('auth.login'))
    try:
        payload = JWTManager.verify_token(token)
        if JWTManager.is_blacklisted(token):
            return redirect(url_for('auth.login'))
    except Exception:
        return redirect(url_for('auth.login'))
    if request.method == 'POST':
        # Form submitted without an action attribute — redirect to the real endpoint.
        return redirect(url_for('upload_files'), code=307)  # 307 preserves POST + body

    # Pass uid from query param or from latest analysis history
    uid = request.args.get('uid', '').strip()
    if not uid:
        try:
            history = _load_analysis_history()
            if history:
                uid = history[0].get('uid', '')
        except Exception:
            pass
    return render_template('dashboard.html', uid=uid)


@app.route("/health")
def health():
    """Early health check for quick deployment validation"""
    return {"status": "ok"}, 200


@app.route("/favicon.ico")
def favicon():
    """Serve favicon to prevent noisy 404 errors in logs"""
    favicon_path = os.path.join(app.static_folder, 'favicon.ico')
    if os.path.exists(favicon_path):
        return send_file(favicon_path, mimetype='image/vnd.microsoft.icon')
    # Return empty 204 if favicon file doesn't exist yet
    return '', 204

logger.info(f"Configured MAX_CONTENT_LENGTH: {app.config['MAX_CONTENT_LENGTH']} bytes")
logger.info(f"Configured MAX_FORM_MEMORY_SIZE: {app.config['MAX_FORM_MEMORY_SIZE']} bytes")
logger.info(f"Configured MAX_FORM_PARTS: {app.config['MAX_FORM_PARTS']}")


@app.route("/processing")
def processing_page():
    """Analysis processing/progress page — requires authentication."""
    from auth.jwt_utils import JWTManager
    token = session.get('jwt_access_token')
    if not token:
        return redirect(url_for('auth.login'))
    try:
        payload = JWTManager.verify_token(token)
        if JWTManager.is_blacklisted(token):
            return redirect(url_for('auth.login'))
    except Exception:
        return redirect(url_for('auth.login'))
    uid = request.args.get('uid', '')
    return render_template('processing.html', uid=uid)


# -----------------------------------------------------------------------
# Page routes — each nav section gets its own template
# -----------------------------------------------------------------------
def _require_auth():
    """Returns a redirect response if the user is not authenticated, else None."""
    from auth.jwt_utils import JWTManager
    token = session.get('jwt_access_token')
    if not token:
        return redirect(url_for('auth.login'))
    try:
        payload = JWTManager.verify_token(token)
        if JWTManager.is_blacklisted(token):
            return redirect(url_for('auth.login'))
    except Exception:
        return redirect(url_for('auth.login'))
    return None


@app.route("/chat")
def chat_page():
    """Workspace — combined AI Chat + Code Editor."""
    redir = _require_auth()
    if redir:
        return redir
    uid = request.args.get('uid', '').strip()
    if not uid:
        try:
            history = _load_analysis_history()
            if history:
                uid = history[0].get('uid', '')
        except Exception:
            pass
    return render_template('chat.html', uid=uid)


@app.route("/code-viewer")
def code_viewer_page():
    """Code Viewer — redirects to the unified chat/workspace with the uid."""
    redir = _require_auth()
    if redir:
        return redir
    uid = request.args.get('uid', '').strip()
    # code-viewer is now merged into chat; redirect there
    return redirect(f'/chat?uid={uid}' if uid else '/chat')


@app.route("/report/<uid>")
def report_page(uid):
    """Detailed analysis report page."""
    redir = _require_auth()
    if redir:
        return redir
    # Load report data from processed directory
    report_data = {}
    report_path = os.path.join('processed', uid, 'security_report.json')
    if os.path.exists(report_path):
        try:
            with open(report_path, 'r', encoding='utf-8') as f:
                report_data = json.load(f)
        except Exception as e:
            logger.error(f"Error loading report for {uid}: {e}")
    return render_template('report.html', uid=uid, report=report_data)


@app.route("/team")
def team_page():
    """Team management page."""
    redir = _require_auth()
    if redir:
        return redir
    return render_template('team.html')


@app.route("/download/<uid>/<path:filename>")
def download_report(uid, filename):
    """Serve downloadable report files from processed/{uid}/."""
    redir = _require_auth()
    if redir:
        return redir
    report_dir = os.path.abspath(os.path.join('processed', uid))
    return send_from_directory(report_dir, filename, as_attachment=True)



@app.route("/api/agent/status/<uid>", methods=['GET'])
def agent_status(uid):
    """Return live status for the 4-agent pipeline for the given uid."""
    status = analysis_status.get(uid)
    if status is None:
        return jsonify({'status': 'not_found', 'progress': 0}), 404
    return jsonify(dict(status)), 200


# -----------------------------------------------------------------------
# Security Report API — dashboard data endpoints
# -----------------------------------------------------------------------
def _load_security_report(uid):
    """Load security_report.json for the given uid. Returns dict or None."""
    path = os.path.join('processed', uid, 'security_report.json')
    if os.path.exists(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error reading security report for {uid}: {e}")
    return None


@app.route("/api/security/summary", methods=['GET'])
def security_summary():
    """
    Return an aggregated summary for the dashboard.
    ?uid=<uid>  — required to identify which analysis to load.
    """
    uid = request.args.get('uid', '').strip()
    if not uid:
        # Try last analysis
        try:
            if os.path.exists(ANALYSIS_HISTORY_FILE):
                with open(ANALYSIS_HISTORY_FILE, 'r') as f:
                    history = json.load(f)
                if history:
                    uid = history[0].get('uid', '')
        except Exception:
            pass

    if not uid:
        return jsonify({'total_findings': 0, 'critical_count': 0, 'high_count': 0,
                        'medium_count': 0, 'low_count': 0, 'severity_distribution': {}}), 200

    report = _load_security_report(uid)
    if not report:
        return jsonify({'total_findings': 0, 'critical_count': 0, 'high_count': 0,
                        'medium_count': 0, 'low_count': 0, 'severity_distribution': {},
                        'error': 'Report not found or still processing'}), 200

    # Build summary from security_findings list
    findings = report.get('security_findings', [])
    dist = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
    for f in findings:
        sev = (f.get('severity') or 'LOW').upper()
        dist[sev] = dist.get(sev, 0) + 1

    summary = {
        'uid': uid,
        'total_findings': len(findings),
        'critical_count': dist.get('CRITICAL', 0),
        'high_count': dist.get('HIGH', 0),
        'medium_count': dist.get('MEDIUM', 0),
        'low_count': dist.get('LOW', 0),
        'severity_distribution': dist,
        # Pass through any top-level keys the report may already have
        'overall_risk_score': report.get('overall_risk_score'),
        'scan_timestamp': report.get('scan_timestamp'),
    }
    return jsonify(summary), 200


@app.route("/api/security/findings", methods=['GET'])
def security_findings():
    """
    Return the raw security findings list for the dashboard table.
    ?uid=<uid>  — required.
    ?limit=N    — optional cap (default 50).
    """
    uid = request.args.get('uid', '').strip()
    limit = int(request.args.get('limit', 50))

    if not uid:
        try:
            if os.path.exists(ANALYSIS_HISTORY_FILE):
                with open(ANALYSIS_HISTORY_FILE, 'r') as f:
                    history = json.load(f)
                if history:
                    uid = history[0].get('uid', '')
        except Exception:
            pass

    if not uid:
        return jsonify({'findings': [], 'total': 0}), 200

    report = _load_security_report(uid)
    if not report:
        return jsonify({'findings': [], 'total': 0, 'error': 'Report not found'}), 200

    findings = report.get('security_findings', [])
    # Normalise field names for the dashboard table
    normalized = []
    for f in findings:
        normalized.append({
            'severity': f.get('severity', 'LOW'),
            'file': f.get('file_path', f.get('file', 'Unknown')),
            'title': f.get('title', f.get('type', 'Security Issue')),
            'description': f.get('description', ''),
            'line_number': f.get('line_number', 0),
            'owasp_category': f.get('owasp_category'),
        })
    return jsonify({'findings': normalized[:limit], 'total': len(normalized)}), 200


# Session configuration - prevent auto-login across server restarts
app.config['SESSION_PERMANENT'] = True           # Give cookie an expiry so it survives OAuth redirects
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 hour
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = config.FLASK_ENV == 'production'  # HTTPS only in production

# Enable CSRF protection after session config
enable_csrf_protection(app)

# Setup Flask structured logging (request tracing, correlation IDs)
setup_flask_logging(app)

# JWT is stateless — no server-side session manager needed

# Register blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(api_v2)
app.register_blueprint(file_issues_bp)
app.register_blueprint(bounty_bp)  # Bug bounty / vulnerability scanner routes
app.register_blueprint(team_bp)    # Team management routes

# Initialize database tables
Repository.create_table()
logger.info("Initialized repository tracking table")

# Initialize TeamMember table
try:
    from models.team_member import TeamMember
    TeamMember.create_table()
    logger.info("Initialized team_members table")
except Exception as _te:
    logger.warning(f"Team member DB init failed (non-fatal): {_te}")

# Shared bus registry: uid → AgentBus instance
_agent_buses: dict = {}


# -----------------------------------------------------------------------
# Template context: inject current_user from JWT stored in session
# -----------------------------------------------------------------------
class _AnonymousUser:
    """Stands in for current_user when no JWT is present."""
    is_authenticated = False
    email = None
    github_username = None
    id = None


@app.context_processor
def inject_current_user():
    """
    Make `current_user` available in all templates.
    If the access token is expired but a refresh token exists, silently renews it.
    """
    from auth.jwt_utils import JWTManager
    import jwt as _jwt

    token = session.get('jwt_access_token')
    if token:
        try:
            payload = JWTManager.verify_token(token)
            if not JWTManager.is_blacklisted(token):
                user = User.get_by_id(int(payload['sub']))
                if user:
                    return dict(current_user=user)
        except _jwt.ExpiredSignatureError:
            # Try to silently renew using the refresh token
            refresh_token = session.get('jwt_refresh_token', '')
            if refresh_token and not JWTManager.is_blacklisted(refresh_token):
                try:
                    rp = JWTManager.verify_token(refresh_token)
                    if rp.get('type') == 'refresh':
                        user = User.get_by_id(int(rp['sub']))
                        if user:
                            new_tokens = JWTManager.generate_tokens(user.id, user.email or '')
                            session['jwt_access_token'] = new_tokens['access_token']
                            session.modified = True
                            logger.info(f"context_processor: silent JWT refresh for user_id={user.id}")
                            return dict(current_user=user)
                except Exception:
                    pass
            session.pop('jwt_access_token', None)
        except Exception:
            session.pop('jwt_access_token', None)

    return dict(current_user=_AnonymousUser())

# Ensure directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['PROCESSED_FOLDER'], exist_ok=True)

# Log temp directory locations
logger.info(f"Using temporary storage at: {config.TEMP_BASE_DIR}")
logger.info(f"Upload folder: {app.config['UPLOAD_FOLDER']}")
logger.info(f"Processed folder: {app.config['PROCESSED_FOLDER']}")
logger.info(f"Temp file retention: {config.TEMP_FILE_RETENTION_HOURS} hours")

# Clean up old temporary files on startup
cleanup_old_temp_files()

# Initialize authentication database on every startup
try:
    User.init_db()
    logger.info("Authentication database initialized successfully")
except Exception as e:
    logger.error(f"Failed to initialize database: {e}")

# Analysis status tracking (in-memory)
analysis_status = defaultdict(lambda: {'status': 'pending', 'progress': 0, 'error': None})

LAST_ANALYSIS_PATH_FILE = 'last_analysis_path.txt'
ANALYSIS_HISTORY_FILE = 'analysis_history.json'
MAX_HISTORY_ENTRIES = 5


def _load_analysis_history() -> list:
    """Load the persisted analysis history list."""
    try:
        if os.path.exists(ANALYSIS_HISTORY_FILE):
            with open(ANALYSIS_HISTORY_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception as e:
        logger.warning(f"Could not load analysis history: {e}")
    return []


def _save_analysis_history(history: list):
    """Persist the analysis history list."""
    try:
        with open(ANALYSIS_HISTORY_FILE, 'w', encoding='utf-8') as f:
            json.dump(history, f, indent=2)
    except Exception as e:
        logger.error(f"Could not save analysis history: {e}")


def _record_analysis(uid: str, input_path: str, file_count: int = 0, repo_url: str = None):
    """Append a completed analysis entry to the history file."""
    try:
        history = _load_analysis_history()
        project_name = os.path.basename(input_path.rstrip('/\\')) or uid[:8]
        entry = {
            'uid': uid,
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'project_name': project_name,
            'file_count': file_count,
            'repo_url': repo_url,
        }
        # Insert newest first; trim to max entries
        history.insert(0, entry)
        history = history[:MAX_HISTORY_ENTRIES]
        _save_analysis_history(history)
        logger.info(f"Recorded analysis history for UID {uid}")
    except Exception as e:
        logger.error(f"Error recording analysis history: {e}")

def sync_results_to_dashboard(processed_path):
    """Sync analysis results to the global output directory for dashboard"""
    try:
        # Use parent directory's output when running from backend/
        global_output = os.path.join('..', 'output')
        os.makedirs(global_output, exist_ok=True)
        
        # Files to sync
        files_to_sync = ['security_report.json', 'dashboard_data.json', 'security_report.md']
        
        for filename in files_to_sync:
            src = os.path.join(processed_path, filename)
            dst = os.path.join(global_output, filename)
            if os.path.exists(src):
                shutil.copy2(src, dst)
                logger.info(f"Synced {filename} to {global_output}")
                
        # Clear report service cache to force reload
        get_report_service().clear_cache()
        
    except Exception as e:
        logger.error(f"Error syncing results to dashboard: {e}")

def save_last_analysis_path(path):
    """Save the last analyzed path for manual refresh"""
    try:
        with open(LAST_ANALYSIS_PATH_FILE, 'w') as f:
            f.write(path)
    except Exception as e:
        logger.error(f"Error saving last analysis path: {e}")

def get_last_analysis_path():
    """Get the last analyzed path"""
    try:
        if os.path.exists(LAST_ANALYSIS_PATH_FILE):
            with open(LAST_ANALYSIS_PATH_FILE, 'r') as f:
                return f.read().strip()
    except Exception as e:
        logger.error(f"Error reading last analysis path: {e}")
    return None


def generate_file_tree(base_path, relative_path=""):
    """Generate a nested dictionary representing the file structure with relative paths"""
    full_path = os.path.join(base_path, relative_path)
    item_name = os.path.basename(relative_path) if relative_path else "Project Root"
    
    tree = {'name': item_name, 'type': 'directory', 'children': []}
    
    try:
        items = sorted(os.listdir(full_path))
        for item in items:
            item_rel_path = os.path.join(relative_path, item)
            item_full_path = os.path.join(base_path, item_rel_path)
            
            if os.path.isdir(item_full_path):
                # Skip ignored directories
                if should_ignore_directory(item_full_path):
                    continue
                tree['children'].append(generate_file_tree(base_path, item_rel_path))
            else:
                # Skip ignored files
                if should_ignore_file(item_full_path):
                    continue
                tree['children'].append({
                    'name': item,
                    'type': 'file',
                    'path': item_rel_path.replace('\\', '/')  # Ensure forward slashes for web
                })
    except Exception as e:
        logger.error(f"Error generating file tree: {e}")
        
    return tree


def flatten_file_tree(tree_node, result=None):
    """Flatten nested file tree into a list of file objects for frontend"""
    if result is None:
        result = []
    
    if tree_node.get('type') == 'file':
        # Add file to result
        result.append({
            'name': tree_node['name'],
            'path': tree_node['path'],
            'type': 'file'
        })
    elif tree_node.get('type') == 'directory' and 'children' in tree_node:
        # Recursively process children
        for child in tree_node['children']:
            flatten_file_tree(child, result)
    
    return result



def extract_zip(zip_path, extract_to):
    """Extract ZIP file to directory"""
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_to)
        logger.info(f"Extracted ZIP to {extract_to}")
    except Exception as e:
        logger.error(f"Error extracting ZIP: {e}")
        raise


def run_analysis_background(input_path, output_path, uid):
    """
    4-Agent coordinated analysis pipeline.

    Agents run in parallel threads:
      SecurityAgent  (Mistral)    → OWASP / CWE findings
      QualityAgent   (Anthropic)  → code smells, tech debt
      DependencyAgent             → CVE & unpinned packages
      OrchestratorAgent (OpenAI)  → waits for all 3, merges + roadmap

    Live progress is pushed via AgentBus → analysis_status[uid].
    """
    try:
        from llm_agents.agent_bus import AgentBus
        from llm_agents.security_agent import SecurityAgent
        from llm_agents.quality_agent import QualityAgent
        from llm_agents.dependency_agent import DependencyAgent
        from llm_agents.orchestrator_agent import OrchestratorAgent

        logger.info(f"[4-Agent] Pipeline started for {uid}")
        analysis_status[uid]['status'] = 'running'
        analysis_status[uid]['progress'] = 5
        analysis_status[uid]['agent_log'] = []
        analysis_status[uid]['agents'] = {
            'security':     {'status': 'waiting', 'progress': 0},
            'quality':      {'status': 'waiting', 'progress': 0},
            'dependency':   {'status': 'waiting', 'progress': 0},
            'orchestrator': {'status': 'waiting', 'progress': 0},
        }

        # ── Step 1: Traditional codebase analysis (AST, metrics, etc.) ──────
        analysis_result = analyze_codebase(input_path, output_path)
        analysis_status[uid]['progress'] = 20
        logger.info(f"[4-Agent] Traditional analysis done for {uid}")

        # ── Step 2: Collect code content for LLM agents ──────────────────────
        code_chunks = []
        file_list = []
        for root, dirs, files in os.walk(input_path):
            dirs[:] = [d for d in dirs if d not in {
                'node_modules', '.git', '__pycache__', '.venv', 'venv', 'env', 'dist', 'build'
            }]
            for fname in files:
                if should_ignore_file(os.path.join(root, fname)):
                    continue
                fpath = os.path.join(root, fname)
                rel = os.path.relpath(fpath, input_path).replace('\\', '/')
                file_list.append(rel)
                try:
                    with open(fpath, 'r', encoding='utf-8', errors='replace') as f:
                        content = f.read()
                    if content.strip():
                        code_chunks.append(f"# === {rel} ===\n{content[:3000]}")
                except Exception:
                    pass
                if len('\n'.join(code_chunks)) > 30000:
                    break

        combined_code = '\n\n'.join(code_chunks)
        agent_context = {
            'language': 'python',
            'files': file_list,
            'project_path': input_path,
        }

        # ── Step 3: Create AgentBus ───────────────────────────────────────────
        bus = AgentBus(uid)
        _agent_buses[uid] = bus

        # Progress callback → analysis_status
        def _on_progress(agent_name, status, progress, message):
            analysis_status[uid]['agents'][agent_name] = {
                'status': status, 'progress': progress or 0, 'message': message
            }
            # Compute overall from bus
            overall = bus._overall_progress()
            # Map 0-100% of agents onto 20-90% of overall progress
            analysis_status[uid]['progress'] = 20 + int(overall * 0.70)
            analysis_status[uid]['message'] = f"[{agent_name}] {message}"
            log_entry = {'agent': agent_name, 'status': status, 'message': message}
            analysis_status[uid].setdefault('agent_log', []).append(log_entry)

        bus.register_progress_callback(_on_progress)

        # ── Step 4: Launch specialist agents in parallel ──────────────────────
        def _run_security():
            try:
                SecurityAgent().run_on_bus(combined_code, bus, agent_context)
            except Exception as e:
                logger.error(f"[SecurityAgent thread] {e}", exc_info=True)
                bus.mark_error('security', str(e))

        def _run_quality():
            # Wait briefly so security findings are available for coordination
            import time; time.sleep(2)
            try:
                QualityAgent().run_on_bus(combined_code, bus, agent_context)
            except Exception as e:
                logger.error(f"[QualityAgent thread] {e}", exc_info=True)
                bus.mark_error('quality', str(e))

        def _run_dependency():
            try:
                DependencyAgent().run_on_bus(combined_code, bus, agent_context)
            except Exception as e:
                logger.error(f"[DependencyAgent thread] {e}", exc_info=True)
                bus.mark_error('dependency', str(e))

        def _run_orchestrator():
            try:
                OrchestratorAgent().run_on_bus(combined_code, bus, agent_context)
            except Exception as e:
                logger.error(f"[OrchestratorAgent thread] {e}", exc_info=True)
                bus.mark_error('orchestrator', str(e))

        threads = [
            threading.Thread(target=_run_security, daemon=True, name=f"{uid}-security"),
            threading.Thread(target=_run_quality, daemon=True, name=f"{uid}-quality"),
            threading.Thread(target=_run_dependency, daemon=True, name=f"{uid}-dependency"),
            threading.Thread(target=_run_orchestrator, daemon=True, name=f"{uid}-orchestrator"),
        ]
        for t in threads:
            t.start()
        logger.info(f"[4-Agent] All 4 agent threads launched for {uid}")

        # ── Step 5: Wait for orchestrator to finish ───────────────────────────
        threads[-1].join(timeout=300)  # max 5 min

        # ── Step 6: Save agent results to disk ──────────────────────────────
        try:
            import json as _json
            agent_results = {
                'security': bus.read_all('security'),
                'quality': bus.read_all('quality'),
                'dependency': bus.read_all('dependency'),
                'orchestrator': bus.read_all('orchestrator'),
                'agent_log': bus.get_agent_log(),
            }
            results_path = os.path.join(output_path, 'agent_results.json')
            # Remove non-serializable keys
            safe = _json.dumps(agent_results, default=str)
            with open(results_path, 'w') as f:
                f.write(safe)
            logger.info(f"[4-Agent] Agent results saved to {results_path}")
        except Exception as e:
            logger.warning(f"[4-Agent] Could not save agent results: {e}")

        # ── Step 7: Sync and complete ─────────────────────────────────────────
        sync_results_to_dashboard(output_path)
        save_last_analysis_path(input_path)

        # Count files analyzed
        file_count = sum(1 for _ in Path(input_path).rglob('*') if _.is_file())
        _record_analysis(uid, input_path, file_count=file_count)

        analysis_status[uid]['status'] = 'complete'
        analysis_status[uid]['progress'] = 100
        logger.info(f"[4-Agent] Pipeline complete for {uid}")

    except Exception as e:
        logger.error(f"[4-Agent] Pipeline error for {uid}: {e}", exc_info=True)
        analysis_status[uid]['status'] = 'error'
        analysis_status[uid]['error'] = str(e)


# ---------------------------------------------------------------------------
# File Upload — POST /api/analyze/upload
# ---------------------------------------------------------------------------
@app.route('/api/analyze/upload', methods=['POST'])
def upload_files():
    """
    Accept multipart file uploads (individual files or a ZIP), kick off the
    4-agent analysis pipeline in a background thread, and return the uid so
    the browser can redirect to /processing?uid=<uid>.
    """
    from auth.jwt_utils import JWTManager
    import jwt as _jwt

    # Auth check
    token = session.get('jwt_access_token')
    if not token:
        return jsonify({'error': 'Authentication required'}), 401
    try:
        payload = JWTManager.verify_token(token)
        if JWTManager.is_blacklisted(token):
            return jsonify({'error': 'Session expired'}), 401
    except _jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401

    files = request.files.getlist('codebase')
    if not files or all(f.filename == '' for f in files):
        return jsonify({'error': 'No files provided'}), 400

    uid = str(uuid.uuid4())
    upload_dir   = os.path.join(app.config['UPLOAD_FOLDER'],   uid)
    processed_dir = os.path.join(app.config['PROCESSED_FOLDER'], uid)
    os.makedirs(upload_dir,    exist_ok=True)
    os.makedirs(processed_dir, exist_ok=True)

    saved_files = []
    for f in files:
        if f.filename == '':
            continue
        safe_name = os.path.basename(f.filename)
        dest = os.path.join(upload_dir, safe_name)
        f.save(dest)
        saved_files.append(dest)
        logger.info(f"Saved uploaded file: {safe_name}")

    if not saved_files:
        return jsonify({'error': 'No valid files were saved'}), 400

    # If a single ZIP was uploaded, extract it
    if len(saved_files) == 1 and saved_files[0].lower().endswith('.zip'):
        try:
            extract_zip(saved_files[0], upload_dir)
            os.remove(saved_files[0])   # remove the raw ZIP after extraction
            logger.info(f"ZIP extracted for uid {uid}")
        except Exception as e:
            logger.error(f"ZIP extraction failed for uid {uid}: {e}")
            return jsonify({'error': f'Failed to extract ZIP: {e}'}), 400

    # Start the 4-agent pipeline in the background
    analysis_status[uid] = {'status': 'pending', 'progress': 0, 'error': None}
    thread = threading.Thread(
        target=run_analysis_background,
        args=(upload_dir, processed_dir, uid),
        daemon=True,
        name=f"{uid}-pipeline"
    )
    thread.start()
    logger.info(f"Analysis pipeline started for uid {uid} with {len(saved_files)} file(s)")

    return jsonify({'uid': uid, 'status': 'started'}), 202


@app.errorhandler(404)
def not_found(error):
    """Handle 404 Not Found errors — redirect to dashboard root."""
    return redirect(url_for('index')), 302


@app.errorhandler(413)
def request_entity_too_large(error):
    """Handle file too large error"""
    max_size_mb = app.config['MAX_CONTENT_LENGTH'] / (1024 * 1024)
    return render_template('index.html', error=f"File too large. Maximum size is {int(max_size_mb)}MB"), 413


@app.errorhandler(500)
def internal_error(error):
    """Handle internal server errors"""
    logger.error(f"Internal error: {error}")
    return render_template('index.html', error="Internal server error occurred"), 500


if __name__ == '__main__':
    logger.info("Starting AI Code Review Platform...")
    # Disable auto-reload to prevent connection resets during uploads
    port = int(os.getenv('PORT', 5000)) 
    app.run(host='0.0.0.0', port=port, debug=True, use_reloader=False)
