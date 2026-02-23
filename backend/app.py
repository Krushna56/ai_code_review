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
import google.generativeai as genai
from code_analysis import analyze_codebase
from services.report_service import get_report_service
from services.feedback_service import get_feedback_service
from models.user import User
from auth import auth_bp
from auth.jwt_utils import jwt_required
from utils.file_filter import should_ignore_file, should_ignore_directory


# Import API v2 routes
from api.v2_routes import api_v2
from api.file_issues import file_issues_bp

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
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
    max_form_memory_size = config.MAX_CONTENT_LENGTH  
    max_form_parts = 100000  # Increased from default 1000

app = Flask(__name__, 
            static_folder='../frontend/static',
            template_folder='../frontend/templates')
app.request_class = LargeUploadRequest  # Use custom request class
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['PROCESSED_FOLDER'] = 'processed'
app.config['MAX_CONTENT_LENGTH'] = config.MAX_CONTENT_LENGTH
app.config['MAX_FORM_MEMORY_SIZE'] = config.MAX_CONTENT_LENGTH  # Werkzeug multipart limit
app.config['MAX_FORM_PARTS'] = 100000  # Werkzeug 3.x: max parts in multipart upload
app.config['SECRET_KEY'] = config.SECRET_KEY
logger.info(f"Configured MAX_CONTENT_LENGTH: {app.config['MAX_CONTENT_LENGTH']} bytes")
logger.info(f"Configured MAX_FORM_MEMORY_SIZE: {app.config['MAX_FORM_MEMORY_SIZE']} bytes")
logger.info(f"Configured MAX_FORM_PARTS: {app.config['MAX_FORM_PARTS']}")

# Session configuration - prevent auto-login across server restarts
app.config['SESSION_PERMANENT'] = True           # Give cookie an expiry so it survives OAuth redirects
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 hour
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = False      # Must be False for local http:// dev

# JWT is stateless — no server-side session manager needed

# Register blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(api_v2)
app.register_blueprint(file_issues_bp)


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

# Initialize authentication database
User.init_db()
logger.info("Authentication database initialized")

# Analysis status tracking (in-memory)
analysis_status = defaultdict(lambda: {'status': 'pending', 'progress': 0, 'error': None})

LAST_ANALYSIS_PATH_FILE = 'last_analysis_path.txt'

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
    """Run analysis in background thread"""
    try:
        logger.info(f"Background analysis started for {uid}")
        analysis_status[uid]['status'] = 'running'
        analysis_status[uid]['progress'] = 10
        
        # Run analysis
        analysis_result = analyze_codebase(input_path, output_path)
        analysis_status[uid]['progress'] = 80
        
        # Sync to dashboard
        sync_results_to_dashboard(output_path)
        save_last_analysis_path(input_path)
        analysis_status[uid]['progress'] = 90
        
        # Mark as complete
        analysis_status[uid]['status'] = 'complete'
        analysis_status[uid]['progress'] = 100
        logger.info(f"Background analysis complete for {uid}")
    except Exception as e:
        logger.error(f"Background analysis error for {uid}: {e}", exc_info=True)
        analysis_status[uid]['status'] = 'error'
        analysis_status[uid]['error'] = str(e)


@app.route('/', methods=['GET', 'POST'])
def index():
    """Main route for file upload and analysis"""
    if request.method == 'POST':
        try:
            logger.info("=== UPLOAD REQUEST RECEIVED ===")
            logger.info(f"Content-Type: {request.content_type}")
            logger.info(f"Content-Length: {request.content_length}")
            
            # Clear previous session data for new upload
            session.pop('current_uid', None)
            
            # Validate file upload
            if 'codebase' not in request.files:
                logger.warning("No file part in request")
                return render_template('index.html', error="No file uploaded")

            # Get all uploaded files (supports multiple files and folders)
            uploaded_files = request.files.getlist('codebase')
            logger.info(f"Number of files received: {len(uploaded_files)}")
            
            if not uploaded_files or all(f.filename == '' for f in uploaded_files):
                return render_template('index.html', error="No file selected")

            # Generate unique ID for this analysis
            uid = str(uuid.uuid4())
            input_path = os.path.join(app.config['UPLOAD_FOLDER'], uid)
            output_path = os.path.join(app.config['PROCESSED_FOLDER'], uid)

            os.makedirs(input_path, exist_ok=True)
            os.makedirs(output_path, exist_ok=True)

            # Save all uploaded files
            has_zip = False
            logger.info(f"Processing {len(uploaded_files)} uploaded files")
            for uploaded_file in uploaded_files:
                if uploaded_file.filename == '':
                    continue
                    
                # Preserve folder structure for folder uploads
                filename = uploaded_file.filename
                logger.info(f"Processing file: {filename}")
                
                # Create subdirectories if needed
                file_path = os.path.join(input_path, filename)
                
                # Only create parent directory if filename contains a path separator
                file_dir = os.path.dirname(file_path)
                if file_dir and file_dir != input_path:
                    os.makedirs(file_dir, exist_ok=True)
                    logger.info(f"Created directory: {file_dir}")
                
                uploaded_file.save(file_path)
                logger.info(f"Saved file: {filename} to {file_path}")
                
                # Check if any file is a ZIP
                if zipfile.is_zipfile(file_path):
                    has_zip = True
                    extract_zip(file_path, input_path)
                    logger.info(f"Extracted ZIP: {filename}")

            # Generate file tree for explorer
            file_tree = generate_file_tree(input_path)

            # Start analysis in background
            analysis_status[uid] = {'status': 'running', 'progress': 0, 'error': None}
            thread = threading.Thread(
                target=run_analysis_background,
                args=(input_path, output_path, uid)
            )
            thread.daemon = True
            thread.start()
            logger.info(f"Started background analysis for {uid}")
            
            # Store UID in session for persistence across page navigations
            session['current_uid'] = uid
            session.modified = True
            logger.info(f"Stored UID {uid} in session")

            # Redirect to processing page to show loading animation
            return redirect(f'/processing?uid={uid}')

        except Exception as e:
            logger.error(f"Error during upload: {e}", exc_info=True)
            return render_template('index.html', error=str(e),
                                   jwt_token=session.get('jwt_access_token', ''))

    return render_template('index.html', jwt_token=session.get('jwt_access_token', ''))


@app.route('/api/file/content/<uid>/<path:filepath>')
@jwt_required
def get_file_content(uid, filepath):
    """Get file content for code viewer"""
    try:
        # Handle virtual reports path
        if filepath.startswith('REPORTS/'):
            filename = filepath.split('/', 1)[1]
            base_path = os.path.join(app.config['PROCESSED_FOLDER'], uid)
            file_path = os.path.join(base_path, filename)
        else:
            base_path = os.path.join(app.config['UPLOAD_FOLDER'], uid)
            file_path = os.path.join(base_path, filepath)
        
        # Security check: prevent directory traversal
        if not os.path.abspath(file_path).startswith(os.path.abspath(base_path)):
             return jsonify({'error': 'Invalid file path'}), 403
        
        if not os.path.exists(file_path):
            return jsonify({'error': 'File not found'}), 404
        
        # Helper to check for binary files
        def is_binary_file(filename):
            binary_extensions = {
                '.pdf', '.png', '.jpg', '.jpeg', '.gif', '.ico', 
                '.zip', '.tar', '.gz', '.pyc', '.exe', '.dll', 
                '.so', '.dylib', '.bin', '.pkl', '.db', '.sqlite'
            }
            return any(filename.lower().endswith(ext) for ext in binary_extensions)

        if is_binary_file(filepath):
             return jsonify({
                 'content': '[Binary file cannot be viewed in text editor]', 
                 'language': 'plaintext',
                 'is_binary': True,
                 'path': filepath
             })

        # Read file content
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except UnicodeDecodeError:
            try:
                # Try with different encoding
                with open(file_path, 'r', encoding='latin-1') as f:
                    content = f.read()
            except Exception:
                return jsonify({
                     'content': '[File encoding not supported]', 
                     'language': 'plaintext',
                     'is_binary': True,
                     'path': filepath
                 })
        
        # Detect language from extension
        ext = filepath.split('.')[-1].lower()
        language_map = {
            'py': 'python', 'js': 'javascript', 'java': 'java', 
            'ts': 'typescript', 'tsx': 'typescript', 'jsx': 'javascript',
            'cpp': 'cpp', 'c': 'c', 'h': 'c', 'hpp': 'cpp',
            'html': 'html', 'css': 'css', 'scss': 'scss',
            'json': 'json', 'xml': 'xml', 'yaml': 'yaml', 'yml': 'yaml',
            'sh': 'bash', 'md': 'markdown', 'txt': 'plaintext',
            'sql': 'sql', 'dockerfile': 'dockerfile'
        }
        language = language_map.get(ext, 'plaintext')
        
        return jsonify({
            'content': content,
            'language': language,
            'is_binary': False,
            'path': filepath
        })
    except Exception as e:
        logger.error(f"Error reading file: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/analysis/status/<uid>')
@jwt_required
def get_analysis_status(uid):
    """Check analysis status"""
    try:
        status = analysis_status.get(uid, {'status': 'not_found'})
        return jsonify(status)
    except Exception as e:
        logger.error(f"Error getting status: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/analyze/repo', methods=['POST'])
@jwt_required
def api_analyze_repo():
    """Clone a GitHub repository and run analysis"""
    try:
        data = request.json
        if not data or 'repo_url' not in data:
            return jsonify({'error': 'No repository URL provided'}), 400

        repo_url = data['repo_url']
        logger.info(f"Cloning repository: {repo_url}")

        # Generate unique ID for this analysis
        uid = str(uuid.uuid4())
        input_path = os.path.join(app.config['UPLOAD_FOLDER'], uid)
        output_path = os.path.join(app.config['PROCESSED_FOLDER'], uid)

        os.makedirs(input_path, exist_ok=True)
        os.makedirs(output_path, exist_ok=True)

        # Clone repository
        try:
            # Add --depth 1 for faster cloning
            subprocess.run(['git', 'clone', '--depth', '1', repo_url, input_path], 
                           check=True, capture_output=True, text=True)
            logger.info(f"Cloned {repo_url} to {input_path}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Git clone failed: {e.stderr}")
            return jsonify({'error': f"Failed to clone repository: {e.stderr}"}), 500

        # Run analysis
        logger.info(f"Starting analysis for cloned repo {uid}")
        
        # Generate file tree
        file_tree = generate_file_tree(input_path)
        
        # Start analysis in background
        analysis_status[uid] = {'status': 'running', 'progress': 0, 'error': None}
        thread = threading.Thread(
            target=run_analysis_background,
            args=(input_path, output_path, uid)
        )
        thread.daemon = True
        thread.start()
        logger.info(f"Started background analysis for cloned repo {uid}")
        
        # Store UID in session
        session['current_uid'] = uid
        session.modified = True
        logger.info(f"Stored repo UID {uid} in session")
        
        # Return success with redirect to processing page
        return jsonify({
            'status': 'success',
            'message': 'Repository cloned successfully',
            'uid': uid,
            'redirect': f'/processing?uid={uid}'
        }), 200

    except Exception as e:
        logger.error(f"Error during repo analysis: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/download/<uid>/<filename>')
@jwt_required
def download_report(uid, filename):
    """Download generated reports"""
    try:
        base_path = os.path.abspath(
            os.path.join(app.config['PROCESSED_FOLDER'], uid)
        )
        file_path = os.path.abspath(os.path.join(base_path, filename))
        # Prevent path traversal via crafted filenames
        if not file_path.startswith(base_path):
            return jsonify({'error': 'Invalid file path'}), 403
        if os.path.exists(file_path):
            return send_file(file_path, as_attachment=True)
        else:
            logger.warning(f"File not found: {file_path}")
            return "File not found", 404
    except Exception as e:
        logger.error(f"Error downloading file: {e}")
        return str(e), 500


@app.route('/api/file/<uid>')
@jwt_required
def api_get_file_content(uid):
    """Get content of a specific file"""
    try:
        if 'path' not in request.args:
            return jsonify({'error': 'Path parameter required'}), 400

        rel_path = request.args.get('path')

        # Handle virtual reports path
        if rel_path.startswith('REPORTS/'):
            filename = rel_path.split('/', 1)[1]
            base_path = os.path.join(app.config['PROCESSED_FOLDER'], uid)
            file_path = os.path.join(base_path, filename)
        else:
            base_path = os.path.join(app.config['UPLOAD_FOLDER'], uid)
            file_path = os.path.join(base_path, rel_path)

        # Strict abspath-based path traversal check (consistent with get_file_content)
        if not os.path.abspath(file_path).startswith(os.path.abspath(base_path)):
            return jsonify({'error': 'Invalid file path'}), 403

        if not os.path.exists(file_path):
            return jsonify({'error': 'File not found'}), 404
             
        # Read file content
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
            
        return jsonify({'content': content, 'path': rel_path}), 200
        
    except Exception as e:
        logger.error(f"Error reading file detail: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/files/<uid>')
@jwt_required
def api_get_files(uid):
    """Get file tree structure for a given UID"""
    try:
        input_path = os.path.join(app.config['UPLOAD_FOLDER'], uid)
        
        if not os.path.exists(input_path):
            logger.warning(f"Upload path not found for UID {uid}: {input_path}")
            return jsonify({'error': 'Project not found', 'files': []}), 404
        
        # Generate file tree
        tree_structure = generate_file_tree(input_path)
        
        # Flatten to file list
        file_list = flatten_file_tree(tree_structure)

        # Include reports from processed folder
        processed_path = os.path.join(app.config['PROCESSED_FOLDER'], uid)
        if os.path.exists(processed_path):
             for item in os.listdir(processed_path):
                  if item.endswith(('.json', '.md', '.txt')):
                       file_list.append({
                            'name': f"[REPORT] {item}",
                            'path': f"REPORTS/{item}",
                            'type': 'file'
                       })
        
        logger.info(f"Returning {len(file_list)} files for UID {uid}")
        
        return jsonify({
            'uid': uid,
            'files': file_list,
            'total': len(file_list)
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting files for {uid}: {e}", exc_info=True)
        return jsonify({'error': str(e), 'files': []}), 500


@app.route('/api/analyze', methods=['POST'])
@jwt_required
def api_analyze():
    """API endpoint for programmatic access — runs analysis asynchronously"""
    try:
        if 'codebase' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400

        uploaded_file = request.files['codebase']
        if uploaded_file.filename == '':
            return jsonify({'error': 'No file selected'}), 400

        uid = str(uuid.uuid4())
        input_path = os.path.join(app.config['UPLOAD_FOLDER'], uid)
        output_path = os.path.join(app.config['PROCESSED_FOLDER'], uid)

        os.makedirs(input_path, exist_ok=True)
        os.makedirs(output_path, exist_ok=True)

        filename = uploaded_file.filename
        file_path = os.path.join(input_path, filename)
        uploaded_file.save(file_path)

        if zipfile.is_zipfile(file_path):
            extract_zip(file_path, input_path)

        # Run analysis asynchronously to avoid request timeout on large codebases
        analysis_status[uid] = {'status': 'running', 'progress': 0, 'error': None}
        thread = threading.Thread(
            target=run_analysis_background,
            args=(input_path, output_path, uid)
        )
        thread.daemon = True
        thread.start()
        logger.info(f"Started async API analysis for {uid}")

        return jsonify({
            'uid': uid,
            'status': 'queued',
            'status_url': f'/api/analysis/status/{uid}',
            'download_url': f'/download/{uid}/comprehensive_report.json'
        }), 202

    except Exception as e:
        logger.error(f"API error: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/chat')
@jwt_required
def chat():
    """Interactive chat page with optional file context"""
    # Try to get UID from URL first, then from session
    uid = request.args.get('uid') or session.get('current_uid')
    file_tree = []
    
    if uid:
        # Store/update in session for future use
        session['current_uid'] = uid
        session.modified = True
        logger.info(f"Chat route using UID: {uid} (from {'URL' if request.args.get('uid') else 'session'})")
        
        # Load file tree for the uploaded code
        input_path = os.path.join(app.config['UPLOAD_FOLDER'], uid)
        logger.info(f"Loading file tree for UID: {uid}, path: {input_path}")
        logger.info(f"Path exists: {os.path.exists(input_path)}")
        
        if os.path.exists(input_path):
            tree_structure = generate_file_tree(input_path)
            logger.info(f"Generated tree with {len(tree_structure.get('children', []))} children")
            
            file_tree = flatten_file_tree(tree_structure)
            logger.info(f"Flattened to {len(file_tree)} files")
            
            if file_tree:
                logger.info(f"Sample files: {[f['path'] for f in file_tree[:3]]}")
    else:
        logger.info("No UID provided to chat route (not in URL or session)")
    
    return render_template('chat.html', uid=uid, file_tree=file_tree)


@app.route('/processing')
def processing():
    """Processing page with loading animation"""
    uid = request.args.get('uid')
    if not uid:
        return redirect('/')
    return render_template('processing.html', uid=uid)



@app.route('/code-viewer/<uid>')
@jwt_required
def code_viewer_redirect(uid):
    """Legacy redirect for code viewer"""
    return redirect(url_for('chat', uid=uid))


@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'version': '1.0'}), 200


# ====================
# Chat Compatibility Routes
# ====================

@app.route('/api/chat/message', methods=['POST'])
def api_chat_message_compat():
    """
    Compatibility route for chat messages
    Handles legacy frontend that sends 'uid' instead of 'session_id'
    """
    try:
        from api.v2_routes import chat_engine, conversation_manager
        
        # Check if services are available
        if chat_engine is None or conversation_manager is None:
            logger.error("Chat services not initialized")
            return jsonify({'error': 'Chat service is currently unavailable. Please check server logs.'}), 503
        
        data = request.get_json()
        
        if not data or 'message' not in data:
            return jsonify({'error': 'message is required'}), 400
        
        message = data['message']
        uid = data.get('uid')
        code_context = data.get('code_context')
        
        # Handle session management
        session_id = data.get('session_id')
        
        if not session_id and uid:
            # Legacy frontend: use uid to find or create session
            # Use uid as user_id and check for existing sessions
            existing_sessions = conversation_manager.get_user_sessions(uid, active_only=True)
            
            if existing_sessions:
                # Use the most recent session
                session_id = existing_sessions[0]['session_id']
                logger.info(f"Using existing session {session_id} for uid {uid}")
            else:
                # Create a new session with uid in metadata
                session_id = chat_engine.start_session(
                    user_id=uid,
                    metadata={'uid': uid}
                )
                logger.info(f"Created new session {session_id} for uid {uid}")
        elif not session_id:
            return jsonify({'error': 'session_id or uid is required'}), 400
        
        # Call the chat engine directly
        response = chat_engine.send_message(
            session_id=session_id,
            message=message,
            code_context=code_context,
            stream=False
        )
        
        # Return response in format expected by frontend
        return jsonify({
            'response': response.get('content'),
            'message': response.get('content'),
            'tokens_used': response.get('tokens_used'),
            'intent': response.get('intent'),
            'agent': response.get('agent')
        }), 200
        
    except ValueError as e:
        logger.error(f"Chat message validation error: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        logger.error(f"Chat message error: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/api/query', methods=['POST'])
@jwt_required
def api_query():
    """API endpoint for natural language security queries"""
    try:
        data = request.get_json()
        if not data or 'question' not in data:
            return jsonify({'error': 'No question provided'}), 400

        question = data['question']
        max_results = data.get('max_results', 5)

        logger.info(f"API query: {question}")

        # Import here to avoid circular dependencies
        from query.query_handler import QueryHandler
        from indexing.code_indexer import CodeIndexer

        indexer = CodeIndexer()
        handler = QueryHandler(indexer=indexer)

        response = handler.query(question, k=max_results)

        return jsonify(response), 200

    except Exception as e:
        logger.error(f"Query API error: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


# ====================
# Phase 6: Dashboard Routes
# ====================

@app.route('/dashboard')
@jwt_required
def dashboard():
    """Security dashboard page"""
    try:
        service = get_report_service()
        summary = service.get_summary()
        uid = session.get('current_uid')  # Get UID from session
        logger.info(f"Dashboard route using UID: {uid}")
        return render_template('dashboard.html', summary=summary, uid=uid)
    except Exception as e:
        logger.error(f"Dashboard error: {e}", exc_info=True)
        return render_template('dashboard.html', error=str(e))


@app.route('/api/security/summary')
@jwt_required
def api_security_summary():
    """Get executive summary data"""
    try:
        service = get_report_service()
        # Extract UID from query params or session
        uid = request.args.get('uid') or session.get('current_uid')
        logger.info(f"Summary API using UID: {uid}")
        summary = service.get_summary(uid=uid)
        return jsonify(summary), 200
    except Exception as e:
        logger.error(f"Summary API error: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/api/security/charts')
@jwt_required
def api_security_charts():
    """Get all dashboard charts data"""
    try:
        service = get_report_service()
        # Extract UID from query params or session
        uid = request.args.get('uid') or session.get('current_uid')
        logger.info(f"Charts API using UID: {uid}")
        charts = service.get_dashboard_data(uid=uid)
        return jsonify(charts), 200
    except Exception as e:
        logger.error(f"Charts API error: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/api/security/findings')
@jwt_required
def api_security_findings():
    """Get security findings with filtering and pagination"""
    try:
        service = get_report_service()

        # Get query parameters
        severity = request.args.get('severity')
        owasp_category = request.args.get('owasp_category')
        limit = int(request.args.get('limit', 100))
        offset = int(request.args.get('offset', 0))
        # Extract UID from query params or session
        uid = request.args.get('uid') or session.get('current_uid')
        logger.info(f"Findings API using UID: {uid}")
        
        findings = service.get_findings(
            severity=severity,
            owasp_category=owasp_category,
            limit=limit,
            offset=offset,
            uid=uid
        )

        return jsonify(findings), 200
    except Exception as e:
        logger.error(f"Findings API error: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/api/security/finding/<finding_id>')
@jwt_required
def api_security_finding_detail(finding_id):
    """Get detailed information for a specific finding"""
    try:
        service = get_report_service()
        # Extract UID from query params or session
        uid = request.args.get('uid') or session.get('current_uid')
        logger.info(f"Finding detail API using UID: {uid}")
        finding = service.get_finding_by_id(finding_id, uid=uid)

        if finding:
            return jsonify(finding), 200
        else:
            return jsonify({'error': 'Finding not found'}), 404
    except Exception as e:
        logger.error(f"Finding detail API error: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/api/security/remediation')
@jwt_required
def api_security_remediation():
    """Get prioritized remediation plan"""
    try:
        service = get_report_service()
        # Extract UID from query params or session
        uid = request.args.get('uid') or session.get('current_uid')
        logger.info(f"Remediation API using UID: {uid}")
        plan = service.get_remediation_plan(uid=uid)
        return jsonify({'remediation_plan': plan}), 200
    except Exception as e:
        logger.error(f"Remediation API error: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/api/security/refresh')
@jwt_required
def api_security_refresh():
    """Trigger a full re-analysis and refresh dashboard data"""
    try:
        last_path = get_last_analysis_path()
        if not last_path or not os.path.exists(last_path):
            logger.warning("No recent analysis path found for refresh")
            # Just clear cache if no path found
            get_report_service().clear_cache()
            return jsonify({'status': 'cache cleared', 'details': 'No source found for re-scan'}), 200

        logger.info(f"Refreshing analysis for: {last_path}")
        
        # Create a new output folder for this refresh
        uid = f"refresh_{str(uuid.uuid4())[:8]}"
        output_path = os.path.join(app.config['PROCESSED_FOLDER'], uid)
        os.makedirs(output_path, exist_ok=True)

        # Re-run analysis
        analysis_result = analyze_codebase(last_path, output_path)
        
        # Sync results
        sync_results_to_dashboard(output_path)
        
        return jsonify({'status': 'refreshed', 'summary': analysis_result.get('summary')}), 200
    except Exception as e:
        logger.error(f"Refresh API error: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/api/feedback', methods=['POST'])
@jwt_required
def api_save_feedback():
    """Save user feedback for a finding"""
    try:
        data = request.json
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        finding_id = data.get('finding_id')
        feedback_type = data.get('feedback_type')
        comment = data.get('comment', '')
        code_snippet = data.get('code_snippet', '')
        
        if not finding_id or not feedback_type:
            return jsonify({'error': 'finding_id and feedback_type are required'}), 400
            
        service = get_feedback_service()
        success = service.save_feedback(finding_id, feedback_type, comment, code_snippet)
        
        if success:
            return jsonify({'message': 'Feedback saved successfully'}), 200
        else:
            return jsonify({'error': 'Failed to save feedback'}), 500
            
    except Exception as e:
        logger.error(f"Feedback API error: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


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