"""
Bug Bounty API Routes

Endpoints for the vulnerability / bug bounty scanner.
Adds persistent score tracking, mark-as-patched, user stats, and leaderboard.
"""

import logging
import os
import json
import sqlite3
from datetime import datetime
from flask import Blueprint, request, jsonify, session
from auth.jwt_utils import jwt_required
import config

logger = logging.getLogger(__name__)

bounty_bp = Blueprint('bounty', __name__, url_prefix='/api/bounty')

# In-memory cache for scan results keyed by uid
_scan_cache: dict = {}

# ---------------------------------------------------------------------------
# DB helpers — persistent bounty score storage
# ---------------------------------------------------------------------------
_DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'bounty_scores.db')


def _get_db():
    conn = sqlite3.connect(_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _init_db():
    with _get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS bounty_scores (
                user_id   TEXT NOT NULL,
                uid       TEXT NOT NULL,
                score     INTEGER DEFAULT 0,
                patched   INTEGER DEFAULT 0,
                rank      TEXT DEFAULT 'Hacker',
                updated   TEXT,
                PRIMARY KEY(user_id, uid)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS bounty_patches (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id       TEXT NOT NULL,
                uid           TEXT NOT NULL,
                finding_id    TEXT NOT NULL,
                severity      TEXT,
                title         TEXT,
                points        INTEGER DEFAULT 0,
                patched_at    TEXT
            )
        """)
        conn.commit()


_init_db()

SEVERITY_POINTS = {
    'CRITICAL': 500,
    'HIGH':     200,
    'MEDIUM':   80,
    'LOW':      20,
    'INFO':     5,
}

RANKS = [
    (0,     'Script Kiddie'),
    (100,   'Hacker'),
    (500,   'Security Analyst'),
    (1000,  'Pen Tester'),
    (2500,  'Ethical Hacker'),
    (5000,  'Bug Hunter Elite'),
    (10000, 'Zero-Day Legend'),
]


def _compute_rank(score: int) -> str:
    rank = RANKS[0][1]
    for threshold, name in RANKS:
        if score >= threshold:
            rank = name
    return rank


def _next_rank(score: int):
    for threshold, name in RANKS:
        if score < threshold:
            return {'name': name, 'threshold': threshold}
    return {'name': RANKS[-1][1], 'threshold': RANKS[-1][0]}


def _get_user_id() -> str | None:
    """Pull user id from JWT or session."""
    try:
        from auth.jwt_utils import get_current_user_id
        uid = get_current_user_id()
        if uid:
            return str(uid)
    except Exception:
        pass
    return session.get('user_id') or session.get('_user_id')


def _get_upload_path(uid: str) -> str:
    """Resolve the upload directory for a given uid."""
    temp_path = (
        str(config.UPLOAD_FOLDER / uid)
        if hasattr(config.UPLOAD_FOLDER, '__truediv__')
        else os.path.join(str(config.UPLOAD_FOLDER), uid)
    )
    if os.path.exists(temp_path):
        return temp_path
    return os.path.join('uploads', uid)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@bounty_bp.route('/scan', methods=['POST'])
@jwt_required
def scan_for_vulnerabilities():
    """Trigger a bug bounty vulnerability scan on an existing analysis UID."""
    try:
        data = request.get_json() or {}
        uid = data.get('uid') or session.get('current_uid')

        if not uid:
            return jsonify({'error': 'uid is required'}), 400

        if uid in _scan_cache:
            return jsonify(_scan_cache[uid]), 200

        upload_path = _get_upload_path(uid)
        if not os.path.exists(upload_path):
            return jsonify({'error': f'No uploaded codebase for uid: {uid}'}), 404

        from security.vulnerability_scanner import VulnerabilityScanner
        scanner = VulnerabilityScanner()
        results = scanner.scan_directory(upload_path, uid=uid)
        _scan_cache[uid] = results

        logger.info(
            f"Bounty scan complete for uid={uid}: "
            f"{results['summary']['total_findings']} findings"
        )
        return jsonify(results), 200

    except Exception as e:
        logger.error(f"Bounty scan error: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@bounty_bp.route('/results/<uid>', methods=['GET'])
@jwt_required
def get_bounty_results(uid: str):
    """Retrieve cached bounty scan results."""
    if uid in _scan_cache:
        return jsonify(_scan_cache[uid]), 200
    return jsonify({'error': 'No scan results. Run POST /api/bounty/scan first.'}), 404


@bounty_bp.route('/findings/<uid>', methods=['GET'])
@jwt_required
def get_bounty_findings(uid: str):
    """Filtered / paginated findings for a uid."""
    if uid not in _scan_cache:
        return jsonify({'error': 'No scan results. Run /api/bounty/scan first.'}), 404

    findings = _scan_cache[uid].get('findings', [])
    severity   = request.args.get('severity', '').upper()
    owasp      = request.args.get('owasp', '')
    limit      = int(request.args.get('limit', 50))
    offset     = int(request.args.get('offset', 0))
    bounty_only = request.args.get('bounty_only', 'false').lower() == 'true'

    if severity:
        findings = [f for f in findings if f.get('severity', '').upper() == severity]
    if owasp:
        findings = [f for f in findings if owasp.lower() in f.get('owasp_category', '').lower()]
    if bounty_only:
        findings = [f for f in findings if f.get('bounty_relevant')]

    paginated = findings[offset: offset + limit]
    return jsonify({'uid': uid, 'total': len(findings), 'offset': offset, 'limit': limit, 'findings': paginated}), 200


@bounty_bp.route('/stats/<uid>', methods=['GET'])
@jwt_required
def get_bounty_stats(uid: str):
    """Return this user's bounty score stats for a given uid."""
    user_id = _get_user_id() or 'anonymous'

    with _get_db() as conn:
        row = conn.execute(
            "SELECT * FROM bounty_scores WHERE user_id=? AND uid=?",
            (user_id, uid)
        ).fetchone()

    score   = row['score']   if row else 0
    patched = row['patched'] if row else 0
    rank    = _compute_rank(score)
    nxt     = _next_rank(score)

    # Get patched finding ids so the UI can mark them
    with _get_db() as conn:
        patches = conn.execute(
            "SELECT finding_id FROM bounty_patches WHERE user_id=? AND uid=?",
            (user_id, uid)
        ).fetchall()
    patched_ids = [p['finding_id'] for p in patches]

    return jsonify({
        'score':       score,
        'patched':     patched,
        'rank':        rank,
        'next_rank':   nxt,
        'patched_ids': patched_ids,
    }), 200


@bounty_bp.route('/patch', methods=['POST'])
@jwt_required
def mark_as_patched():
    """
    Mark a finding as patched and award points.

    Body: { "uid": "...", "finding_id": "...", "severity": "HIGH", "title": "SQL Injection" }
    """
    try:
        data       = request.get_json() or {}
        uid        = data.get('uid')
        finding_id = data.get('finding_id')
        severity   = (data.get('severity') or 'LOW').upper()
        title      = data.get('title', 'Vulnerability')
        user_id    = _get_user_id() or 'anonymous'

        if not uid or not finding_id:
            return jsonify({'error': 'uid and finding_id required'}), 400

        # Check not already patched
        with _get_db() as conn:
            existing = conn.execute(
                "SELECT 1 FROM bounty_patches WHERE user_id=? AND uid=? AND finding_id=?",
                (user_id, uid, finding_id)
            ).fetchone()

        if existing:
            return jsonify({'error': 'Already patched', 'already_patched': True}), 409

        points = SEVERITY_POINTS.get(severity, 20)
        now    = datetime.utcnow().isoformat()

        with _get_db() as conn:
            conn.execute(
                """INSERT INTO bounty_patches (user_id, uid, finding_id, severity, title, points, patched_at)
                   VALUES (?,?,?,?,?,?,?)""",
                (user_id, uid, finding_id, severity, title, points, now)
            )
            # Upsert score row
            conn.execute(
                """INSERT INTO bounty_scores (user_id, uid, score, patched, rank, updated)
                   VALUES (?,?,?,1,?,?)
                   ON CONFLICT(user_id, uid) DO UPDATE SET
                     score   = score + excluded.score,
                     patched = patched + 1,
                     rank    = excluded.rank,
                     updated = excluded.updated
                """,
                (user_id, uid, points, _compute_rank(points), now)
            )
            conn.commit()

        # Fetch updated stats
        with _get_db() as conn:
            row = conn.execute(
                "SELECT score, patched FROM bounty_scores WHERE user_id=? AND uid=?",
                (user_id, uid)
            ).fetchone()

        new_score   = row['score']   if row else points
        new_patched = row['patched'] if row else 1
        new_rank    = _compute_rank(new_score)

        return jsonify({
            'status':    'patched',
            'points':    points,
            'score':     new_score,
            'patched':   new_patched,
            'rank':      new_rank,
            'next_rank': _next_rank(new_score),
        }), 200

    except Exception as e:
        logger.error(f"Bounty patch error: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@bounty_bp.route('/leaderboard', methods=['GET'])
def get_leaderboard():
    """Top 10 across all users (no auth required)."""
    with _get_db() as conn:
        rows = conn.execute(
            "SELECT user_id, SUM(score) as total, SUM(patched) as bugs FROM bounty_scores "
            "GROUP BY user_id ORDER BY total DESC LIMIT 10"
        ).fetchall()

    board = [{'user': r['user_id'][:8] + '...', 'score': r['total'], 'bugs': r['bugs']} for r in rows]
    return jsonify({'leaderboard': board}), 200


@bounty_bp.route('/scan-snippet', methods=['POST'])
@jwt_required
def scan_snippet():
    """Scan a single code snippet."""
    try:
        data     = request.get_json() or {}
        code     = data.get('code', '')
        filename = data.get('filename', 'snippet.py')
        if not code:
            return jsonify({'error': 'code is required'}), 400

        from security.vulnerability_scanner import VulnerabilityScanner
        scanner  = VulnerabilityScanner()
        findings = scanner.scan_code_snippet(code, filename)
        return jsonify({'filename': filename, 'findings': findings, 'total': len(findings)}), 200

    except Exception as e:
        logger.error(f"Snippet scan error: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@bounty_bp.route('/extract-data', methods=['POST'])
@jwt_required
def extract_code_data():
    """Extract structured data from code using AI."""
    try:
        data     = request.get_json() or {}
        code     = data.get('code', '')
        filename = data.get('filename', 'snippet.py')
        if not code:
            return jsonify({'error': 'code is required'}), 400

        from llm_agents.report_agent import ReportAgent
        agent  = ReportAgent()
        result = agent.extract_data_from_code(code, filename)
        return jsonify(result), 200

    except Exception as e:
        logger.error(f"Extract data error: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@bounty_bp.route('/clear-cache/<uid>', methods=['DELETE'])
@jwt_required
def clear_bounty_cache(uid: str):
    """Clear cached scan results for a uid."""
    if uid in _scan_cache:
        del _scan_cache[uid]
        return jsonify({'status': 'cleared', 'uid': uid}), 200
    return jsonify({'status': 'not_found', 'uid': uid}), 404


@bounty_bp.route('/generate-ai-report/<uid>', methods=['POST'])
@jwt_required
def generate_ai_report(uid: str):
    """Generate the executive AI report."""
    try:
        from services.report_service import get_report_service
        service     = get_report_service()
        report_text = service.generate_ai_report(uid)
        return jsonify({'status': 'success', 'report': report_text}), 200
    except Exception as e:
        logger.error(f"Generate AI Report error: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
