"""
Bug Bounty API Routes

Endpoints for the vulnerability / bug bounty scanner.
All scanning uses Mistral + Anthropic LLMs (via create_analysis_client).
"""

import logging
from flask import Blueprint, request, jsonify, session
from auth.jwt_utils import jwt_required
import config

logger = logging.getLogger(__name__)

bounty_bp = Blueprint('bounty', __name__, url_prefix='/api/bounty')

# In-memory cache for scan results keyed by uid
_scan_cache: dict = {}


def _get_upload_path(uid: str) -> str:
    """Resolve the upload directory for a given uid."""
    import os
    # Try temp dir first (matches config.UPLOAD_FOLDER)
    temp_path = str(config.UPLOAD_FOLDER / uid) if hasattr(config.UPLOAD_FOLDER, '__truediv__') else \
                os.path.join(str(config.UPLOAD_FOLDER), uid)
    if os.path.exists(temp_path):
        return temp_path
    # Fall back to local uploads/
    local_path = os.path.join('uploads', uid)
    return local_path


@bounty_bp.route('/scan', methods=['POST'])
@jwt_required
def scan_for_vulnerabilities():
    """
    Trigger a bug bounty / vulnerability scan on an existing analysis UID.

    Request Body (JSON):
        { "uid": "<analysis_uid>" }

    Response:
        {
          "scan_id": "...",
          "findings": [...],
          "summary": {...},
          "files_scanned": N
        }
    """
    try:
        data = request.get_json() or {}
        uid = data.get('uid') or session.get('current_uid')

        if not uid:
            return jsonify({'error': 'uid is required (or set via session)'}), 400

        # Return cached result if available
        if uid in _scan_cache:
            logger.info(f"Returning cached bounty scan for uid={uid}")
            return jsonify(_scan_cache[uid]), 200

        upload_path = _get_upload_path(uid)

        import os
        if not os.path.exists(upload_path):
            return jsonify({'error': f'No uploaded codebase found for uid: {uid}'}), 404

        logger.info(f"Starting bounty scan for uid={uid}, path={upload_path}")

        from security.vulnerability_scanner import VulnerabilityScanner
        scanner = VulnerabilityScanner()
        results = scanner.scan_directory(upload_path, uid=uid)

        # Cache results
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
    """
    Retrieve cached bounty scan results for a given uid.
    Returns 404 if no scan has been run yet.
    """
    if uid in _scan_cache:
        return jsonify(_scan_cache[uid]), 200
    return jsonify({'error': 'No scan results found for this uid. Run POST /api/bounty/scan first.'}), 404


@bounty_bp.route('/findings/<uid>', methods=['GET'])
@jwt_required
def get_bounty_findings(uid: str):
    """
    Return filtered/paginated findings for a uid.

    Query params:
        severity   - filter by severity (CRITICAL|HIGH|MEDIUM|LOW)
        owasp      - filter by OWASP category (e.g. A03:2021)
        limit      - max findings (default 50)
        offset     - pagination offset (default 0)
        bounty_only- if 'true', only return bounty-relevant findings
    """
    if uid not in _scan_cache:
        return jsonify({'error': 'No scan results found. Run /api/bounty/scan first.'}), 404

    findings = _scan_cache[uid].get('findings', [])

    severity = request.args.get('severity', '').upper()
    owasp = request.args.get('owasp', '')
    limit = int(request.args.get('limit', 50))
    offset = int(request.args.get('offset', 0))
    bounty_only = request.args.get('bounty_only', 'false').lower() == 'true'

    if severity:
        findings = [f for f in findings if f.get('severity', '').upper() == severity]
    if owasp:
        findings = [f for f in findings if owasp.lower() in f.get('owasp_category', '').lower()]
    if bounty_only:
        findings = [f for f in findings if f.get('bounty_relevant')]

    paginated = findings[offset: offset + limit]

    return jsonify({
        'uid': uid,
        'total': len(findings),
        'offset': offset,
        'limit': limit,
        'findings': paginated
    }), 200


@bounty_bp.route('/scan-snippet', methods=['POST'])
@jwt_required
def scan_snippet():
    """
    Scan a single code snippet for vulnerabilities.

    Request Body:
        {
          "code": "<source code>",
          "filename": "example.py"  # optional
        }
    """
    try:
        data = request.get_json() or {}
        code = data.get('code', '')
        filename = data.get('filename', 'snippet.py')

        if not code:
            return jsonify({'error': 'code is required'}), 400

        from security.vulnerability_scanner import VulnerabilityScanner
        scanner = VulnerabilityScanner()
        findings = scanner.scan_code_snippet(code, filename)

        return jsonify({
            'filename': filename,
            'findings': findings,
            'total': len(findings)
        }), 200

    except Exception as e:
        logger.error(f"Snippet scan error: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@bounty_bp.route('/extract-data', methods=['POST'])
@jwt_required
def extract_code_data():
    """
    Extract structured data from code using OpenAI (report agent).

    Request Body:
        {
          "code": "<source code>",
          "filename": "example.py"
        }
    """
    try:
        data = request.get_json() or {}
        code = data.get('code', '')
        filename = data.get('filename', 'snippet.py')

        if not code:
            return jsonify({'error': 'code is required'}), 400

        from llm_agents.report_agent import ReportAgent
        agent = ReportAgent()
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
    """
    Generate the final executive AI report using OpenAI.
    """
    try:
        from services.report_service import get_report_service
        service = get_report_service()
        report_text = service.generate_ai_report(uid)
        
        return jsonify({'status': 'success', 'report': report_text}), 200
    except Exception as e:
        logger.error(f"Generate AI Report error: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500

