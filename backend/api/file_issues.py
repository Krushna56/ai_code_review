"""
API endpoint for fetching security issues for specific files
"""

import os
import json
import logging
from flask import Blueprint, jsonify, request
from auth.jwt_utils import jwt_required

logger = logging.getLogger(__name__)

file_issues_bp = Blueprint('file_issues', __name__)


@file_issues_bp.route('/api/file/issues/<uid>/<path:filepath>')
@jwt_required
def get_file_issues(uid, filepath):
    """
    Get security issues for a specific file
    
    Args:
        uid: Unique identifier for the analysis session
        filepath: Relative path to the file
        
    Returns:
        JSON array of security issues with line numbers, severity, and descriptions
    """
    try:
        # Construct path to security report
        processed_folder = 'processed'
        security_report_path = os.path.join(processed_folder, uid, 'security_report.json')
        
        # Check if security report exists
        if not os.path.exists(security_report_path):
            logger.warning(f"Security report not found for UID {uid}")
            return jsonify({'issues': [], 'message': 'No security report available'}), 200
        
        # Read security report
        with open(security_report_path, 'r', encoding='utf-8') as f:
            security_report = json.load(f)
        
        # Extract security findings
        security_findings = security_report.get('security_findings', [])
        
        # Normalize filepath for comparison (handle both forward and backward slashes)
        normalized_filepath = filepath.replace('\\', '/').strip('/')
        
        # Filter issues for this specific file
        file_issues = []
        for finding in security_findings:
            finding_path = finding.get('file_path', '').replace('\\', '/').strip('/')
            
            # Check if the file path matches
            if finding_path == normalized_filepath or finding_path.endswith('/' + normalized_filepath):
                issue = {
                    'id': finding.get('id'),
                    'line_number': finding.get('line_number', 0),
                    'severity': finding.get('severity', 'UNKNOWN'),
                    'type': finding.get('type', 'unknown'),
                    'title': finding.get('title', 'Security Issue'),
                    'description': finding.get('description', ''),
                    'remediation': finding.get('remediation', ''),
                    'confidence': finding.get('confidence', 'MEDIUM'),
                    'owasp_category': finding.get('owasp_category'),
                    'owasp_name': finding.get('owasp_name'),
                    'risk_score': finding.get('risk_score', 0)
                }
                file_issues.append(issue)
        
        # Sort by line number
        file_issues.sort(key=lambda x: x['line_number'])
        
        logger.info(f"Found {len(file_issues)} issues for file {filepath} in UID {uid}")
        
        return jsonify({
            'issues': file_issues,
            'total': len(file_issues),
            'filepath': filepath
        }), 200
        
    except json.JSONDecodeError as e:
        logger.error(f"Error parsing security report: {e}")
        return jsonify({'error': 'Invalid security report format', 'issues': []}), 500
    except Exception as e:
        logger.error(f"Error fetching file issues: {e}", exc_info=True)
        return jsonify({'error': str(e), 'issues': []}), 500
